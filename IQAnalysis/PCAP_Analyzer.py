"""
Enhanced 5G NR Fronthaul IQ Extractor
Separates IQ samples by direction (UL/DL) and eAxC ID
"""
import sys
import os
import struct
import math
import numpy as np
from collections import defaultdict
from scapy.all import rdpcap  # type: ignore
from scapy.layers.l2 import Dot1Q  # type: ignore

# ============================================================================
# COMPRESSION CONFIGURATION
# ============================================================================
# Override auto-detection by setting these variables:
# - Set FORCE_COMPRESSION_TYPE to 'BFP' or 'uncompressed'
# - Set FORCE_BFP_BITWIDTH to 8-14 for BFP compression
# - Set FORCE_BFP_EXPONENT to 0-15 for BFP exponent (None = auto-detect from packet)
# Leave as None to use auto-detection
#
# Examples:
#   FORCE_COMPRESSION_TYPE = 'BFP'
#   FORCE_BFP_BITWIDTH = 10
#   FORCE_BFP_EXPONENT = 5
#
#   FORCE_COMPRESSION_TYPE = 'uncompressed'  # Force 16-bit uncompressed
#
#   FORCE_COMPRESSION_TYPE = None  # Use auto-detection (default)
# ============================================================================
FORCE_COMPRESSION_TYPE = None  # Options: None, 'BFP', 'uncompressed'
FORCE_BFP_BITWIDTH = None      # Options: None, 8, 9, 10, 11, 12, 13, 14
FORCE_BFP_EXPONENT = None      # Options: None, 0-15
# ============================================================================

def calculate_max_iq(samples):
    """
    Calculate maximum uncompressed I/Q values from a list of complex samples.
    
    Args:
        samples: List of complex IQ samples
    
    Returns:
        tuple: (max_i, max_q, max_abs)
    """
    if not samples:
        return 0.0, 0.0, 0.0
    
    # Use numpy for efficient calculation
    samples_array = np.array(samples, dtype=complex)
    max_i = float(np.max(np.abs(samples_array.real)))
    max_q = float(np.max(np.abs(samples_array.imag)))
    max_abs = max(max_i, max_q)
    
    return max_i, max_q, max_abs

def calculate_dbfs(max_iq, full_scale=32767.0):
    """
    Calculate dBFS (decibels relative to full scale) from max I/Q value.
    
    Args:
        max_iq: Maximum I/Q value
        full_scale: Full scale value (default 32767 for 16-bit signed integers)
    
    Returns:
        float: dBFS value, or None if max_iq <= 0
    """
    if max_iq <= 0:
        return None
    return 20 * math.log10(max_iq / full_scale)

def decompress_bfp(iq_data_bytes, exponent, bits_per_sample=8):
    """
    Decompress Block Floating Point (BFP) compressed IQ samples
    
    Args:
        iq_data_bytes: Compressed IQ data bytes
        exponent: BFP exponent value (typically 0-15)
        bits_per_sample: Number of bits per I/Q component (8-14)
    
    Returns:
        List of complex IQ samples
    """
    samples = []
    scale_factor = 2.0 ** exponent
    
    if bits_per_sample == 8:
        # 8-bit compression: 1 byte per I, 1 byte per Q
        num_samples = len(iq_data_bytes) // 2
        for i in range(num_samples):
            # Read as unsigned, then convert to signed
            i_compressed = iq_data_bytes[i * 2]
            q_compressed = iq_data_bytes[i * 2 + 1]
            
            # Convert unsigned to signed (0-255 -> -128 to 127)
            i_val = (i_compressed - 128) * scale_factor
            q_val = (q_compressed - 128) * scale_factor
            
            samples.append(complex(i_val, q_val))
    elif 9 <= bits_per_sample <= 14:
        # N-bit compression: (2*N) bits per sample (I: N bits, Q: N bits)
        # Packed format: samples are bit-packed across byte boundaries
        bits_per_sample_pair = 2 * bits_per_sample
        num_samples = (len(iq_data_bytes) * 8) // bits_per_sample_pair
        bit_offset = 0
        max_value = (1 << bits_per_sample) - 1
        signed_offset = 1 << (bits_per_sample - 1)  # For signed conversion
        
        def read_n_bits(bit_offset, n_bits):
            """Read n_bits starting at bit_offset"""
            value = 0
            bits_read = 0
            
            while bits_read < n_bits:
                byte_idx = bit_offset // 8
                bit_in_byte = bit_offset % 8
                
                if byte_idx >= len(iq_data_bytes):
                    break
                
                # How many bits can we read from this byte?
                bits_available = 8 - bit_in_byte
                bits_needed = n_bits - bits_read
                bits_to_read = min(bits_available, bits_needed)
                
                # Extract bits from current byte
                mask = (1 << bits_to_read) - 1
                byte_value = (iq_data_bytes[byte_idx] >> bit_in_byte) & mask
                value |= (byte_value << bits_read)
                
                bits_read += bits_to_read
                bit_offset += bits_to_read
            
            return value, bit_offset
        
        for i in range(num_samples):
            # Read I component (N bits)
            i_compressed, bit_offset = read_n_bits(bit_offset, bits_per_sample)
            
            # Read Q component (N bits)
            q_compressed, bit_offset = read_n_bits(bit_offset, bits_per_sample)
            
            # Convert to signed (0 to max_value -> -signed_offset to signed_offset-1)
            i_val = (i_compressed - signed_offset) * scale_factor
            q_val = (q_compressed - signed_offset) * scale_factor
            samples.append(complex(i_val, q_val))
    else:
        raise ValueError(f"Unsupported bits_per_sample: {bits_per_sample}. Supported range: 8-14")
    
    return samples

def parse_iq_samples(ecpri_data, iq_offset, payload_version, filter_index, force_bfp=False, bfp_exponent=None, bfp_bitwidth=None):
    """
    Parse IQ samples from eCPRI packet, handling both uncompressed and BFP compressed formats
    
    Args:
        ecpri_data: eCPRI packet data
        iq_offset: Offset to start of IQ data
        payload_version: Payload version from radio header (bits 4-6 of byte 8)
        filter_index: Filter index from radio header (bits 0-3 of byte 8)
        force_bfp: If True, force BFP decompression (overridden by FORCE_COMPRESSION_TYPE)
        bfp_exponent: Explicit exponent value (overridden by FORCE_BFP_EXPONENT)
        bfp_bitwidth: Explicit bitwidth (overridden by FORCE_BFP_BITWIDTH)
    
    Returns:
        tuple: (samples_list, compression_type, num_samples)
    """
    iq_data_bytes = ecpri_data[iq_offset:]
    samples = []
    compression_type = "uncompressed"
    
    if len(iq_data_bytes) == 0:
        return samples, compression_type, 0
    
    # Check configuration variables first (highest priority)
    use_config_override = False
    config_compression_type = None
    config_bfp_bitwidth = None
    config_bfp_exponent = None
    
    if FORCE_COMPRESSION_TYPE is not None:
        use_config_override = True
        config_compression_type = FORCE_COMPRESSION_TYPE.lower()
        if config_compression_type == 'bfp':
            config_bfp_bitwidth = FORCE_BFP_BITWIDTH if FORCE_BFP_BITWIDTH is not None else (bfp_bitwidth if bfp_bitwidth is not None else 8)
            config_bfp_exponent = FORCE_BFP_EXPONENT if FORCE_BFP_EXPONENT is not None else bfp_exponent
        elif config_compression_type == 'uncompressed':
            # Force uncompressed
            pass
        else:
            raise ValueError(f"Invalid FORCE_COMPRESSION_TYPE: {FORCE_COMPRESSION_TYPE}. Must be 'BFP' or 'uncompressed'")
    
    # Determine compression type and parameters
    use_bfp = force_bfp or (use_config_override and config_compression_type == 'bfp')
    use_uncompressed = (use_config_override and config_compression_type == 'uncompressed')
    bfp_bits = config_bfp_bitwidth if use_config_override else (bfp_bitwidth if bfp_bitwidth is not None else 8)
    detected_exponent = None
    
    # If forcing uncompressed, skip all BFP detection
    if use_uncompressed:
        use_bfp = False
    elif not use_bfp:
        # Auto-detection logic for BFP compression
        # Check if first byte could be exponent (0-15 is typical range for BFP)
        if len(iq_data_bytes) > 1:
            potential_exponent = iq_data_bytes[0]
            compressed_data = iq_data_bytes[1:]
            
            # Calculate expected sample counts for different formats
            uncompressed_samples = len(iq_data_bytes) // 4  # 16-bit: 4 bytes per sample
            
            # Try to detect BFP compression for bitwidths 8-14
            best_match = None
            best_score = 0
            
            for test_bits in range(8, 15):  # Test 8-14 bits
                if test_bits == 8:
                    # 8-bit: 2 bytes per sample (1 I + 1 Q)
                    test_samples = len(compressed_data) // 2
                    expected_size = (test_samples * 2) + 1  # +1 for exponent
                    size_ratio = len(compressed_data) / len(iq_data_bytes) if len(iq_data_bytes) > 0 else 0
                else:
                    # 9-14 bit: bit-packed
                    bits_per_sample_pair = 2 * test_bits
                    test_samples = (len(compressed_data) * 8) // bits_per_sample_pair
                    expected_size = ((test_samples * bits_per_sample_pair + 7) // 8) + 1  # +1 for exponent, round up bytes
                    size_ratio = len(compressed_data) / len(iq_data_bytes) if len(iq_data_bytes) > 0 else 0
                
                # Score based on:
                # 1. Exponent in valid range
                # 2. Size ratio matches expected (8-bit ~50%, 9-bit ~56%, 10-bit ~62%, etc.)
                # 3. Sample count consistency
                score = 0
                if 0 <= potential_exponent <= 15:
                    score += 1
                
                # Expected size ratio for N-bit BFP: (2*N/32) = N/16
                expected_ratio = test_bits / 16.0
                ratio_diff = abs(size_ratio - expected_ratio)
                if ratio_diff < 0.1:  # Within 10% of expected
                    score += 2
                
                # Check if sample count makes sense
                if test_samples > 0 and test_samples == uncompressed_samples:
                    score += 1
                elif test_samples > 0 and abs(test_samples - uncompressed_samples) <= 2:
                    score += 0.5
                
                if score > best_score:
                    best_score = score
                    best_match = (test_bits, potential_exponent, test_samples)
            
            # If we found a good match (score >= 2), use it
            if best_match and best_score >= 2:
                use_bfp = True
                bfp_bits = best_match[0]
                detected_exponent = best_match[1]
    
    # Apply compression based on determined type
    if use_bfp:
        # Use configured or detected values
        exponent = config_bfp_exponent if use_config_override and config_bfp_exponent is not None else (
                   bfp_exponent if bfp_exponent is not None else detected_exponent)
        
        if exponent is None:
            # Try to extract from first byte
            if len(iq_data_bytes) > 0:
                exponent = iq_data_bytes[0]
                compressed_data = iq_data_bytes[1:]
            else:
                exponent = 0
                compressed_data = iq_data_bytes
        else:
            # Exponent provided or detected, skip first byte
            compressed_data = iq_data_bytes[1:] if len(iq_data_bytes) > 1 else iq_data_bytes
        
        if 0 <= exponent <= 15 and 8 <= bfp_bits <= 14:
            try:
                samples = decompress_bfp(compressed_data, exponent, bits_per_sample=bfp_bits)
                compression_type = f"BFP_{bfp_bits}bit"
                return samples, compression_type, len(samples)
            except Exception as e:
                # If forced BFP fails, raise error; otherwise fall back
                if use_config_override or force_bfp:
                    raise ValueError(f"BFP decompression failed: {e}")
                # Fall through to uncompressed
    
    # Default: Uncompressed 16-bit IQ samples (big-endian signed integers)
    # Use numpy for efficient parsing
    num_samples = len(iq_data_bytes) // 4
    if num_samples > 0:
        # Convert bytes to numpy array of int16 (big-endian)
        iq_array = np.frombuffer(iq_data_bytes[:num_samples*4], dtype='>i2')
        # Reshape to separate I and Q components
        iq_reshaped = iq_array.reshape(num_samples, 2)
        # Create complex array
        samples = (iq_reshaped[:, 0] + 1j * iq_reshaped[:, 1]).tolist()
    
    return samples, compression_type, num_samples

def analyze_pcap(pcap_file, force_bfp=False, bfp_exponent=None):
    """Analyze PCAP file and display summary information without extracting full data"""
    # Normalize path to handle relative paths correctly
    pcap_file = os.path.normpath(os.path.abspath(pcap_file))
    print(f"Analyzing {pcap_file}...")
    packets = rdpcap(pcap_file)
    print(f"Found {len(packets)} total packets\n")
    
    # Collect analysis data
    analysis_data = {
        'eaxc_ids': set(),
        'directions': set(),
        'frames': set(),
        'subframes': set(),
        'slots': set(),
        'symbols': set(),
        'packet_timestamps': [],
        'packet_count': 0,
        'total_samples': 0,
        'eaxc_stats': defaultdict(lambda: {'UL': {'packets': 0, 'samples': 0}, 'DL': {'packets': 0, 'samples': 0}}),
        'symbol_counts': defaultdict(int),
        'symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: {'packets': 0, 'samples': 0})),  # symbol_id -> eaxc_id -> stats
        'slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(int))),  # slot_id -> symbol_id -> eaxc_id -> count
        'frame_slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {'packets': 0, 'samples': 0})))),  # frame_id -> slot_id -> symbol_id -> eaxc_id -> stats
        'compression_types': set(),  # Track compression types found
        'max_iq_values': defaultdict(lambda: {'max_i': 0.0, 'max_q': 0.0, 'max_abs': 0.0})  # Track max uncompressed I/Q values per eAxC ID
    }
    
    for packet in packets:
        # Check for VLAN-tagged eCPRI packets
        if packet.haslayer(Dot1Q) and packet[Dot1Q].type == 0xAEFE:
            ecpri_data = bytes(packet[Dot1Q].payload)
            
            # Check if this is an IQ data message (type 0x00)
            if len(ecpri_data) >= 12 and ecpri_data[1] == 0x00:
                analysis_data['packet_count'] += 1
                
                # Get packet timestamp
                # Scapy stores timestamp in packet.time or packet[0].time depending on packet type
                try:
                    if hasattr(packet, 'time'):
                        timestamp = packet.time
                    elif hasattr(packet, '__getitem__') and len(packet) > 0:
                        timestamp = packet[0].time if hasattr(packet[0], 'time') else None
                    else:
                        timestamp = None
                    if timestamp is not None:
                        analysis_data['packet_timestamps'].append(timestamp)
                except:
                    pass  # Skip if timestamp not available
                
                # Parse eCPRI header
                eaxc_id = struct.unpack('!H', ecpri_data[4:6])[0]
                
                # Parse radio application header
                radio_start = 8
                data_direction = (ecpri_data[radio_start] >> 7) & 0x01
                payload_version = (ecpri_data[radio_start] >> 4) & 0x07
                filter_index = ecpri_data[radio_start] & 0x0F
                frame_id = ecpri_data[radio_start + 1]
                subframe_id = (ecpri_data[radio_start + 2] >> 4) & 0x0F
                slot_id = ((ecpri_data[radio_start + 2] & 0x0F) << 2) | ((ecpri_data[radio_start + 3] >> 6) & 0x03)
                symbol_id = ecpri_data[radio_start + 3] & 0x3F
                
                direction = 'DL' if data_direction == 1 else 'UL'
                
                # Skip headers to get IQ data
                iq_offset = 16
                # Parse IQ samples (handles both uncompressed and BFP compressed)
                samples, compression_type, num_samples = parse_iq_samples(ecpri_data, iq_offset, payload_version, filter_index,
                                                                     force_bfp=force_bfp, bfp_exponent=bfp_exponent)
                
                # Track compression type
                analysis_data['compression_types'].add(compression_type)
                
                # Track maximum uncompressed I/Q values for this eAxC ID
                if len(samples) > 0:
                    max_i, max_q, max_abs = calculate_max_iq(samples)
                    
                    # Update maximums for this eAxC ID
                    if max_abs > analysis_data['max_iq_values'][eaxc_id]['max_abs']:
                        analysis_data['max_iq_values'][eaxc_id]['max_i'] = max_i
                        analysis_data['max_iq_values'][eaxc_id]['max_q'] = max_q
                        analysis_data['max_iq_values'][eaxc_id]['max_abs'] = max_abs
                
                # Update statistics
                analysis_data['eaxc_ids'].add(eaxc_id)
                analysis_data['directions'].add(direction)
                analysis_data['frames'].add(frame_id)
                analysis_data['subframes'].add(subframe_id)
                analysis_data['slots'].add(slot_id)
                analysis_data['symbols'].add(symbol_id)
                analysis_data['total_samples'] += num_samples
                analysis_data['eaxc_stats'][eaxc_id][direction]['packets'] += 1
                analysis_data['eaxc_stats'][eaxc_id][direction]['samples'] += num_samples
                analysis_data['symbol_counts'][symbol_id] += 1
                analysis_data['symbol_eaxc_data'][symbol_id][eaxc_id]['packets'] += 1
                analysis_data['symbol_eaxc_data'][symbol_id][eaxc_id]['samples'] += num_samples
                analysis_data['slot_symbol_eaxc_data'][slot_id][symbol_id][eaxc_id] += 1
                analysis_data['frame_slot_symbol_eaxc_data'][frame_id][slot_id][symbol_id][eaxc_id]['packets'] += 1
                analysis_data['frame_slot_symbol_eaxc_data'][frame_id][slot_id][symbol_id][eaxc_id]['samples'] += num_samples
    
    # Calculate duration
    duration_sec = 0
    if len(analysis_data['packet_timestamps']) > 1:
        duration_sec = max(analysis_data['packet_timestamps']) - min(analysis_data['packet_timestamps'])
    
    # Print analysis report
    print("=" * 80)
    print("PCAP FILE ANALYSIS REPORT")
    print("=" * 80)
    print()
    
    print("OVERVIEW:")
    print(f"  Total Packets:        {len(packets):,}")
    print(f"  IQ Data Packets:      {analysis_data['packet_count']:,}")
    print(f"  Total IQ Samples:      {analysis_data['total_samples']:,}")
    if analysis_data['compression_types']:
        comp_types = ', '.join(sorted(analysis_data['compression_types']))
        print(f"  Compression Types:    {comp_types}")
    if duration_sec > 0:
        print(f"  Duration:             {duration_sec:.3f} seconds ({duration_sec*1000:.1f} ms)")
        if analysis_data['packet_count'] > 0:
            print(f"  Average Packet Rate:  {analysis_data['packet_count']/duration_sec:.1f} packets/sec")
    print()
    
    print("eAxC IDs:")
    if analysis_data['eaxc_ids']:
        eaxc_list = sorted(analysis_data['eaxc_ids'])
        print(f"  Found: {len(eaxc_list)} eAxC ID(s): {', '.join(map(str, eaxc_list))}")
        print()
        # Print summary table with max I/Q values
        print("=" * 110)
        print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10} {'Max I/Q':<15} {'Est. IQ Backoff':<18}")
        print("=" * 110)
        for eaxc_id in eaxc_list:
            max_iq = analysis_data['max_iq_values'][eaxc_id]['max_abs']
            max_iq_str = f"{max_iq:.2f}" if max_iq > 0 else "N/A"
            # Calculate dBFS (decibels relative to full scale)
            dbfs = calculate_dbfs(max_iq)
            dbfs_str = f"{dbfs:.2f} dBFS" if dbfs is not None else "N/A"
            for direction in ['UL', 'DL']:
                stats = analysis_data['eaxc_stats'][eaxc_id][direction]
                if stats['packets'] > 0:
                    print(f"{eaxc_id:<10} {direction:<12} {stats['samples']:<15,} {stats['packets']:<10} {max_iq_str:<15} {dbfs_str:<18}")
        print("=" * 110)
        print()
    else:
        print("  No eAxC IDs found")
        print()
    
    print("DIRECTIONS:")
    if analysis_data['directions']:
        dir_list = sorted(analysis_data['directions'])
        print(f"  Found: {', '.join(dir_list)}")
    else:
        print("  No direction data found")
    print()
    
    print("FRAME INFORMATION:")
    if analysis_data['frames']:
        frame_list = sorted(analysis_data['frames'])
        print(f"  Frame IDs: {min(frame_list)} to {max(frame_list)} ({len(frame_list)} unique frames)")
        print(f"  Subframe IDs: {sorted(analysis_data['subframes'])}")
    else:
        print("  No frame data found")
    print()
    
    print("SLOT INFORMATION:")
    if analysis_data['slots']:
        slot_list = sorted(analysis_data['slots'])
        print(f"  Slot IDs: {min(slot_list)} to {max(slot_list)} ({len(slot_list)} unique slots)")
    else:
        print("  No slot data found")
    print()
    
    print("SYMBOL INFORMATION:")
    if analysis_data['symbols']:
        symbol_list = sorted(analysis_data['symbols'])
        print(f"  Symbol IDs: {min(symbol_list)} to {max(symbol_list)} ({len(symbol_list)} unique symbols)")
        print(f"  Symbol range: {symbol_list}")
        if analysis_data['symbol_counts']:
            print(f"  Packets per symbol:")
            for sym_id in symbol_list:
                count = analysis_data['symbol_counts'][sym_id]
                print(f"    Symbol {sym_id:2d}: {count:4d} packets")
    else:
        print("  No symbol data found")
    print()
    
    print("=" * 80)
    print()
    
    # Create resource allocation plot
    if analysis_data['packet_count'] > 0:
        plot_resource_allocation(analysis_data, pcap_file)
    
    return analysis_data

def plot_resource_allocation(analysis_data, pcap_file):
    """Create separate resource allocation plots for each eAxC ID showing symbols vs Resource Blocks (RBs)"""
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    from matplotlib.colors import ListedColormap
    import os
    
    if not analysis_data['symbols'] or not analysis_data['eaxc_ids']:
        print("Insufficient data for resource allocation plot")
        return
    
    symbol_list = sorted(analysis_data['symbols'])
    eaxc_list = sorted(analysis_data['eaxc_ids'])
    
    # Calculate RBs per symbol per eAxC ID
    # In 5G NR: 1 RB = 12 subcarriers, typically 1 sample per subcarrier per symbol
    # So: samples / 12 ≈ number of RBs
    samples_per_rb = 12  # Standard: 12 subcarriers per RB
    
    # Get base name and directory for output files
    pcap_dir = os.path.dirname(pcap_file) if os.path.dirname(pcap_file) else '.'
    base_name = os.path.basename(pcap_file)
    base_name = base_name.replace('.pcap', '')
    
    # Create a separate plot for each eAxC ID
    for eaxc_id in eaxc_list:
        # Collect all unique (frame, slot, symbol) combinations for this eAxC ID
        unique_combinations = []
        combination_data = {}  # (frame, slot, symbol) -> {'samples': X, 'rbs': Y}
        
        for frame_id in sorted(analysis_data['frames']):
            for slot_id in sorted(analysis_data['slots']):
                for symbol_id in sorted(analysis_data['symbols']):
                    if (frame_id in analysis_data['frame_slot_symbol_eaxc_data'] and
                        slot_id in analysis_data['frame_slot_symbol_eaxc_data'][frame_id] and
                        symbol_id in analysis_data['frame_slot_symbol_eaxc_data'][frame_id][slot_id] and
                        eaxc_id in analysis_data['frame_slot_symbol_eaxc_data'][frame_id][slot_id][symbol_id]):
                        
                        samples = analysis_data['frame_slot_symbol_eaxc_data'][frame_id][slot_id][symbol_id][eaxc_id]['samples']
                        if samples > 0:
                            combo = (frame_id, slot_id, symbol_id)
                            unique_combinations.append(combo)
                            num_rbs = int(np.ceil(samples / samples_per_rb))
                            combination_data[combo] = {'samples': samples, 'rbs': num_rbs}
        
        if len(unique_combinations) == 0:
            continue  # Skip this eAxC ID if no data
        
        # Find maximum number of RBs across all combinations
        max_rbs = max(combo_data['rbs'] for combo_data in combination_data.values())
        
        if max_rbs == 0:
            continue
        
        # Create a 2D grid: rows = RBs, columns = unique (frame, slot, symbol) combinations
        # Grid value = RB index + 1 if allocated, 0 if not (so each RB gets unique color)
        num_columns = len(unique_combinations)
        grid = np.zeros((max_rbs, num_columns))
        sample_grid = np.zeros((max_rbs, num_columns))  # Store sample counts
        
        # Fill grid - mark allocated RBs with their RB index + 1
        for col_idx, combo in enumerate(unique_combinations):
            frame_id, slot_id, symbol_id = combo
            combo_info = combination_data[combo]
            num_rbs_for_combo = combo_info['rbs']
            
            for rb_idx in range(num_rbs_for_combo):
                if rb_idx < max_rbs:
                    grid[rb_idx, col_idx] = rb_idx + 1  # Each RB gets unique value
                    sample_grid[rb_idx, col_idx] = combo_info['samples']
        
        # Create colormap - each RB gets a distinct color
        # Use a vibrant colormap that cycles through distinct colors
        unallocated_color = '#f0f0f0'  # Light gray for unallocated
        
        # Create distinct colors for each RB using a colormap
        # Use a colormap that gives good distinction
        if max_rbs <= 20:
            # For small number of RBs, use tab20
            base_colors = plt.cm.tab20(np.linspace(0, 1, 20))
        elif max_rbs <= 50:
            # For medium, use Set3
            base_colors = plt.cm.Set3(np.linspace(0, 1, 12))
        else:
            # For many RBs, use a gradient with distinct hues
            base_colors = plt.cm.hsv(np.linspace(0, 1, max_rbs))
        
        # Create color list: unallocated (index 0) + distinct colors for each RB
        colors = [unallocated_color]
        for i in range(max_rbs):
            # Cycle through base colors
            color = base_colors[i % len(base_colors)]
            # Convert RGBA to hex if needed, or use directly
            if isinstance(color, np.ndarray) and len(color) == 4:
                # Convert RGBA to hex
                r, g, b, a = color
                hex_color = '#{:02x}{:02x}{:02x}'.format(int(r*255), int(g*255), int(b*255))
                colors.append(hex_color)
            else:
                colors.append(color)
        
        cmap = ListedColormap(colors[:max_rbs + 1])
        
        # Create figure - adjust height based on number of RBs, make it bigger
        fig_height = max(10, min(24, max_rbs * 0.4))
        fig_width = max(18, num_columns * 0.8)  # Adjust width based on number of columns
        fig, ax = plt.subplots(figsize=(fig_width, fig_height))
        
        # Create the heatmap
        im = ax.imshow(grid, aspect='auto', cmap=cmap, interpolation='nearest', 
                       vmin=0, vmax=max_rbs)
        
        # Set ticks and labels with larger fonts
        ax.set_xticks(range(num_columns))
        # Create labels showing frame/slot/symbol for each column
        column_labels = []
        for frame_id, slot_id, symbol_id in unique_combinations:
            column_labels.append(f'F{frame_id}S{slot_id}Sy{symbol_id}')
        ax.set_xticklabels(column_labels, fontsize=11, rotation=45, ha='right')
        
        # Set Y-axis labels for RBs - show every 10th RB only
        y_ticks = list(range(0, max_rbs, 10))
        ax.set_yticks(y_ticks)
        ax.set_yticklabels([f'RB {i}' for i in y_ticks], fontsize=11)
        
        # Add grid lines
        ax.set_xticks(np.arange(num_columns) - 0.5, minor=True)
        ax.set_yticks(np.arange(max_rbs) - 0.5, minor=True)
        ax.grid(which='minor', color='black', linestyle='-', linewidth=0.8, alpha=0.6)
        
        # Labels with larger fonts
        ax.set_xlabel('Frame/Slot/Symbol Combination', fontsize=14, fontweight='bold')
        ax.set_ylabel('Resource Block (RB) Index', fontsize=14, fontweight='bold')
        ax.set_title(f'Resource Allocation: eAxC ID {eaxc_id}\n(Each column = unique Frame/Slot/Symbol, Each cell = 1 RB = 12 subcarriers)', 
                     fontsize=16, fontweight='bold', pad=20)
        
        # Add text annotations showing sample counts (only for first RB of each combination to avoid clutter)
        for col_idx, combo in enumerate(unique_combinations):
            combo_info = combination_data[combo]
            if combo_info['rbs'] > 0:
                # Show sample count on the first RB of this combination
                first_rb = 0
                samples = combo_info['samples']
                if samples > 0:
                    ax.text(col_idx, first_rb, f'{int(samples):,}', 
                           ha='center', va='center', color='white', 
                           fontsize=10, fontweight='bold', 
                           bbox=dict(boxstyle='round,pad=0.5', facecolor='black', alpha=0.7))
        
        plt.tight_layout(pad=3.0)
        
        # Save plot with higher DPI in the same directory as input file
        output_file = os.path.join(pcap_dir, f'{base_name}_eAxC{eaxc_id}_resource_allocation.png')
        plt.savefig(output_file, dpi=200, bbox_inches='tight')
        print(f"Saved resource allocation plot for eAxC {eaxc_id}: {output_file}")
        plt.close()
    
    print()  # Add blank line after all plots

def extract_iq_with_metadata(pcap_file, force_bfp=False, bfp_exponent=None):
    """Extract IQ samples with direction and eAxC ID information"""
    # Normalize path to handle relative paths correctly
    pcap_file = os.path.normpath(os.path.abspath(pcap_file))
    print(f"Reading {pcap_file}...")
    packets = rdpcap(pcap_file)
    print(f"Found {len(packets)} packets\n")
    
    # Organize by eAxC ID and direction
    iq_data = defaultdict(lambda: {'UL': [], 'DL': [], 'metadata': []})
    # Track maximum uncompressed I/Q values per eAxC ID
    max_iq_values = defaultdict(lambda: {'max_i': 0, 'max_q': 0, 'max_abs': 0})
    packet_count = 0
    
    for packet in packets:
        # Check for VLAN-tagged eCPRI packets
        if packet.haslayer(Dot1Q) and packet[Dot1Q].type == 0xAEFE:
            ecpri_data = bytes(packet[Dot1Q].payload)
            
            # Check if this is an IQ data message (type 0x00)
            if len(ecpri_data) >= 12 and ecpri_data[1] == 0x00:
                packet_count += 1
                
                # Parse eCPRI header
                protocol_revision = (ecpri_data[0] >> 4) & 0x0F
                c_bit = ecpri_data[0] & 0x01
                msg_type = ecpri_data[1]
                payload_size = struct.unpack('!H', ecpri_data[2:4])[0]
                
                # Extract PC_ID/eAxC ID (2 bytes after eCPRI common header)
                # This is the physical connection identifier
                eaxc_id = struct.unpack('!H', ecpri_data[4:6])[0]
                
                # Extract sequence ID (for packet ordering)
                seq_id = struct.unpack('!H', ecpri_data[6:8])[0]
                
                # Parse radio application header (starts at byte 8)
                radio_start = 8
                data_direction = (ecpri_data[radio_start] >> 7) & 0x01
                payload_version = (ecpri_data[radio_start] >> 4) & 0x07
                filter_index = ecpri_data[radio_start] & 0x0F
                frame_id = ecpri_data[radio_start + 1]
                subframe_id = (ecpri_data[radio_start + 2] >> 4) & 0x0F
                slot_id = ((ecpri_data[radio_start + 2] & 0x0F) << 2) | ((ecpri_data[radio_start + 3] >> 6) & 0x03)
                symbol_id = ecpri_data[radio_start + 3] & 0x3F
                
                # Determine direction string
                direction = 'DL' if data_direction == 1 else 'UL'
                
                # Skip eCPRI header (4) + PC_ID/SeqID (4) + radio header (8) = 16 bytes total
                iq_offset = 16
                # Parse IQ samples (handles both uncompressed and BFP compressed)
                samples, compression_type, num_samples = parse_iq_samples(ecpri_data, iq_offset, payload_version, filter_index, 
                                                                          force_bfp=force_bfp, bfp_exponent=bfp_exponent)
                
                # Store samples by eAxC ID and direction
                iq_data[eaxc_id][direction].extend(samples)
                
                # Track maximum uncompressed I/Q values for this eAxC ID
                if len(samples) > 0:
                    max_i, max_q, max_abs = calculate_max_iq(samples)
                    
                    # Update maximums for this eAxC ID
                    if max_abs > max_iq_values[eaxc_id]['max_abs']:
                        max_iq_values[eaxc_id]['max_i'] = max_i
                        max_iq_values[eaxc_id]['max_q'] = max_q
                        max_iq_values[eaxc_id]['max_abs'] = max_abs
                
                # Store metadata for this packet
                iq_data[eaxc_id]['metadata'].append({
                    'direction': direction,
                    'seq_id': seq_id,
                    'frame_id': frame_id,
                    'subframe_id': subframe_id,
                    'slot_id': slot_id,
                    'symbol_id': symbol_id,
                    'num_samples': num_samples,
                    'filter_index': filter_index,
                    'compression_type': compression_type,
                    'payload_version': payload_version
                })
    
    print(f"Processed {packet_count} IQ data packets\n")
    
    # Print summary by eAxC ID
    print("=" * 110)
    print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10} {'Max I/Q':<15} {'Est. IQ Backoff':<18}")
    print("=" * 110)
    
    total_ul = 0
    total_dl = 0
    
    for eaxc_id in sorted(iq_data.keys()):
        ul_samples = len(iq_data[eaxc_id]['UL'])
        dl_samples = len(iq_data[eaxc_id]['DL'])
        max_iq = max_iq_values[eaxc_id]['max_abs']
        max_iq_str = f"{max_iq:.2f}" if max_iq > 0 else "N/A"
        
        # Calculate dBFS (decibels relative to full scale)
        dbfs = calculate_dbfs(max_iq)
        dbfs_str = f"{dbfs:.2f} dBFS" if dbfs is not None else "N/A"
        
        if ul_samples > 0:
            ul_packets = sum(1 for m in iq_data[eaxc_id]['metadata'] if m['direction'] == 'UL')
            print(f"{eaxc_id:<10} {'UL':<12} {ul_samples:<15,} {ul_packets:<10} {max_iq_str:<15} {dbfs_str:<18}")
            total_ul += ul_samples
            
        if dl_samples > 0:
            dl_packets = sum(1 for m in iq_data[eaxc_id]['metadata'] if m['direction'] == 'DL')
            print(f"{eaxc_id:<10} {'DL':<12} {dl_samples:<15,} {dl_packets:<10} {max_iq_str:<15} {dbfs_str:<18}")
            total_dl += dl_samples
    
    print("=" * 110)
    print(f"{'TOTAL':<10} {'UL':<12} {total_ul:<15,} {'':<10} {'':<15} {'':<18}")
    print(f"{'TOTAL':<10} {'DL':<12} {total_dl:<15,} {'':<10} {'':<15} {'':<18}")
    print("=" * 110)
    print()
    
    return iq_data

def save_separated_data(iq_data, output_base):
    """Save IQ data separated by eAxC ID and direction"""
    import json
    
    for eaxc_id in sorted(iq_data.keys()):
        # Save UL data
        if len(iq_data[eaxc_id]['UL']) > 0:
            ul_array = np.array(iq_data[eaxc_id]['UL'])
            filename = f"{output_base}_eAxC{eaxc_id}_UL"
            np.save(f"{filename}.npy", ul_array)
            print(f"Saved: {filename}.npy ({len(ul_array):,} samples)")
            
            # Save UL statistics
            with open(f"{filename}_stats.txt", 'w') as f:
                f.write(f"eAxC ID: {eaxc_id}\n")
                f.write(f"Direction: Uplink (UL)\n")
                f.write(f"Total samples: {len(ul_array):,}\n")
                f.write(f"I - Mean: {np.mean(ul_array.real):.2f}, Std: {np.std(ul_array.real):.2f}\n")
                f.write(f"Q - Mean: {np.mean(ul_array.imag):.2f}, Std: {np.std(ul_array.imag):.2f}\n")
                f.write(f"Magnitude - Mean: {np.mean(np.abs(ul_array)):.2f}, Max: {np.max(np.abs(ul_array)):.2f}\n")
                f.write(f"Average Power: {np.mean(np.abs(ul_array)**2):.2f}\n")
        
        # Save DL data
        if len(iq_data[eaxc_id]['DL']) > 0:
            dl_array = np.array(iq_data[eaxc_id]['DL'])
            filename = f"{output_base}_eAxC{eaxc_id}_DL"
            np.save(f"{filename}.npy", dl_array)
            print(f"Saved: {filename}.npy ({len(dl_array):,} samples)")
            
            # Save DL statistics
            with open(f"{filename}_stats.txt", 'w') as f:
                f.write(f"eAxC ID: {eaxc_id}\n")
                f.write(f"Direction: Downlink (DL)\n")
                f.write(f"Total samples: {len(dl_array):,}\n")
                f.write(f"I - Mean: {np.mean(dl_array.real):.2f}, Std: {np.std(dl_array.real):.2f}\n")
                f.write(f"Q - Mean: {np.mean(dl_array.imag):.2f}, Std: {np.std(dl_array.imag):.2f}\n")
                f.write(f"Magnitude - Mean: {np.mean(np.abs(dl_array)):.2f}, Max: {np.max(np.abs(dl_array)):.2f}\n")
                f.write(f"Average Power: {np.mean(np.abs(dl_array)**2):.2f}\n")
        
        # Save metadata
        metadata_file = f"{output_base}_eAxC{eaxc_id}_metadata.json"
        with open(metadata_file, 'w') as f:
            json.dump(iq_data[eaxc_id]['metadata'], f, indent=2)
        print(f"Saved: {metadata_file}")
    
    print()

def calculate_samples_for_symbols(iq_data, eaxc_id, direction, num_symbols):
    """Calculate the number of samples needed for a given number of symbols"""
    if eaxc_id not in iq_data or len(iq_data[eaxc_id][direction]) == 0:
        return 0
    
    # Get metadata for this eAxC ID and direction
    metadata = [m for m in iq_data[eaxc_id]['metadata'] if m['direction'] == direction]
    
    if len(metadata) == 0:
        return 0
    
    # Track unique symbols we want to include
    target_symbols = set()
    total_samples = 0
    
    for m in metadata:
        symbol_id = m['symbol_id']
        
        # If this is a new symbol and we haven't reached our limit, add it
        if symbol_id not in target_symbols:
            if len(target_symbols) >= num_symbols:
                # We've collected enough unique symbols, stop
                break
            target_symbols.add(symbol_id)
        
        # Count samples from symbols we want to include
        if symbol_id in target_symbols:
            total_samples += m['num_samples']
    
    return total_samples

def get_sample_mask_for_symbols(iq_data, eaxc_id, direction, start_symbol=None, end_symbol=None):
    """Get a boolean mask for samples in the given symbol range (inclusive)
    
    Returns:
        numpy array: Boolean mask where True indicates sample is in symbol range
    """
    if eaxc_id not in iq_data or len(iq_data[eaxc_id][direction]) == 0:
        return np.array([], dtype=bool)
    
    # Get metadata for this eAxC ID and direction
    metadata = [m for m in iq_data[eaxc_id]['metadata'] if m['direction'] == direction]
    
    if len(metadata) == 0:
        return np.array([], dtype=bool)
    
    total_samples = len(iq_data[eaxc_id][direction])
    mask = np.zeros(total_samples, dtype=bool)
    
    # If no symbol range specified, return all True
    if start_symbol is None and end_symbol is None:
        mask[:] = True
        return mask
    
    # Set defaults
    if start_symbol is None:
        start_symbol = 0
    if end_symbol is None:
        end_symbol = 63  # Maximum symbol ID in 5G NR
    
    # Build mask by checking each packet's symbol
    current_sample_index = 0
    
    for m in metadata:
        symbol_id = m['symbol_id']
        num_samples = m['num_samples']
        
        # Check if this symbol is in our range
        if start_symbol <= symbol_id <= end_symbol:
            mask[current_sample_index:current_sample_index + num_samples] = True
        
        current_sample_index += num_samples
    
    return mask

def get_sample_range_for_symbols(iq_data, eaxc_id, direction, start_symbol=None, end_symbol=None):
    """Get the sample index range for a given symbol range (inclusive)
    Note: This returns a simple range, but symbols may be interleaved.
    Use get_sample_mask_for_symbols() for accurate filtering.
    
    Returns:
        tuple: (start_sample_index, end_sample_index) or (0, total_samples) if no range specified
    """
    if eaxc_id not in iq_data or len(iq_data[eaxc_id][direction]) == 0:
        return (0, 0)
    
    # Get metadata for this eAxC ID and direction
    metadata = [m for m in iq_data[eaxc_id]['metadata'] if m['direction'] == direction]
    
    if len(metadata) == 0:
        return (0, 0)
    
    # If no symbol range specified, return all samples
    if start_symbol is None and end_symbol is None:
        total_samples = sum(m['num_samples'] for m in metadata)
        return (0, total_samples)
    
    # Set defaults
    if start_symbol is None:
        start_symbol = 0
    if end_symbol is None:
        end_symbol = 63  # Maximum symbol ID in 5G NR
    
    # Find first and last occurrence of symbols in range
    first_index = None
    last_index = None
    current_sample_index = 0
    
    for m in metadata:
        symbol_id = m['symbol_id']
        num_samples = m['num_samples']
        
        if start_symbol <= symbol_id <= end_symbol:
            if first_index is None:
                first_index = current_sample_index
            last_index = current_sample_index + num_samples
        
        current_sample_index += num_samples
    
    if first_index is None:
        return (0, 0)
    
    return (first_index, last_index)

def plot_comparison(iq_data, output_file, max_samples=10000, start_symbol=None, end_symbol=None):
    """Create comparison plots for UL vs DL"""
    import matplotlib.pyplot as plt
    
    # Find an eAxC ID that has both UL and DL data
    eaxc_with_both = None
    for eaxc_id in sorted(iq_data.keys()):
        if len(iq_data[eaxc_id]['UL']) > 0 and len(iq_data[eaxc_id]['DL']) > 0:
            eaxc_with_both = eaxc_id
            break
    
    if eaxc_with_both is None:
        print("No eAxC ID with both UL and DL data for comparison plot")
        return
    
    # Get samples, filtering by symbol range if specified
    if start_symbol is not None or end_symbol is not None:
        ul_mask = get_sample_mask_for_symbols(iq_data, eaxc_with_both, 'UL', start_symbol, end_symbol)
        dl_mask = get_sample_mask_for_symbols(iq_data, eaxc_with_both, 'DL', start_symbol, end_symbol)
        ul_all = np.array(iq_data[eaxc_with_both]['UL'])
        dl_all = np.array(iq_data[eaxc_with_both]['DL'])
        ul_samples = ul_all[ul_mask]
        dl_samples = dl_all[dl_mask]
        # Apply max_samples limit if needed
        if len(ul_samples) > max_samples:
            ul_samples = ul_samples[:max_samples]
        if len(dl_samples) > max_samples:
            dl_samples = dl_samples[:max_samples]
    else:
        ul_samples = np.array(iq_data[eaxc_with_both]['UL'][:max_samples])
        dl_samples = np.array(iq_data[eaxc_with_both]['DL'][:max_samples])
    
    # Create title with symbol range if specified
    title = f'UL vs DL Comparison (eAxC ID: {eaxc_with_both})'
    if start_symbol is not None or end_symbol is not None:
        symbol_range = f"Symbols {start_symbol if start_symbol is not None else 0}-{end_symbol if end_symbol is not None else 'end'}"
        title += f" - {symbol_range}"
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(title, fontsize=14, fontweight='bold')
    
    # UL Constellation
    axes[0, 0].scatter(ul_samples.real, ul_samples.imag, alpha=0.3, s=1, c='blue')
    axes[0, 0].set_xlabel('I (In-phase)')
    axes[0, 0].set_ylabel('Q (Quadrature)')
    axes[0, 0].set_title(f'Uplink Constellation ({len(ul_samples):,} samples)')
    axes[0, 0].grid(True, alpha=0.3)
    axes[0, 0].axis('equal')
    
    # DL Constellation
    axes[0, 1].scatter(dl_samples.real, dl_samples.imag, alpha=0.3, s=1, c='red')
    axes[0, 1].set_xlabel('I (In-phase)')
    axes[0, 1].set_ylabel('Q (Quadrature)')
    axes[0, 1].set_title(f'Downlink Constellation ({len(dl_samples):,} samples)')
    axes[0, 1].grid(True, alpha=0.3)
    axes[0, 1].axis('equal')
    
    # UL Magnitude
    ul_mag = np.abs(ul_samples)
    axes[1, 0].plot(ul_mag, color='blue', alpha=0.7)
    axes[1, 0].set_xlabel('Sample Index')
    axes[1, 0].set_ylabel('Magnitude')
    axes[1, 0].set_title(f'Uplink Magnitude (Mean: {np.mean(ul_mag):.1f})')
    axes[1, 0].grid(True, alpha=0.3)
    
    # DL Magnitude
    dl_mag = np.abs(dl_samples)
    axes[1, 1].plot(dl_mag, color='red', alpha=0.7)
    axes[1, 1].set_xlabel('Sample Index')
    axes[1, 1].set_ylabel('Magnitude')
    axes[1, 1].set_title(f'Downlink Magnitude (Mean: {np.mean(dl_mag):.1f})')
    axes[1, 1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(output_file, dpi=200, bbox_inches='tight')
    print(f"Saved comparison plot: {output_file}\n")
    plt.close()

def plot_all_eaxc(iq_data, output_base, max_samples=10000, start_symbol=None, end_symbol=None):
    """Create individual plots for each eAxC ID"""
    import matplotlib.pyplot as plt
    
    for eaxc_id in sorted(iq_data.keys()):
        for direction in ['UL', 'DL']:
            if len(iq_data[eaxc_id][direction]) == 0:
                continue
            
            # Get samples, filtering by symbol range if specified
            if start_symbol is not None or end_symbol is not None:
                mask = get_sample_mask_for_symbols(iq_data, eaxc_id, direction, start_symbol, end_symbol)
                all_samples = np.array(iq_data[eaxc_id][direction])
                samples = all_samples[mask]
                # Apply max_samples limit if needed
                if len(samples) > max_samples:
                    samples = samples[:max_samples]
            else:
                samples = np.array(iq_data[eaxc_id][direction][:max_samples])
            
            # Create title with symbol range if specified
            title = f'eAxC ID: {eaxc_id} - {direction}'
            if start_symbol is not None or end_symbol is not None:
                symbol_range = f"Symbols {start_symbol if start_symbol is not None else 0}-{end_symbol if end_symbol is not None else 'end'}"
                title += f" - {symbol_range}"
            
            fig, axes = plt.subplots(2, 2, figsize=(12, 10))
            fig.suptitle(title, fontsize=14, fontweight='bold')
            
            # I/Q Time Domain
            axes[0, 0].plot(samples.real, label='I', alpha=0.7)
            axes[0, 0].plot(samples.imag, label='Q', alpha=0.7)
            axes[0, 0].set_xlabel('Sample Index')
            axes[0, 0].set_ylabel('Amplitude')
            axes[0, 0].set_title('I/Q Time Domain')
            axes[0, 0].legend()
            axes[0, 0].grid(True, alpha=0.3)
            
            # Magnitude
            magnitude = np.abs(samples)
            axes[0, 1].plot(magnitude, color='purple')
            axes[0, 1].set_xlabel('Sample Index')
            axes[0, 1].set_ylabel('Magnitude')
            axes[0, 1].set_title(f'Magnitude (Mean: {np.mean(magnitude):.1f})')
            axes[0, 1].grid(True, alpha=0.3)
            
            # Phase
            phase = np.angle(samples)
            axes[1, 0].plot(phase, color='green')
            axes[1, 0].set_xlabel('Sample Index')
            axes[1, 0].set_ylabel('Phase (radians)')
            axes[1, 0].set_title('Phase')
            axes[1, 0].grid(True, alpha=0.3)
            
            # Constellation
            axes[1, 1].scatter(samples.real, samples.imag, alpha=0.3, s=1)
            axes[1, 1].set_xlabel('I (In-phase)')
            axes[1, 1].set_ylabel('Q (Quadrature)')
            axes[1, 1].set_title('Constellation Diagram')
            axes[1, 1].grid(True, alpha=0.3)
            axes[1, 1].axis('equal')
            
            plt.tight_layout()
            plot_file = f"{output_base}_eAxC{eaxc_id}_{direction}.png"
            plt.savefig(plot_file, dpi=150, bbox_inches='tight')
            print(f"Saved plot: {plot_file}")
            plt.close()
    
    print()

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Extract IQ samples from 5G NR Fronthaul PCAP files',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  python PCAP_Analyzer.py capture.pcap --analyze
  python PCAP_Analyzer.py capture.pcap
  python PCAP_Analyzer.py capture.pcap iq_data
  python PCAP_Analyzer.py capture.pcap iq_data --symbols 10
  python PCAP_Analyzer.py capture.pcap iq_data --samples 5000
  python PCAP_Analyzer.py capture.pcap iq_data --start-symbol 5 --end-symbol 10
  python PCAP_Analyzer.py capture.pcap iq_data --start-symbol 0 --end-symbol 13
        '''
    )
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('output_base', nargs='?', default='iq_separated',
                       help='Base name for output files (default: iq_separated)')
    parser.add_argument('--symbols', type=int, metavar='N',
                       help='Number of symbols to plot from the start (overrides --samples if specified, ignored if --start-symbol/--end-symbol specified)')
    parser.add_argument('--samples', type=int, default=10000, metavar='N',
                       help='Number of samples to plot (default: 10000, ignored if --symbols or symbol range is specified)')
    parser.add_argument('--start-symbol', type=int, metavar='N',
                       help='Start symbol ID for analysis (inclusive, 0-63)')
    parser.add_argument('--end-symbol', type=int, metavar='N',
                       help='End symbol ID for analysis (inclusive, 0-63)')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze PCAP file and display summary information (no extraction/plotting)')
    parser.add_argument('--force-bfp', action='store_true',
                       help='Force BFP (Block Floating Point) decompression for all packets')
    parser.add_argument('--bfp-exponent', type=int, metavar='N',
                       help='Explicit BFP exponent value (0-15). If not specified, will auto-detect from packet')
    
    args = parser.parse_args()
    
    # If --analyze is specified, just analyze and exit
    if args.analyze:
        analyze_pcap(args.pcap_file, force_bfp=args.force_bfp, bfp_exponent=args.bfp_exponent)
        sys.exit(0)
    
    # Extract IQ samples with metadata
    iq_data = extract_iq_with_metadata(args.pcap_file, force_bfp=args.force_bfp, bfp_exponent=args.bfp_exponent)
    
    if len(iq_data) == 0:
        print("No IQ data found!")
        sys.exit(1)
    
    # Save separated data
    print("Saving data files...")
    save_separated_data(iq_data, args.output_base)
    
    # Validate symbol range if provided
    start_symbol = args.start_symbol
    end_symbol = args.end_symbol
    if start_symbol is not None and end_symbol is not None:
        if start_symbol > end_symbol:
            print(f"Error: --start-symbol ({start_symbol}) must be <= --end-symbol ({end_symbol})")
            sys.exit(1)
        if start_symbol < 0 or end_symbol > 63:
            print(f"Error: Symbol IDs must be between 0 and 63")
            sys.exit(1)
    
    # Determine max_samples based on symbols or samples parameter
    # Symbol range takes precedence over --symbols, which takes precedence over --samples
    max_samples = args.samples
    if start_symbol is None and end_symbol is None and args.symbols is not None:
        # Find the first eAxC ID with data to calculate samples per symbol
        # We'll use the first eAxC ID that has DL data (or UL if no DL)
        eaxc_id_for_calc = None
        direction_for_calc = None
        for eaxc_id in sorted(iq_data.keys()):
            if len(iq_data[eaxc_id]['DL']) > 0:
                eaxc_id_for_calc = eaxc_id
                direction_for_calc = 'DL'
                break
            elif len(iq_data[eaxc_id]['UL']) > 0:
                eaxc_id_for_calc = eaxc_id
                direction_for_calc = 'UL'
                break
        
        if eaxc_id_for_calc is not None:
            max_samples = calculate_samples_for_symbols(iq_data, eaxc_id_for_calc, 
                                                         direction_for_calc, args.symbols)
            print(f"Plotting {args.symbols} symbols ({max_samples:,} samples)")
        else:
            print(f"Warning: Could not determine samples per symbol, using default {max_samples:,} samples")
    elif start_symbol is not None or end_symbol is not None:
        # Symbol range specified - calculate max_samples for display purposes
        # Find the first eAxC ID with data to estimate sample count
        eaxc_id_for_calc = None
        direction_for_calc = None
        for eaxc_id in sorted(iq_data.keys()):
            if len(iq_data[eaxc_id]['DL']) > 0:
                eaxc_id_for_calc = eaxc_id
                direction_for_calc = 'DL'
                break
            elif len(iq_data[eaxc_id]['UL']) > 0:
                eaxc_id_for_calc = eaxc_id
                direction_for_calc = 'UL'
                break
        
        if eaxc_id_for_calc is not None:
            mask = get_sample_mask_for_symbols(iq_data, eaxc_id_for_calc, 
                                                direction_for_calc, start_symbol, end_symbol)
            max_samples = np.sum(mask)  # Count of True values in mask
            symbol_range_str = f"Symbols {start_symbol if start_symbol is not None else 0}-{end_symbol if end_symbol is not None else 'end'}"
            print(f"Plotting {symbol_range_str} ({max_samples:,} samples)")
        else:
            print(f"Warning: Could not determine samples per symbol, using default {max_samples:,} samples")
    
    # Create comparison plot
    print("Creating comparison plot...")
    plot_comparison(iq_data, f"{args.output_base}_UL_vs_DL.png", max_samples=max_samples, 
                    start_symbol=start_symbol, end_symbol=end_symbol)
    
    # Create individual plots for each eAxC/direction
    print("Creating individual plots...")
    plot_all_eaxc(iq_data, args.output_base, max_samples=max_samples, 
                  start_symbol=start_symbol, end_symbol=end_symbol)
    
    print("Done!")

