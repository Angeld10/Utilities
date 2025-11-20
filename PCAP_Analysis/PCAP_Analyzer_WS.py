"""
Enhanced 5G NR Fronthaul IQ Extractor (Wireshark-based)
Separates IQ samples by direction (UL/DL) and eAxC ID using pyshark/Wireshark library
"""
import sys
import os
import struct
import time
import math
import re
import json
import numpy as np
import subprocess
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor, as_completed
try:
    import pyshark
except ImportError:
    print("Error: pyshark library not found. Please install it with: pip install pyshark")
    sys.exit(1)

try:
    import mplcursors
except ImportError:
    mplcursors = None
    # Don't exit, just disable interactive cursor features

# Import helper functions from the original script

# Global configuration - these are defaults that can be overridden by command-line arguments
FORCE_COMPRESSION_TYPE = 'uncompressed'  # 'BFP' or 'uncompressed' - default compression type
FORCE_BFP_BITWIDTH = 16          # 8-14 for BFP compression - default bitwidth
NUMEROLOGY = 1                  # 0 (15 kHz SCS) or 1 (30 kHz SCS)
ENDIAN = 'big'                  # 'little' or 'big' endian for byte order

#Debug loop count
debug_count = 0

# Global list to collect compression warnings
_compression_warnings = []

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

def detect_wrong_compression_settings(iq_data_bytes, samples, compression_type, configured_compression='uncompressed', configured_bitwidth=16):
    """
    Detect if wrong compression settings are being used by checking various heuristics.
    Similar to Wireshark's malformed packet detection.
    
    Args:
        iq_data_bytes: Raw IQ data bytes
        samples: Parsed IQ samples (list of complex)
        compression_type: Compression type string (e.g., 'uncompressed', 'BFP_9bit')
        configured_compression: What compression was configured ('uncompressed' or 'bfp')
        configured_bitwidth: Configured bitwidth (for BFP: 8-14, for uncompressed: 16)
    
    Returns:
        tuple: (is_wrong, confidence, warning_messages)
            is_wrong: Boolean indicating if wrong settings detected
            confidence: Float 0.0-1.0 indicating confidence level
            warning_messages: List of warning messages
    """
    warnings = []
    confidence = 0.0
    
    if not samples or len(iq_data_bytes) == 0:
        return False, 0.0, []
    
    samples_array = np.array(samples, dtype=complex)
    
    # Heuristic 1: Check for extreme values clustering (±32768, ±32767)
    # If uncompressed data is actually BFP compressed, we'll see many samples at these extremes
    i_real = samples_array.real
    q_imag = samples_array.imag
    
    # Count samples at extreme values
    extreme_values = [-32768, -32767, 32767, 32768]
    extreme_count_i = sum(np.sum(i_real == val) for val in extreme_values)
    extreme_count_q = sum(np.sum(q_imag == val) for val in extreme_values)
    extreme_count_total = extreme_count_i + extreme_count_q
    
    total_samples = len(samples) * 2  # I and Q components
    extreme_percentage = (extreme_count_total / total_samples) * 100 if total_samples > 0 else 0
    
    # If more than 1% of samples are at extremes, that's suspicious for uncompressed data
    if configured_compression == 'uncompressed' and extreme_percentage > 1.0:
        confidence += 0.4
        warnings.append(f"Suspicious: {extreme_percentage:.2f}% of samples at extreme values (±32767, ±32768)")
        warnings.append(f"  Found {extreme_count_i} extreme I values and {extreme_count_q} extreme Q values")
    
    # Heuristic 2: Check if data size aligns properly
    if configured_compression == 'uncompressed':
        # Uncompressed: should be divisible by 4 (2 bytes I + 2 bytes Q per sample)
        if len(iq_data_bytes) % 4 != 0:
            confidence += 0.2
            warnings.append(f"Data size {len(iq_data_bytes)} bytes is not divisible by 4 (uncompressed should be)")
        else:
            # Check if the actual number of samples matches expected
            expected_samples = len(iq_data_bytes) // 4
            if abs(len(samples) - expected_samples) > expected_samples * 0.01:  # Allow 1% tolerance
                confidence += 0.2
                warnings.append(f"Sample count mismatch: expected {expected_samples}, got {len(samples)}")
    elif configured_compression == 'bfp':
        # BFP: Check if first bytes look like exponent bytes (0-15 range)
        if len(iq_data_bytes) > 0:
            first_bytes = iq_data_bytes[:min(20, len(iq_data_bytes))]
            exponent_like_bytes = sum(1 for b in first_bytes if 0 <= b <= 15)
            if exponent_like_bytes >= len(first_bytes) * 0.5:  # More than 50% look like exponents
                confidence += 0.3
                warnings.append(f"First {len(first_bytes)} bytes mostly in 0-15 range (looks like BFP exponents)")
    
    # Heuristic 3: Check for -32768 specifically (minimum signed int16)
    # This is a strong indicator of byte misalignment when reading BFP as uncompressed
    count_min32768_i = np.sum(i_real == -32768)
    count_min32768_q = np.sum(q_imag == -32768)
    
    if configured_compression == 'uncompressed' and (count_min32768_i > 0 or count_min32768_q > 0):
        total_min32768 = count_min32768_i + count_min32768_q
        if total_min32768 > 10:  # More than 10 occurrences is suspicious
            confidence += 0.4
            warnings.append(f"Found {total_min32768} samples with value -32768 (minimum int16)")
            warnings.append("  This suggests byte misalignment - BFP data may be read as uncompressed")
    
    # Heuristic 4: Check distribution - valid uncompressed IQ should have reasonable distribution
    # If most values are clustered at extremes, that's suspicious
    if configured_compression == 'uncompressed' and len(samples) > 100:
        # Check if values are distributed across the range
        i_abs = np.abs(i_real)
        q_abs = np.abs(q_imag)
        
        # Check what percentage of values are in the upper 10% of range
        range_90_100 = np.sum(i_abs > 29490) + np.sum(q_abs > 29490)  # Upper 10% of 32767
        range_90_100_pct = (range_90_100 / total_samples) * 100
        
        if range_90_100_pct > 10:  # More than 10% in top 10% is unusual
            confidence += 0.2
            warnings.append(f"Unusual distribution: {range_90_100_pct:.2f}% of samples in upper 10% of range")
    
    # Heuristic 5: Try to detect BFP structure if configured as uncompressed
    if configured_compression == 'uncompressed' and len(iq_data_bytes) > 20:
        # Check if data structure matches BFP (exponent bytes followed by compressed data)
        # For BFP9: bytes per RB = 1 (exponent) + (12 samples * 2.25 bytes) = 28 bytes
        # Check if we can find a pattern that looks like BFP9
        possible_bfp9_rbs = 0
        bytes_per_rb_bfp9 = 28  # 1 exponent + 27 bytes for 12 samples at 9 bits
        
        for start in range(0, min(100, len(iq_data_bytes) - bytes_per_rb_bfp9), bytes_per_rb_bfp9):
            exp_byte = iq_data_bytes[start]
            if 0 <= exp_byte <= 15:
                possible_bfp9_rbs += 1
        
        if possible_bfp9_rbs >= 3:
            confidence += 0.3
            warnings.append(f"Detected possible BFP9 structure: {possible_bfp9_rbs} potential exponent bytes found")
            warnings.append("  Data may be BFP9 compressed but read as uncompressed")
    
    # Determine if wrong settings detected
    is_wrong = confidence >= 0.5  # At least 50% confidence threshold
    
    if is_wrong:
        warnings.insert(0, f"WARNING: Possible wrong compression settings detected (confidence: {confidence:.1%})")
        warnings.append(f"  Configured: {configured_compression} (bitwidth={configured_bitwidth})")
        warnings.append("  Recommendation: Try different compression settings")
    
    return is_wrong, min(confidence, 1.0), warnings

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
    debug_count = 0
    samples = []
    scale_factor = 2.0 ** exponent
    
    if bits_per_sample == 8:
        # 8-bit compression: 1 byte per I, 1 byte per Q
        num_samples = len(iq_data_bytes) // 2
        is_little_endian = (ENDIAN.lower() == 'little')
        
        for i in range(num_samples):
            # Read as unsigned, then convert to signed using two's complement
            if is_little_endian:
                i_compressed = iq_data_bytes[i * 2]
                q_compressed = iq_data_bytes[i * 2 + 1]
            else:
                # Big-endian: swap byte order
                i_compressed = iq_data_bytes[i * 2 + 1]
                q_compressed = iq_data_bytes[i * 2]
            
            # Convert to signed: if MSB is set, treat as negative (two's complement)
            if i_compressed >= 128:
                i_signed = i_compressed - 256
            else:
                i_signed = i_compressed
            
            if q_compressed >= 128:
                q_signed = q_compressed - 256
            else:
                q_signed = q_compressed
            
            i_val = i_signed * scale_factor
            q_val = q_signed * scale_factor
            
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
            is_little_endian = (ENDIAN.lower() == 'little')
            value = 0
            
            if is_little_endian:
                # Little-endian: bits read LSB-first within bytes
                for i in range(n_bits):
                    byte_idx = (bit_offset + i) // 8
                    bit_in_byte = (bit_offset + i) % 8  # LSB-first: bit 0 is first
                    
                    if byte_idx >= len(iq_data_bytes):
                        break
                    
                    # Read the bit from the byte
                    bit_value = (iq_data_bytes[byte_idx] >> bit_in_byte) & 1
                    # Assemble in LSB-first order
                    value = value | (bit_value << i)
            else:
                # Big-endian: bits read MSB-first within bytes
                for i in range(n_bits):
                    byte_idx = (bit_offset + i) // 8
                    bit_in_byte = 7 - ((bit_offset + i) % 8)  # MSB-first: bit 7 is first
                    
                    if byte_idx >= len(iq_data_bytes):
                        break
                    
                    # Read the bit from the byte
                    bit_value = (iq_data_bytes[byte_idx] >> bit_in_byte) & 1
                    # Assemble in MSB-first order
                    value = (value << 1) | bit_value
            
            return value, bit_offset + n_bits
        
        for i in range(num_samples):
            # Read I component (N bits)
            i_compressed, bit_offset = read_n_bits(bit_offset, bits_per_sample)
            
            # Read Q component (N bits)
            q_compressed, bit_offset = read_n_bits(bit_offset, bits_per_sample)
            
            # Convert to signed using two's complement
            # If MSB is set, treat as negative
            if i_compressed >= signed_offset:
                i_signed = i_compressed - (signed_offset * 2)
            else:
                i_signed = i_compressed
            
            if q_compressed >= signed_offset:
                q_signed = q_compressed - (signed_offset * 2)
            else:
                q_signed = q_compressed
            
            i_val = i_signed * scale_factor
            q_val = q_signed * scale_factor
            samples.append(complex(i_val, q_val))
    else:
        raise ValueError(f"Unsupported bits_per_sample: {bits_per_sample}. Supported range: 8-14")
    
    return samples

def parse_iq_samples(ecpri_data, iq_offset, payload_version, filter_index, force_bfp=False, bfp_exponent=None, bfp_bitwidth=None, max_rbs=106):
    """
    Parse IQ samples from eCPRI packet.
    
    Args:
        ecpri_data: eCPRI packet data (bytes)
        iq_offset: Offset to start of IQ data
        payload_version: Payload version from radio header
        filter_index: Filter index from radio header
        force_bfp: Force BFP decompression
        bfp_exponent: Unused
        bfp_bitwidth: Unused
    
    Returns:
        tuple: (samples_list, compression_type, num_samples, exponents_list)
        where exponents_list is a list of exponents (one per RB) or None if uncompressed
    """
    global debug_count
    iq_data_bytes = ecpri_data[iq_offset:]
    samples = []
    compression_type = "uncompressed"
    exponents_list = None
    
    if len(iq_data_bytes) == 0:
        return samples, compression_type, 0, exponents_list
    
    if FORCE_COMPRESSION_TYPE is None:
        raise ValueError("FORCE_COMPRESSION_TYPE must be set")
    
    config_compression_type = FORCE_COMPRESSION_TYPE.lower()
    if config_compression_type not in ['bfp', 'uncompressed']:
        raise ValueError(f"Invalid FORCE_COMPRESSION_TYPE: {FORCE_COMPRESSION_TYPE}")
    
    use_bfp = (config_compression_type == 'bfp') or force_bfp
    use_uncompressed = (config_compression_type == 'uncompressed')
    
    if use_bfp:
        bfp_bits = bfp_bitwidth if bfp_bitwidth is not None else FORCE_BFP_BITWIDTH
        
        if bfp_bits is None:
            raise ValueError("FORCE_BFP_BITWIDTH must be set")
        if bfp_bits < 8 or bfp_bits > 14:
            raise ValueError(f"Invalid BFP bitwidth: {bfp_bits}")

        samples_per_rb = 12
        # max_rbs is now passed as parameter (dynamically determined from ORAN section tree)
        
        # In BFP, there's typically one exponent per Resource Block (RB)
        # Each RB has 12 subcarriers (samples)
        # Calculate bytes per sample for compressed data
        if bfp_bits == 8:
            bytes_per_sample = 2  # 1 byte I + 1 byte Q
        else:
            # For N-bit compression: (2*N) bits per sample
            bytes_per_sample = (2 * bfp_bits) / 8
        
        # Strategy: Try to determine number of RBs by working backwards from data size
        # Total size = num_rbs (exponent bytes) + (num_rbs * 12 * bytes_per_sample) (compressed data)
        # So: total_size = num_rbs * (1 + 12 * bytes_per_sample)
        # Therefore: num_rbs = total_size / (1 + 12 * bytes_per_sample)
        
        total_bytes = len(iq_data_bytes)
        estimated_rbs = int(total_bytes / (1 + 12 * bytes_per_sample))
        
        # Clamp to reasonable range (1 to max_rbs)
        estimated_rbs = max(1, min(estimated_rbs, max_rbs))
        
        # Try reading that many exponents, but also try reading more if the pattern suggests it
        # Read exponents: try estimated_rbs first, but also check if we can read more
        exponents_list = []
        exponent_offset = 0
        
        # Read up to max_rbs exponent bytes, but stop if we encounter values > 15
        # (which are unlikely to be exponents)
        for i in range(min(estimated_rbs, max_rbs, len(iq_data_bytes))):
            exp_byte = iq_data_bytes[i]
            if exp_byte > 15:
                # This might be compressed data, stop here
                break
            exponents_list.append(int(exp_byte))
            exponent_offset = i + 1
        
        # If we read fewer exponents than estimated, try reading a few more
        # (in case some exponents are > 15, which is valid but less common)
        if len(exponents_list) < estimated_rbs and exponent_offset < len(iq_data_bytes):
            # Try reading a few more bytes as exponents
            for i in range(exponent_offset, min(exponent_offset + 10, len(iq_data_bytes))):
                exp_byte = iq_data_bytes[i]
                if exp_byte > 15:
                    break
                exponents_list.append(int(exp_byte))
                exponent_offset = i + 1
        
        # If we still don't have exponents, fall back to single exponent
        if len(exponents_list) == 0:
            # Fallback: use single exponent
            exponent = iq_data_bytes[0]
            if exponent < 0 or exponent > 15:
                raise ValueError(f"Invalid BFP exponent: {exponent}")
            exponents_list = [int(exponent)]
            compressed_data = iq_data_bytes[1:]
            exponent = exponents_list[0]
        else:
            # Use the exponents we found
            compressed_data = iq_data_bytes[exponent_offset:]
            # Use the first exponent for decompression (decompress function only supports one)
            exponent = exponents_list[0]
        
        try:
            # Decompress using the first exponent
            samples = decompress_bfp(compressed_data, exponent, bits_per_sample=bfp_bits)
            compression_type = f"BFP_{bfp_bits}bit"
            
            # Calculate actual number of RBs from decompressed samples
            actual_num_rbs = int(np.ceil(len(samples) / samples_per_rb))
            
            # Adjust exponents list to match actual number of RBs
            if len(exponents_list) == 1:
                # Single exponent case - replicate for all RBs
                exponents_list = exponents_list * actual_num_rbs
            elif len(exponents_list) > actual_num_rbs:
                # Truncate if we read too many
                exponents_list = exponents_list[:actual_num_rbs]
            elif len(exponents_list) < actual_num_rbs:
                # Extend with last exponent if we didn't read enough
                last_exp = exponents_list[-1] if exponents_list else 0
                exponents_list.extend([last_exp] * (actual_num_rbs - len(exponents_list)))
            
            return samples, compression_type, len(samples), exponents_list
        except Exception as e:
            raise ValueError(f"BFP decompression failed: {e}")
    
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
        
        # Detect if wrong compression settings are being used
        # Collect warnings for summary at end instead of printing immediately
        is_wrong, confidence, warnings = detect_wrong_compression_settings(
            iq_data_bytes[:num_samples*4], samples, compression_type, 
            configured_compression=FORCE_COMPRESSION_TYPE.lower(),
            configured_bitwidth=FORCE_BFP_BITWIDTH
        )
        # Store warnings globally for summary at end
        if is_wrong and warnings:
            # Only store if we don't already have similar warnings (avoid duplicates)
            warning_key = (confidence, warnings[0] if warnings else '')
            if not any(w.get('key') == warning_key for w in _compression_warnings):
                _compression_warnings.append({'confidence': confidence, 'warnings': warnings, 'key': warning_key})
    
    return samples, compression_type, num_samples, exponents_list

def parse_iq_from_prb_raw(prb_raw, compression_method, compression_width, max_rbs=106):
    """
    Parse IQ samples from prb_raw list structure.
    
    Args:
        prb_raw: List of lists, where each inner list contains [hex_string, offset, length, ...]
        compression_method: Compression method (1 = BFP, 0 = uncompressed)
        compression_width: Compression width in bits (for BFP: 8-14)
    
    Returns:
        tuple: (samples_list, compression_type, num_samples, exponents_list)
    """
    global debug_count
    samples = []
    compression_type = "uncompressed"
    exponents_list = None
    
    if not prb_raw or not isinstance(prb_raw, list):
        return samples, compression_type, 0, exponents_list
    
    # Collect all hex strings from prb_raw
    all_hex_data = []
    for prb_entry in prb_raw:
        if isinstance(prb_entry, list) and len(prb_entry) > 0:
            hex_str = prb_entry[0]
            if isinstance(hex_str, str):
                # Optimize: Use translate/str.maketrans for faster character removal (or regex for one pass)
                # Remove spaces/colons in one pass using translate (faster than multiple replace calls)
                hex_clean = hex_str.translate(str.maketrans('', '', ': '))
                try:
                    hex_bytes = bytes.fromhex(hex_clean)
                    all_hex_data.append(hex_bytes)
                except ValueError:
                    continue

    if not all_hex_data:
        return samples, compression_type, 0, exponents_list
    
    # Concatenate all hex data
    iq_data_bytes = b''.join(all_hex_data)
    
    if len(iq_data_bytes) == 0:
        return samples, compression_type, 0, exponents_list
    
    # Parse based on compression method
    # compression_method: 1 = BFP, 0 = uncompressed
    # Handle string input for backward compatibility
    if isinstance(compression_method, str):
        compression_method = 1 if compression_method.upper() == 'BFP' else 0
    
    if compression_method == 1:  # BFP compression
        if compression_width < 8 or compression_width > 14:
            compression_width = FORCE_BFP_BITWIDTH if FORCE_BFP_BITWIDTH else 9
        
        # Structure: Exponent (1 byte) + IQ data for RB, repeated for each RB
        # Each RB has 12 samples
        samples_per_rb = 12
        
        # Calculate bytes per RB for compressed data
        if compression_width == 8:
            bytes_per_sample = 2  # 1 byte I + 1 byte Q
        else:
            # For N-bit compression: (2*N) bits per sample
            bytes_per_sample = (2 * compression_width) / 8
        
        bytes_per_rb = int(samples_per_rb * bytes_per_sample)
        
        # Parse interleaved structure: exponent (1 byte) + IQ data (bytes_per_rb bytes) per RB
        exponents_list = []
        all_compressed_data = []
        offset = 0
        # max_rbs is now passed as parameter (dynamically determined from ORAN section tree)
        
        while offset < len(iq_data_bytes) and len(exponents_list) < max_rbs:
            # Check if we have enough bytes for exponent + RB data
            if offset + 1 + bytes_per_rb > len(iq_data_bytes):
                break
            
            # Read exponent (1 byte)
            exponent = int(iq_data_bytes[offset])
            if exponent > 15:
                # Invalid exponent, stop parsing
                break
            
            exponents_list.append(exponent)
            offset += 1
            
            # Read compressed IQ data for this RB
            rb_data = iq_data_bytes[offset:offset + bytes_per_rb]
            all_compressed_data.append((exponent, rb_data))
            offset += bytes_per_rb

        if len(exponents_list) == 0:
            # No valid RB data found
            return samples, compression_type, 0, None
        
        # Decompress each RB's data with its own exponent
        all_samples = []
        for exponent, rb_compressed_data in all_compressed_data:
            try:
                rb_samples = decompress_bfp(rb_compressed_data, exponent, bits_per_sample=compression_width)
                all_samples.extend(rb_samples)
            except Exception as e:
                print(f"BFP decompression failed for RB with exponent {exponent}: {e}")
                # Continue with other RBs
                continue
        
        samples = all_samples
        compression_type = f"BFP_{compression_width}bit"
    else:
        # Uncompressed: 16-bit signed integers (big-endian)
        num_samples = len(iq_data_bytes) // 4
        if num_samples > 0:
            iq_array = np.frombuffer(iq_data_bytes[:num_samples*4], dtype='>i2')
            iq_reshaped = iq_array.reshape(num_samples, 2)
            samples = (iq_reshaped[:, 0] + 1j * iq_reshaped[:, 1]).tolist()
            
            # Detect if wrong compression settings are being used
            # Collect warnings for summary at end instead of printing immediately
            is_wrong, confidence, warnings = detect_wrong_compression_settings(
                iq_data_bytes[:num_samples*4], samples, compression_type,
                configured_compression='uncompressed' if compression_method == 0 else 'bfp',
                configured_bitwidth=compression_width
            )
            # Store warnings globally for summary at end
            if is_wrong and warnings:
                # Only store if we don't already have similar warnings (avoid duplicates)
                warning_key = (confidence, warnings[0] if warnings else '')
                if not any(w.get('key') == warning_key for w in _compression_warnings):
                    _compression_warnings.append({'confidence': confidence, 'warnings': warnings, 'key': warning_key})
    
    return samples, compression_type, len(samples), exponents_list

def extract_oran_fh_data_from_packet(packet):
    """
    Extract ORAN FH CUS data from a pyshark packet.
    Returns the raw ORAN FH payload bytes, or None if not an ORAN FH packet.
    """
    try:
        # First, try to get data from ORAN FH CUS layer if it exists
        oran_layer = None
        # Try both lowercase and uppercase variations
        layer_names_to_try = ['oran_fh_cus', 'ORAN_FH_CUS', 'oran', 'ORAN', 'fh_cus', 'FH_CUS', 'cus', 'CUS']
        
        for layer_name in layer_names_to_try:
            if layer_name in packet:
                try:
                    oran_layer = getattr(packet, layer_name)
                    break
                except AttributeError:
                    continue
        
        # If not found by direct name, check all layers
        if oran_layer is None and hasattr(packet, 'layers'):
            for layer in packet.layers:
                layer_name = layer.layer_name
                layer_name_lower = layer_name.lower()
                if 'oran' in layer_name_lower or 'fh_cus' in layer_name_lower or 'cus' in layer_name_lower:
                    oran_layer = layer
                    break
        
        # Try to get payload from ORAN layer
        if oran_layer is not None:
            try:
                # Try to get raw payload from the layer
                if hasattr(oran_layer, 'payload'):
                    payload_hex = str(oran_layer.payload)
                    if payload_hex:
                        return bytes.fromhex(payload_hex.replace(':', '').replace(' ', ''))
                # Try to get data field
                if hasattr(oran_layer, 'data'):
                    data_hex = str(oran_layer.data)
                    if data_hex:
                        return bytes.fromhex(data_hex.replace(':', '').replace(' ', ''))
            except Exception as e:
                print(f"Exception getting data from ORAN layer: {e}")
                pass
        
        return None
    except Exception as e:
        print(f"Exception in extract_oran_fh_data_from_packet: {e}")
        return None

def get_oran_fh_cus_fields_from_packet(packet):
    """
    Extract ORAN FH CUS (Control User Synchronization) fields from a pyshark packet.
    Returns a dict with parsed fields, or None if not an ORAN FH packet.
    
    ORAN FH CUS header structure (from O-RAN.WG4.CUS.0-v04.00):
    - Section Type (1 byte)
    - Section Extension (1 byte) 
    - Section ID (2 bytes)
    - RU Port ID (1 byte)
    - Frame ID (1 byte)
    - Subframe ID (1 byte)
    - Slot ID (1 byte)
    - Start Symbol ID (1 byte)
    - Number of Symbols (1 byte)
    - ... (additional fields)
    """
    try:
        fields = {}
        
        # Try to find ORAN FH CUS layer
        oran_layer = None
        # Try both lowercase and uppercase variations
        layer_names_to_try = ['oran_fh_cus', 'ORAN_FH_CUS', 'oran', 'ORAN', 'fh_cus', 'FH_CUS', 'cus', 'CUS']
        
        # Check if any ORAN layer exists
        for layer_name in layer_names_to_try:
            if layer_name in packet:
                try:
                    oran_layer = getattr(packet, layer_name)
                    break
                except AttributeError:
                    continue
        
        # If not found by direct name, check all layers
        if oran_layer is None and hasattr(packet, 'layers'):
            for layer in packet.layers:
                layer_name = layer.layer_name
                layer_name_lower = layer_name.lower()
                if 'oran' in layer_name_lower or 'fh_cus' in layer_name_lower or 'cus' in layer_name_lower:
                    oran_layer = layer
                    break
        
        #LOCKED: DO NOT TOUCH THIS CODE UNTIL UNLOCKED
        # If we found the layer, try to extract fields from Wireshark's parsed data
        if oran_layer is not None:

            #Try to get RU Port ID
            ecpri_header_tree = None
            for ecpri_path in ['ecpriRtcid', 'ecpriRtcid_raw']:
                try:
                    ecpri_header_tree = getattr(oran_layer, ecpri_path, None)
                    if ecpri_header_tree is not None:
                        break
                except (AttributeError, TypeError):
                    continue

            if ecpri_header_tree is not None:
                try:
                    val = ecpri_header_tree.ruPortId
                    if hasattr(val, 'get_default_value'):
                        val = val.get_default_value()
                    elif hasattr(val, 'show'):
                        val = val.show
                    fields['ru_port_id'] = int(val)
                except (ValueError, TypeError, AttributeError):
                    try:
                        val = int(ecpri_header_tree.ruPortId_raw[0])
                        fields['ru_port_id'] = val
                    except (ValueError, TypeError, AttributeError):
                        pass
            # Try to get Timing Header Tree
            timing_header_tree = None
            for timing_path in ['timingHeader_tree', 'timing_header_tree']:
                try:
                    timing_header_tree = getattr(oran_layer, timing_path, None)
                    if timing_header_tree is not None:
                        break
                except (AttributeError, TypeError):
                    continue

            if timing_header_tree is not None:
                # Extract fields from timing header tree
                # Timing Header Tree Contains:
                # subframe_id
                # slotId
                # frameId
                # symbolId
                # data_direction
                try:
                    # Extract subframe_id
                    if hasattr(timing_header_tree, 'subframe_id'):
                        try:
                            val = timing_header_tree.subframe_id
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['subframe_id'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    
                    # Extract slotId
                    if hasattr(timing_header_tree, 'slotId'):
                        try:
                            val = timing_header_tree.slotId
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['slot_id'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    # Extract frameId
                    if hasattr(timing_header_tree, 'frameId'):
                        try:
                            val = timing_header_tree.frameId
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['frame_id'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    
                    # Extract symbolId
                    if hasattr(timing_header_tree, 'symbolId'):
                        try:
                            val = timing_header_tree.symbolId
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['start_symbol_id'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    
                    # Extract data_direction
                    if hasattr(timing_header_tree, 'data_direction'):
                        try:
                            val = timing_header_tree.data_direction
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['data_direction'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                except Exception as e:
                    print(f"Exception parsing timing_header_tree: {e}")
                    import traceback
                    traceback.print_exc()

            # Try to get u-plane.section_tree or c-plane.section_tree
            section_tree = None
            for tree_path in ['u-plane.section_tree', 'c-plane.section_tree', 'section_tree']:
                try:
                    section_tree = getattr(oran_layer, tree_path, None)
                    if section_tree is not None:
                        break
                except (AttributeError, TypeError):
                    continue
            
            if section_tree is not None:
                # Extract fields directly from section_tree attributes
                try:
                    # Map section_tree attributes to our field names
                    # Based on the attributes: sectionId, numPrbu, startPrbu, rb, symInc, etc.
                    
                    # Section ID (section_id in section_tree)
                    if hasattr(section_tree, 'sectionId'):
                        try:
                            val = section_tree.sectionId
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['sectionId'] = val
                        except (ValueError, TypeError, AttributeError):
                            pass

                    # PRB IQ Data (prb_raw in section_tree)
                    # prb_raw is a list, the first item contains the IQ data, if compression is used, the first byte is the exponent. The rest of the list contains the IQ data.
                    if hasattr(section_tree, 'prb_raw'):
                        try:
                            val = section_tree.prb_raw
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['prb_raw'] = val
                        except (ValueError, TypeError, AttributeError):
                            pass
                    
                    # Start PRB (startPrbu in section_tree)
                    if hasattr(section_tree, 'startPrbu'):
                        try:
                            val = section_tree.startPrbu
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['start_prbc'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    
                    # Number of PRB (numPrbu in section_tree)
                    if hasattr(section_tree, 'numPrbu'):
                        try:
                            val = section_tree.numPrbu
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['num_prbc'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                            
                    # Symbol increment (symInc) - might relate to number of symbols
                    if hasattr(section_tree, 'symInc'):
                        try:
                            val = section_tree.symInc
                            if hasattr(val, 'get_default_value'):
                                val = val.get_default_value()
                            elif hasattr(val, 'show'):
                                val = val.show
                            fields['sym_inc'] = int(val)
                        except (ValueError, TypeError, AttributeError):
                            pass
                    
                    # Compression method. Hardcoded from top variables
                    # Convert string to integer: 'BFP' -> 1, 'uncompressed' -> 0
                    if FORCE_COMPRESSION_TYPE.upper() == 'BFP':
                        fields['compression_method'] = 1
                    else:
                        fields['compression_method'] = 0
                    
                    # Compression width. Hardcoded from top variables
                    fields['compression_width'] = FORCE_BFP_BITWIDTH
                    
                except Exception as e:
                    print(f"Exception parsing section_tree: {e}")
                    import traceback
                    traceback.print_exc()
        #UNLOCKED

        
        # If we got fields from Wireshark's parsed layer, return them
        if fields:
            return fields
        
        # Fallback: Try to parse from raw data if layer parsing didn't work
        oran_data = extract_oran_fh_data_from_packet(packet)
        if oran_data is None or len(oran_data) < 8:
            print("Fallback: oran_data is None or too short")
            return None
        
        # Parse ORAN FH CUS header (minimum 8 bytes for basic header)
        try:
            # Section Type (byte 0)
            fields['section_type'] = oran_data[0]
            
            # Section Extension (byte 1)
            fields['section_extension'] = oran_data[1]
            
            # Section ID (bytes 2-3, big-endian)
            fields['section_id'] = struct.unpack('!H', oran_data[2:4])[0]
            
            # Frame ID (byte 4)
            fields['frame_id'] = oran_data[4]
            
            # Subframe ID (byte 5)
            fields['subframe_id'] = oran_data[5]
            
            # Slot ID (byte 6)
            fields['slot_id'] = oran_data[6]
            
            # Start Symbol ID (byte 7)
            fields['start_symbol_id'] = oran_data[7]
            
            # Number of Symbols (byte 8, if available)
            if len(oran_data) > 8:
                fields['num_symbols'] = oran_data[8]
            
            # Additional fields depend on section type and extension
            # For now, return what we have
            
            return fields
        except Exception as e:
            print(f"Exception in fallback raw data parsing: {e}")
            return None
    except Exception as e:
        print(f"Exception in get_oran_fh_cus_fields_from_packet: {e}")
        return None

def _process_packet_batch(args):
    """Worker function to process a batch of packets in parallel
    
    Args:
        args: tuple of (packet_data_list, force_bfp, bfp_exponent, FORCE_COMPRESSION_TYPE, FORCE_BFP_BITWIDTH, ENDIAN)
            where packet_data_list is a list of dicts containing:
                - fields: dict of extracted fields
                - prb_raw: raw PRB data (list) or None
                - oran_data: raw ORAN data bytes or None
                - max_rbs: maximum RBs to parse
    
    Returns:
        dict: Results containing samples, metadata, statistics for this batch
    """
    packet_data_list, force_bfp, bfp_exponent, FORCE_COMPRESSION_TYPE, FORCE_BFP_BITWIDTH, ENDIAN = args
    import numpy as np
    from collections import defaultdict
    
    # Import functions needed by worker
    # When using multiprocessing, functions need to be importable
    # Try multiple strategies to get the functions
    import sys
    import importlib
    
    parse_iq_from_prb_raw_func = None
    parse_iq_samples_func = None
    calculate_max_iq_func = None
    
    # Strategy 1: Try importing from PCAP_Analyzer_WS module
    try:
        module = importlib.import_module('PCAP_Analyzer_WS')
        parse_iq_from_prb_raw_func = getattr(module, 'parse_iq_from_prb_raw', None)
        parse_iq_samples_func = getattr(module, 'parse_iq_samples', None)
        calculate_max_iq_func = getattr(module, 'calculate_max_iq', None)
    except ImportError:
        pass
    
    # Strategy 2: Try getting from __main__ (when run as script)
    if not parse_iq_from_prb_raw_func:
        main_module = sys.modules.get('__main__')
        if main_module and hasattr(main_module, 'parse_iq_from_prb_raw'):
            parse_iq_from_prb_raw_func = main_module.parse_iq_from_prb_raw
            parse_iq_samples_func = main_module.parse_iq_samples
            calculate_max_iq_func = main_module.calculate_max_iq
    
    # Strategy 3: Try getting from current module
    if not parse_iq_from_prb_raw_func:
        current_module = sys.modules.get(__name__)
        if current_module:
            parse_iq_from_prb_raw_func = getattr(current_module, 'parse_iq_from_prb_raw', None)
            parse_iq_samples_func = getattr(current_module, 'parse_iq_samples', None)
            calculate_max_iq_func = getattr(current_module, 'calculate_max_iq', None)
    
    # If still no functions, cannot proceed
    if not parse_iq_from_prb_raw_func or not parse_iq_samples_func or not calculate_max_iq_func:
        return {'packet_results': [], 'compression_types': [], 'max_iq_values': {}}
    
    batch_results = {
        'packet_results': [],
        'compression_types': set(),
        'max_iq_values': defaultdict(lambda: {'max_i': 0.0, 'max_q': 0.0, 'max_abs': 0.0}),
        'compression_warnings': []  # Collect warnings from this batch
    }
    
    for packet_data in packet_data_list:
        try:
            fields = packet_data['fields']
            prb_raw = packet_data.get('prb_raw')
            oran_data = packet_data.get('oran_data')
            current_max_rbs = packet_data.get('max_rbs', 106)
            
            # Get compression method and width
            # If force_bfp is explicitly set (not None), override what Wireshark detected
            if force_bfp is not None:
                # User explicitly specified compression settings - use them
                compression_method = 1 if force_bfp else 0  # 1 = BFP, 0 = uncompressed
                compression_width = FORCE_BFP_BITWIDTH
            else:
                # No explicit setting - use what Wireshark detected from packet header
                compression_method = fields.get('compression_method', 1 if FORCE_COMPRESSION_TYPE.upper() == 'BFP' else 0)
                compression_width = fields.get('compression_width', FORCE_BFP_BITWIDTH)
            
            # Parse IQ samples
            samples = []
            compression_type = "uncompressed"
            num_samples = 0
            exponents_list = None
            
            if prb_raw is not None and parse_iq_from_prb_raw_func:
                samples, compression_type, num_samples, exponents_list = parse_iq_from_prb_raw_func(
                    prb_raw, compression_method, compression_width, max_rbs=current_max_rbs)
                # Detect compression warnings after parsing
                # Get raw bytes from prb_raw to pass to detection function
                if samples and len(samples) > 0:
                    try:
                        # Reconstruct raw bytes from prb_raw for detection
                        all_hex_data = []
                        for prb_entry in prb_raw:
                            if isinstance(prb_entry, list) and len(prb_entry) > 0:
                                hex_str = prb_entry[0]
                                if isinstance(hex_str, str):
                                    hex_clean = hex_str.translate(str.maketrans('', '', ': '))
                                    try:
                                        hex_bytes = bytes.fromhex(hex_clean)
                                        all_hex_data.append(hex_bytes)
                                    except ValueError:
                                        continue
                        if all_hex_data:
                            iq_data_bytes = b''.join(all_hex_data)
                            detect_module = importlib.import_module('PCAP_Analyzer_WS')
                            detect_func = getattr(detect_module, 'detect_wrong_compression_settings', None)
                            if detect_func:
                                is_wrong, confidence, warnings = detect_func(
                                    iq_data_bytes, samples, compression_type,
                                    configured_compression='uncompressed' if compression_method == 0 else 'bfp',
                                    configured_bitwidth=compression_width
                                )
                                if is_wrong and warnings:
                                    warning_key = (confidence, warnings[0] if warnings else '')
                                    warning_entry = {'confidence': confidence, 'warnings': warnings, 'key': warning_key}
                                    if not any(w.get('key') == warning_key for w in batch_results['compression_warnings']):
                                        batch_results['compression_warnings'].append(warning_entry)
                    except Exception as e:
                        # Silently continue if detection fails
                        pass
            elif oran_data is not None and parse_iq_samples_func:
                iq_offset = 8
                samples, compression_type, num_samples, exponents_list = parse_iq_samples_func(
                    oran_data, iq_offset, 0, 0,
                    force_bfp=force_bfp, bfp_exponent=bfp_exponent, bfp_bitwidth=FORCE_BFP_BITWIDTH, max_rbs=current_max_rbs)
                # Detect compression warnings after parsing
                if samples and len(samples) > 0:
                    try:
                        iq_data_bytes = oran_data[iq_offset:] if len(oran_data) > iq_offset else b''
                        detect_module = importlib.import_module('PCAP_Analyzer_WS')
                        detect_func = getattr(detect_module, 'detect_wrong_compression_settings', None)
                        if detect_func:
                            is_wrong, confidence, warnings = detect_func(
                                iq_data_bytes, samples, compression_type,
                                configured_compression=FORCE_COMPRESSION_TYPE.lower(),
                                configured_bitwidth=FORCE_BFP_BITWIDTH
                            )
                            if is_wrong and warnings:
                                warning_key = (confidence, warnings[0] if warnings else '')
                                warning_entry = {'confidence': confidence, 'warnings': warnings, 'key': warning_key}
                                if not any(w.get('key') == warning_key for w in batch_results['compression_warnings']):
                                    batch_results['compression_warnings'].append(warning_entry)
                    except Exception as e:
                        # Silently continue if detection fails
                        pass
            else:
                continue  # Skip if no data
            
            if len(samples) == 0:
                continue
            
            # Calculate max IQ values
            if calculate_max_iq_func:
                max_i, max_q, max_abs = calculate_max_iq_func(samples)
            else:
                # Fallback: simple calculation
                if samples:
                    samples_array = np.array(samples, dtype=complex)
                    max_i = float(np.max(np.abs(samples_array.real)))
                    max_q = float(np.max(np.abs(samples_array.imag)))
                    max_abs = max(max_i, max_q)
                else:
                    max_i, max_q, max_abs = 0.0, 0.0, 0.0
            
            # Get packet metadata from fields
            eaxc_id = fields.get('ru_port_id', 0)
            direction = 'DL' if fields.get('data_direction', 1) == 1 else 'UL'
            frame_id = fields.get('frame_id', 0)
            subframe_id = fields.get('subframe_id', 0)
            slot_id = fields.get('slot_id', 0)
            start_symbol_id = fields.get('start_symbol_id', 0)
            start_prbc = fields.get('start_prbc', 0)
            
            # Calculate RB non-zero detection
            rbs_with_data = set()
            samples_per_rb = 12
            num_rbs_in_samples = len(samples) // samples_per_rb
            if num_rbs_in_samples > 0:
                samples_array = np.array(samples[:num_rbs_in_samples * samples_per_rb], dtype=complex)
                rb_samples_2d = samples_array.reshape(num_rbs_in_samples, samples_per_rb)
                magnitudes = np.abs(rb_samples_2d)
                has_nonzero_per_rb = np.any(magnitudes > 1e-10, axis=1)
                for rb_idx in np.where(has_nonzero_per_rb)[0]:
                    actual_rb_index = start_prbc + rb_idx
                    rbs_with_data.add(actual_rb_index)
            
            # Get additional fields for analysis
            section_id = int(fields.get('sectionId', 0)) if 'sectionId' in fields else 0
            ru_port_id = fields.get('ru_port_id', 0) if 'ru_port_id' in fields else 0
            num_prbc = fields.get('num_prbc', None)
            sym_inc = fields.get('sym_inc', 0)
            num_symbols = sym_inc + 1 if sym_inc > 0 else 1
            
            # Prepare results for this packet
            packet_result = {
                'fields': fields,
                'samples': samples,
                'compression_type': compression_type,
                'num_samples': num_samples,
                'exponents_list': exponents_list,
                'max_i': max_i,
                'max_q': max_q,
                'max_abs': max_abs,
                'eaxc_id': eaxc_id,
                'direction': direction,
                'frame_id': frame_id,
                'subframe_id': subframe_id,
                'slot_id': slot_id,
                'start_symbol_id': start_symbol_id,
                'start_prbc': start_prbc,
                'rbs_with_data': list(rbs_with_data),  # Convert set to list for pickling
                'section_id': section_id,
                'ru_port_id': ru_port_id,
                'num_prbc': num_prbc,
                'num_symbols': num_symbols,
                'sym_inc': sym_inc
            }
            
            batch_results['packet_results'].append(packet_result)
            batch_results['compression_types'].add(compression_type)
            
            # Update max IQ values
            if max_abs > batch_results['max_iq_values'][eaxc_id]['max_abs']:
                batch_results['max_iq_values'][eaxc_id]['max_i'] = max_i
                batch_results['max_iq_values'][eaxc_id]['max_q'] = max_q
                batch_results['max_iq_values'][eaxc_id]['max_abs'] = max_abs
                
        except Exception as e:
            # Skip packets that cause errors
            continue
    
    # Convert sets to lists for pickling
    batch_results['compression_types'] = list(batch_results['compression_types'])
    batch_results['max_iq_values'] = dict(batch_results['max_iq_values'])
    
    return batch_results

def extract_iq_with_metadata(pcap_file, force_bfp=None, bfp_exponent=None, bfp_bitwidth=None, start_symbol=None, end_symbol=None, restrict_to_first_combo=False, use_parallel=True):
    """Extract IQ samples with direction and eAxC ID information using pyshark.
    Also collects analysis statistics for reporting.
    
    Args:
        use_parallel: If True, use parallel processing for packet batches. If False, process sequentially.
    
    Returns:
        tuple: (iq_data, analysis_data, total_packets)
    """
    # Clear compression warnings for this run
    global _compression_warnings
    _compression_warnings.clear()
    
    # Normalize path to handle relative paths correctly
    pcap_file = os.path.normpath(os.path.abspath(pcap_file))
    print(f"Reading {pcap_file} with pyshark...")
    
    # 5G NR typically has 14 symbols per slot (for normal cyclic prefix)
    SYMBOLS_PER_SLOT = 14
    # 5G NR has 10 subframes per frame
    SUBFRAMES_PER_FRAME = 10
    # Slots per subframe depends on numerology (0 = 1 slot, 1 = 2 slots)
    SLOTS_PER_SUBFRAME = 2 if NUMEROLOGY == 1 else 1
    
    # Track the first (frame, subframe, slot) combination for filtering
    first_frame_subframe_slot = None
    
    try:
        current_prefs = {}
        try:
            result = subprocess.run(
                ['tshark', '-G', 'defaultprefs'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for pref_name in pref_names:
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('#' + pref_name + ':'):
                        value = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                        current_prefs[pref_name] = value
                        print(f"  {pref_name}: {value}")
                        break
        except Exception as e:
            print(f"  Warning: Could not read current preferences: {e}")
        
        print("-" * 60)
        
        # Set ORAN FH CUS protocol preferences based on compression type
        # This ensures Wireshark/TShark dissects packets correctly
        # Use override_prefs (dictionary) instead of custom_parameters (command-line flags)
        # for a cleaner Python API
        
        # Set compression method preference for ORAN FH CUS
        # Use string values as specified in TShark preferences (case-insensitive)
        # Valid values: "COMP_NONE", "COMP_BLOCK_FP", "No Compression", "Block Floating Point Compression", etc.
        # force_bfp can be: None (use global), True (force BFP), or False (force uncompressed)
        if force_bfp is None:
            # Not explicitly set - use global
            use_bfp = (FORCE_COMPRESSION_TYPE.upper() == 'BFP')
        else:
            # Explicitly set by caller
            use_bfp = force_bfp
        
        bitwidth = bfp_bitwidth if bfp_bitwidth is not None else FORCE_BFP_BITWIDTH
        
        if use_bfp:
            compression_pref = 'COMP_BLOCK_FP'  # or 'Block Floating Point Compression'
            iq_bitwidth = str(bitwidth)
        else:
            compression_pref = 'COMP_NONE'  # or 'No Compression'
            iq_bitwidth = '16'
        
        # Create dictionary of ORAN FH CUS preferences for both uplink and downlink
        # override_prefs expects string values
        override_prefs = {
            'oran_fh_cus.oran.ud_comp_up': compression_pref,
            'oran_fh_cus.oran.iq_bitwidth_up': iq_bitwidth,
            'oran_fh_cus.oran.ud_comp_down': compression_pref,
            'oran_fh_cus.oran.iq_bitwidth_down': iq_bitwidth,
        }
        
        print(f"\nSetting ORAN FH CUS protocol preferences (force_bfp={force_bfp}, use_bfp={use_bfp}, bitwidth={bitwidth}):")
        print("-" * 60)
        for pref_name, pref_value in override_prefs.items():
            if "ud_comp" in pref_name:
                if pref_value == "COMP_BLOCK_FP" or pref_value == "Block Floating Point Compression":
                    comp_desc = "Block Floating Point Compression"
                elif pref_value == "COMP_NONE" or pref_value == "No Compression":
                    comp_desc = "No Compression"
                else:
                    comp_desc = pref_value
                print(f"  {pref_name}: {comp_desc} ({pref_value})")
            else:
                print(f"  {pref_name}: {pref_value}")
        print("-" * 60)
        print()
        
        # Set decode_as to decode UDP packets as ORAN FH CUS
        # This ensures packets are properly dissected even if not auto-detected
        # Note: decode_as format requires port-specific syntax: {'udp.port==PORT': 'oran_fh_cus'}
        # Since we don't know the specific port, we'll try to decode common ORAN ports
        # ORAN FH CUS typically uses ephemeral ports, so we'll skip decode_as for now
        # and rely on Wireshark's auto-detection, or set it conditionally if needed
        decode_as = None  # Disable decode_as to avoid TShark crashes - let Wireshark auto-detect
        # If you know the specific UDP port, uncomment and set it:
        # decode_as = {'udp.port==1234': 'oran_fh_cus'}  # Replace 1234 with actual port
        print("decode_as: Using Wireshark auto-detection for ORAN FH CUS protocol")
        print("  (If packets aren't detected, specify decode_as with known UDP port)")
        print()
        
        # IMPORTANT: Use custom_parameters with -o flags to ensure preferences are actually applied
        # override_prefs may not always work correctly, so we'll use both methods
        # Build custom_parameters list with -o flags for preferences (more reliable)
        custom_params = []
        for pref_name, pref_value in override_prefs.items():
            custom_params.extend(['-o', f'{pref_name}:{pref_value}'])
        
        print("Also setting preferences via custom_parameters (-o flags) for reliability:")
        print("-" * 60)
        for i in range(0, len(custom_params), 2):
            if i+1 < len(custom_params):
                print(f"  {custom_params[i]} {custom_params[i+1]}")
        print("-" * 60)
        print()
        
        # Open pcap file with pyshark
        # Try without display filter first, then filter in Python
        # Display filters can cause issues with some TShark versions
        try:
            # Optimization: Use keep_packets=False to avoid storing all packets in memory
            # This significantly speeds up processing for large PCAP files
            # Use BOTH override_prefs AND custom_parameters to ensure preferences are applied
            print("custom_params: ", custom_params)
            print("override_prefs: ", override_prefs)
            print("decode_as: ", decode_as)
            cap = pyshark.FileCapture(
                pcap_file, 
                use_json=True, 
                include_raw=True, 
                keep_packets=False,
                override_prefs=override_prefs,
                custom_parameters=custom_params if custom_params else None,
                decode_as=decode_as if decode_as else {}
            )
        except:
            try:
                cap = pyshark.FileCapture(
                    pcap_file, 
                    use_json=True, 
                    keep_packets=False,
                    override_prefs=override_prefs,
                    custom_parameters=custom_params if custom_params else None,
                    decode_as=decode_as if decode_as else {}
                )
            except:
                # Fallback to basic capture (without preferences if they cause issues)
                try:
                    cap = pyshark.FileCapture(
                        pcap_file, 
                        keep_packets=False,
                        override_prefs=override_prefs,
                        custom_parameters=custom_params if custom_params else None,
                        decode_as=decode_as if decode_as else {}
                    )
                except:
                    # Last resort: basic capture without preferences
                    cap = pyshark.FileCapture(pcap_file, keep_packets=False)
        
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        return {}, {}, 0
    
    # Helper function to create a new dict with a new set for rbs_with_data
    def make_frame_slot_data():
        return {'packets': 0, 'samples': 0, 'start_prbc': None, 'num_prbc': None, 'rbs_with_data': set()}
    
    # Organize by eAxC ID and direction
    iq_data = defaultdict(lambda: {'UL': [], 'DL': [], 'metadata': []})
    # Track maximum uncompressed I/Q values per eAxC ID
    max_iq_values = defaultdict(lambda: {'max_i': 0, 'max_q': 0, 'max_abs': 0})
    
    # Collect analysis data (same structure as analyze_pcap)
    analysis_data = {
        'eaxc_ids': set(),  # Using RU Port ID as eaxc_id
        'directions': set(),
        'frames': set(),
        'subframes': set(),
        'slots': set(),
        'slots_seen_in_fields': set(),
        'symbols': set(),
        'packet_timestamps': [],
        'packet_count': 0,
        'total_samples': 0,
        'eaxc_stats': defaultdict(lambda: {'UL': {'packets': 0, 'samples': 0}, 'DL': {'packets': 0, 'samples': 0}}),
        'symbol_counts': defaultdict(int),
        'overall_symbol_counts': defaultdict(int),
        'overall_symbol_unique_combos': defaultdict(set),
        'overall_symbol_eaxc_counts': defaultdict(lambda: defaultdict(int)),
        'overall_symbol_samples': defaultdict(int),
        'symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: {'packets': 0, 'samples': 0})),
        'slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(int))),
        'frame_subframe_slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(make_frame_slot_data))))),
        'compression_types': set(),
        'max_iq_values': defaultdict(lambda: {'max_i': 0.0, 'max_q': 0.0, 'max_abs': 0.0}),
        'max_num_prbc': 0,  # Maximum declared PRBs (from num_prbc field)
        'max_rb_index_with_data': 0,  # Maximum RB index that actually has IQ data
        'min_overall_symbol': None,  # Minimum overall symbol seen
        'compression_warnings': []  # Store compression detection warnings
    }
    
    print("Processing packets...")
    total_packets = 0
    # Cache the layer name after first successful detection to speed up subsequent packets
    cached_layer_name = None
    
    # Phase 1: Collect packet data in batches (sequential - fast field extraction)
    BATCH_SIZE = 50  # Process 50 packets per batch
    packet_batches = []
    current_batch = []
    
    print("Phase 1: Extracting packet fields and raw data...")
    for packet in cap:
        total_packets += 1  # Count all packets (single pass)
        try:
            # Skip non-ORAN FH packets early
            # Use cached layer name if available (optimization)
            has_oran_fh_cus = False
            if cached_layer_name:
                try:
                    if cached_layer_name in packet:
                        has_oran_fh_cus = True
                except:
                    cached_layer_name = None  # Cache invalidated, reset
            
            if not has_oran_fh_cus:
                # First, try checking with 'in' operator (pyshark typically uses lowercase)
                layer_checks = ['oran_fh_cus', 'ORAN_FH_CUS', 'oran', 'ORAN']
                for layer_name in layer_checks:
                    try:
                        if layer_name in packet:
                            has_oran_fh_cus = True
                            cached_layer_name = layer_name  # Cache for next packets
                            break
                    except:
                        pass
                
                # Also check all layer names directly (more reliable)
                if not has_oran_fh_cus and hasattr(packet, 'layers'):
                    for layer in packet.layers:
                        layer_name = layer.layer_name
                        layer_name_lower = layer_name.lower()
                        # Check for ORAN_FH_CUS or similar
                        if 'oran' in layer_name_lower and 'fh' in layer_name_lower:
                            has_oran_fh_cus = True
                            # Cache the actual layer name for faster lookups
                            try:
                                if layer_name in packet:
                                    cached_layer_name = layer_name
                            except:
                                pass
                            break
                        elif 'oran' in layer_name_lower or 'fh_cus' in layer_name_lower or 'cus' in layer_name_lower:
                            has_oran_fh_cus = True
                            try:
                                if layer_name in packet:
                                    cached_layer_name = layer_name
                            except:
                                pass
                            break
            
            if not has_oran_fh_cus:
                continue
            
            # Get ORAN FH CUS fields from packet
            fields = get_oran_fh_cus_fields_from_packet(packet)

            # If we couldn't parse ORAN FH fields, skip this packet
            if not fields:
                continue
            
            # Extract ORAN FH CUS fields using the actual field names from extraction
            section_id = int(fields.get('sectionId', 0)) if 'sectionId' in fields else 0
            # Use RU Port ID as eAxC ID (not section_id)
            ru_port_id = fields.get('ru_port_id', 0) if 'ru_port_id' in fields else 0
            eaxc_id = ru_port_id  # Use RU Port ID as eAxC ID
            frame_id = fields.get('frame_id', 0)
            subframe_id = fields.get('subframe_id', 0)
            slot_id = fields.get('slot_id', 0)
            start_symbol_id = fields.get('start_symbol_id', 0)
            
            # Track ALL slots seen in fields extraction (before filtering)
            analysis_data['slots_seen_in_fields'].add(slot_id)
            
            # Calculate overall symbol number: count continuously across frames, subframes, slots, and symbols
            overall_symbol = (frame_id * SUBFRAMES_PER_FRAME * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                            (subframe_id * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                            (slot_id * SYMBOLS_PER_SLOT) + \
                            start_symbol_id
            
            # Track first overall symbol seen (base for relative count)
            # Only set if we have valid timing info (frame_id is present in fields)
            if 'first_overall_symbol' not in analysis_data and 'frame_id' in fields:
                analysis_data['first_overall_symbol'] = overall_symbol
            
            # Calculate relative symbol
            if 'first_overall_symbol' in analysis_data:
                relative_symbol = overall_symbol - analysis_data['first_overall_symbol']
            else:
                # If we haven't found a valid start packet yet, we can't calculate relative symbol correctly
                # For filtering purposes, we can treat it as 0 or skip filtering
                relative_symbol = 0
            
            # Filter by relative symbol number if specified (must happen BEFORE incrementing packet_count)
            if start_symbol is not None or end_symbol is not None:
                if start_symbol is not None and relative_symbol < start_symbol:
                    continue
                if end_symbol is not None and relative_symbol > end_symbol:
                    continue
                
                # Only restrict to first frame/subframe/slot when using --symbols (not --start-symbol/--end-symbol)
                if restrict_to_first_combo:
                    # Identify the first (frame, subframe, slot) combination that matches the range
                    if first_frame_subframe_slot is None:
                        first_frame_subframe_slot = (frame_id, subframe_id, slot_id)
                    
                    # Only include packets from the first frame/subframe/slot combination
                    current_combo = (frame_id, subframe_id, slot_id)
                    if current_combo != first_frame_subframe_slot:
                        continue  # Skip packets not from the first frame/subframe/slot
            
            # Increment packet count only after filtering - this should match the sum of overall_symbol_counts
            analysis_data['packet_count'] += 1
            
            # Get packet timestamp
            try:
                if hasattr(packet, 'sniff_timestamp'):
                    timestamp = float(packet.sniff_timestamp)
                    analysis_data['packet_timestamps'].append(timestamp)
            except:
                pass
            
            # Calculate num_symbols from sym_inc or use default
            sym_inc = fields.get('sym_inc', 0)
            num_symbols = sym_inc + 1 if sym_inc > 0 else 1
            start_prbc = fields.get('start_prbc', 0)
            # Get num_prbc from fields (dynamically determined from ORAN section tree)
            num_prbc = fields.get('num_prbc', None)
            
            # Track maximum num_prbc and validate
            if num_prbc is not None:
                # Check if this packet exceeds the current maximum before updating
                if analysis_data.get('max_num_prbc', 0) > 0 and num_prbc > analysis_data['max_num_prbc']:
                    print(f"ERROR: Packet has {num_prbc} PRBs, which exceeds detected maximum of {analysis_data['max_num_prbc']} PRBs!")
                    print(f"  Frame: {frame_id}, Subframe: {subframe_id}, Slot: {slot_id}, Symbol: {start_symbol_id}, eAxC ID: {eaxc_id}")
                # Update maximum
                if num_prbc > analysis_data.get('max_num_prbc', 0):
                    analysis_data['max_num_prbc'] = num_prbc
            
            # Get compression method and width from fields (hardcoded from top variables)
            # Default to BFP if not set
            compression_method = fields.get('compression_method', 1 if FORCE_COMPRESSION_TYPE.upper() == 'BFP' else 0)
            compression_width = fields.get('compression_width', FORCE_BFP_BITWIDTH)
            prb_raw = fields.get('prb_raw', None)
            
            # Check if prb_raw is empty (empty list) - treat as None
            if prb_raw is not None and isinstance(prb_raw, list) and len(prb_raw) == 0:
                prb_raw = None
            
            # Determine direction from data_direction field (1 = DL, 0 = UL)
            data_direction = fields.get('data_direction', 1)
            direction = 'DL' if data_direction == 1 else 'UL'
            
            # Use max_num_prbc for parsing limits, default to calculated if not available
            current_max_rbs = analysis_data.get('max_num_prbc', 0) if analysis_data.get('max_num_prbc', 0) > 0 else (num_prbc if num_prbc is not None else 106)
            
            # Collect packet data for batch processing instead of processing immediately
            # Get raw ORAN data if prb_raw is not available or empty
            oran_data_bytes = None
            if prb_raw is None or (isinstance(prb_raw, list) and len(prb_raw) == 0):
                # First try the ORAN layer extraction
                oran_data_bytes = extract_oran_fh_data_from_packet(packet)
                
                # If extraction from ORAN layer failed, try getting from UDP layer as fallback
                if oran_data_bytes is None or len(oran_data_bytes) < 8:
                    try:
                        # Try to get raw data from UDP layer
                        if 'udp' in packet:
                            udp_layer = packet.udp
                            # Try payload field
                            if hasattr(udp_layer, 'payload'):
                                try:
                                    payload_hex = str(udp_layer.payload)
                                    if payload_hex:
                                        oran_data_bytes = bytes.fromhex(payload_hex.replace(':', '').replace(' ', ''))
                                except (ValueError, AttributeError):
                                    pass
                            
                            # Try data field if payload didn't work
                            if (oran_data_bytes is None or len(oran_data_bytes) < 8) and hasattr(udp_layer, 'data'):
                                try:
                                    data_hex = str(udp_layer.data)
                                    if data_hex:
                                        oran_data_bytes = bytes.fromhex(data_hex.replace(':', '').replace(' ', ''))
                                except (ValueError, AttributeError):
                                    pass
                            
                            # Also try to get from packet's raw data (if FileCapture was opened with include_raw=True)
                            if (oran_data_bytes is None or len(oran_data_bytes) < 8):
                                try:
                                    # In pyshark, raw packet data can be accessed in different ways depending on version
                                    # Try different methods to get raw packet bytes
                                    raw_bytes = None
                                    
                                    # Method 1: packet.raw attribute (if available)
                                    if hasattr(packet, 'raw') and packet.raw:
                                        try:
                                            raw_bytes = bytes(packet.raw)
                                        except:
                                            pass
                                    
                                    # Method 2: packet.get_raw_packet() method (if available)
                                    if raw_bytes is None and hasattr(packet, 'get_raw_packet'):
                                        try:
                                            raw_packet = packet.get_raw_packet()
                                            if raw_packet:
                                                raw_bytes = bytes(raw_packet) if isinstance(raw_packet, (bytes, bytearray)) else raw_packet
                                        except:
                                            pass
                                    
                                    # Method 3: Access through frame layer's raw field (if available)
                                    if raw_bytes is None and 'frame' in packet:
                                        try:
                                            frame_layer = packet.frame
                                            if hasattr(frame_layer, 'raw') and frame_layer.raw:
                                                raw_hex = str(frame_layer.raw)
                                                if raw_hex:
                                                    raw_bytes = bytes.fromhex(raw_hex.replace(':', '').replace(' ', ''))
                                        except:
                                            pass
                                    
                                    # If we got raw bytes, parse to extract UDP payload
                                    if raw_bytes and len(raw_bytes) > 42:  # Minimum size for Ethernet + IP + UDP headers
                                        # Parse Ethernet header (14 bytes)
                                        # Parse IP header (starts at byte 14, length in low nibble of byte 14)
                                        ip_header_start = 14
                                        if len(raw_bytes) > ip_header_start:
                                            ip_header_len = (raw_bytes[ip_header_start] & 0x0F) * 4  # IP header length
                                            udp_start = ip_header_start + ip_header_len
                                            if len(raw_bytes) > udp_start + 8:  # UDP header is 8 bytes
                                                payload_start = udp_start + 8
                                                oran_data_bytes = raw_bytes[payload_start:]
                                except Exception as e:
                                    # Silently fail - will check oran_data_bytes below
                                    pass
                    except Exception as e:
                        # Silently continue - will check if oran_data_bytes is valid below
                        pass
                
                if oran_data_bytes is None or len(oran_data_bytes) < 8:
                    continue
            
            # Create packet data entry for batch processing
            packet_data_entry = {
                'fields': fields,
                'prb_raw': prb_raw,
                'oran_data': oran_data_bytes,
                'max_rbs': current_max_rbs,
                'timestamp': None,
                'analysis_info': {  # Store info needed for analysis tracking
                    'section_id': section_id,
                    'ru_port_id': ru_port_id,
                    'eaxc_id': eaxc_id,
                    'frame_id': frame_id,
                    'subframe_id': subframe_id,
                    'slot_id': slot_id,
                    'start_symbol_id': start_symbol_id,
                    'overall_symbol': overall_symbol,
                    'direction': direction,
                    'num_symbols': num_symbols,
                    'start_prbc': start_prbc,
                    'num_prbc': num_prbc,
                    'sym_inc': sym_inc
                }
            }
            
            # Update min_overall_symbol
            if analysis_data['min_overall_symbol'] is None or overall_symbol < analysis_data['min_overall_symbol']:
                analysis_data['min_overall_symbol'] = overall_symbol
            
            # Get packet timestamp
            try:
                if hasattr(packet, 'sniff_timestamp'):
                    packet_data_entry['timestamp'] = float(packet.sniff_timestamp)
            except:
                pass
            
            # Add to current batch
            current_batch.append(packet_data_entry)
            
            # When batch is full, add to batches list
            if len(current_batch) >= BATCH_SIZE:
                packet_batches.append(current_batch)
                current_batch = []
            
            # Note: IQ parsing and statistics tracking will happen in Phase 2 (parallel processing)
            # All packet data has been collected in current_batch
            
        except Exception as e:
            # Skip packets that cause errors
            continue
    
    # Add remaining packets to a final batch
    if len(current_batch) > 0:
        packet_batches.append(current_batch)
    
    cap.close()
    print(f"Found {total_packets} total packets")
    print(f"Collected {len(packet_batches)} batches for processing\n")
    
    # Phase 2: Process batches (parallel or sequential based on use_parallel flag)
    if len(packet_batches) > 0:
        batch_results_list = []
        
        # Prepare batch arguments
        effective_compression = 'BFP' if use_bfp else 'uncompressed'
        effective_bitwidth = bitwidth
        
        batch_args = [
            (batch, force_bfp, bfp_exponent, effective_compression, effective_bitwidth, ENDIAN)
            for batch in packet_batches
        ]
        
        if use_parallel:
            print(f"Phase 2: Processing {len(packet_batches)} batches in parallel...")
            # Process batches in parallel
            max_workers = min(8, len(packet_batches))  # Limit to 8 workers
            with ProcessPoolExecutor(max_workers=max_workers) as executor:
                # Submit all batches
                future_to_batch = {executor.submit(_process_packet_batch, args): i for i, args in enumerate(batch_args)}
                
                # Collect results as they complete
                for future in as_completed(future_to_batch):
                    batch_idx = future_to_batch[future]
                    try:
                        batch_result = future.result()
                        batch_results_list.append((batch_idx, batch_result))
                    except Exception as e:
                        print(f"Error processing batch {batch_idx}: {e}")
            
            # Sort results by batch index to maintain order
            batch_results_list.sort(key=lambda x: x[0])
        else:
            print(f"Phase 2: Processing {len(packet_batches)} batches sequentially...")
            # Process batches sequentially
            for batch_idx, args in enumerate(batch_args):
                try:
                    batch_result = _process_packet_batch(args)
                    batch_results_list.append((batch_idx, batch_result))
                except Exception as e:
                    print(f"Error processing batch {batch_idx}: {e}")
        
        # Phase 3: Merge results from all batches
        print("Phase 3: Merging results...")
        for batch_idx, batch_result in batch_results_list:
            # Merge compression warnings from batch results
            if 'compression_warnings' in batch_result:
                for warning in batch_result['compression_warnings']:
                    if warning not in _compression_warnings:
                        _compression_warnings.append(warning)
            
            # Process each packet result from the batch
            for packet_result in batch_result.get('packet_results', []):
                # Extract data from packet result
                fields = packet_result['fields']
                samples = packet_result['samples']
                compression_type = packet_result['compression_type']
                num_samples = packet_result['num_samples']
                exponents_list = packet_result.get('exponents_list')
                max_i = packet_result['max_i']
                max_q = packet_result['max_q']
                max_abs = packet_result['max_abs']
                eaxc_id = packet_result['eaxc_id']
                direction = packet_result['direction']
                frame_id = packet_result['frame_id']
                subframe_id = packet_result['subframe_id']
                slot_id = packet_result['slot_id']
                start_symbol_id = packet_result['start_symbol_id']
                start_prbc = packet_result['start_prbc']
                rbs_with_data_list = packet_result.get('rbs_with_data', [])
                
                # Get analysis info from packet result (already computed in worker)
                section_id = packet_result.get('section_id', int(fields.get('sectionId', 0)) if 'sectionId' in fields else 0)
                ru_port_id = packet_result.get('ru_port_id', fields.get('ru_port_id', 0))
                num_prbc = packet_result.get('num_prbc', fields.get('num_prbc', None))
                sym_inc = packet_result.get('sym_inc', fields.get('sym_inc', 0))
                num_symbols = packet_result.get('num_symbols', sym_inc + 1 if sym_inc > 0 else 1)
                
                # Calculate overall_symbol
                overall_symbol = (frame_id * SUBFRAMES_PER_FRAME * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                                (subframe_id * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                                (slot_id * SYMBOLS_PER_SLOT) + \
                                start_symbol_id
                
                # Calculate relative symbol (relative to first symbol seen)
                first_overall_symbol = analysis_data.get('first_overall_symbol')
                if first_overall_symbol is None:
                    # Only set if we have valid timing info (frame_id is present in fields)
                    if 'frame_id' in fields:
                        first_overall_symbol = overall_symbol
                        analysis_data['first_overall_symbol'] = first_overall_symbol
                
                if first_overall_symbol is not None:
                    relative_symbol = overall_symbol - first_overall_symbol
                else:
                    relative_symbol = 0
                
                # Store samples
                if len(samples) > 0:
                    iq_data[eaxc_id][direction].extend(samples)
                
                # Track compression type
                analysis_data['compression_types'].add(compression_type)
                
                # Update max IQ values
                if max_abs > max_iq_values[eaxc_id]['max_abs']:
                    max_iq_values[eaxc_id]['max_i'] = max_i
                    max_iq_values[eaxc_id]['max_q'] = max_q
                    max_iq_values[eaxc_id]['max_abs'] = max_abs
                
                if max_abs > analysis_data['max_iq_values'][eaxc_id]['max_abs']:
                    analysis_data['max_iq_values'][eaxc_id]['max_i'] = max_i
                    analysis_data['max_iq_values'][eaxc_id]['max_q'] = max_q
                    analysis_data['max_iq_values'][eaxc_id]['max_abs'] = max_abs
                
                # Get exponents for metadata
                rb_exponents = None
                if compression_type.startswith('BFP') and exponents_list is not None:
                    rb_exponents = [int(exp) for exp in exponents_list]
                
                # Store metadata
                metadata_entry = {
                    'direction': direction,
                    'eaxc_id': eaxc_id,
                    'section_id': section_id,
                    'ru_port_id': ru_port_id,
                    'frame_id': frame_id,
                    'subframe_id': subframe_id,
                    'slot_id': slot_id,
                    'start_symbol_id': start_symbol_id,
                    'overall_symbol': overall_symbol,
                    'relative_symbol': relative_symbol,
                    'num_symbols': num_symbols,
                    'start_prbc': start_prbc,
                    'num_prbc': num_prbc,
                    'sym_inc': sym_inc,
                    'num_samples': num_samples,
                    'compression_type': compression_type,
                    'compression_method': fields.get('compression_method', 1 if FORCE_COMPRESSION_TYPE.upper() == 'BFP' else 0),
                    'compression_width': fields.get('compression_width', FORCE_BFP_BITWIDTH)
                }
                
                if rb_exponents is not None:
                    metadata_entry['rb_exponents'] = rb_exponents
                
                iq_data[eaxc_id]['metadata'].append(metadata_entry)
                
                # Update analysis statistics
                analysis_data['eaxc_ids'].add(eaxc_id)
                analysis_data['directions'].add(direction)
                analysis_data['frames'].add(frame_id)
                analysis_data['subframes'].add(subframe_id)
                analysis_data['slots'].add(slot_id)
                analysis_data['symbols'].add(start_symbol_id)
                analysis_data['total_samples'] += num_samples
                analysis_data['eaxc_stats'][eaxc_id][direction]['packets'] += 1
                analysis_data['eaxc_stats'][eaxc_id][direction]['samples'] += num_samples
                
                # Track symbol counts
                if start_symbol is not None or end_symbol is not None:
                    analysis_data['overall_symbol_counts'][overall_symbol] += 1
                    analysis_data['overall_symbol_samples'][overall_symbol] += num_samples
                    combo = (frame_id, subframe_id, slot_id, start_symbol_id, eaxc_id)
                    analysis_data['overall_symbol_unique_combos'][overall_symbol].add(combo)
                    analysis_data['overall_symbol_eaxc_counts'][overall_symbol][eaxc_id] += 1
                else:
                    analysis_data['symbol_counts'][start_symbol_id] += 1
                
                analysis_data['symbol_eaxc_data'][start_symbol_id][eaxc_id]['packets'] += 1
                analysis_data['symbol_eaxc_data'][start_symbol_id][eaxc_id]['samples'] += num_samples
                analysis_data['slot_symbol_eaxc_data'][slot_id][start_symbol_id][eaxc_id] += 1
                
                frame_slot_data = analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][start_symbol_id][eaxc_id]
                frame_slot_data['packets'] += 1
                frame_slot_data['samples'] += num_samples
                if frame_slot_data['start_prbc'] is None:
                    frame_slot_data['start_prbc'] = start_prbc
                if frame_slot_data['num_prbc'] is None:
                    frame_slot_data['num_prbc'] = num_prbc
                
                # Track RBs with data
                rbs_with_data = set(rbs_with_data_list)
                if len(samples) > 0 and len(rbs_with_data) > 0:
                    for rb_index in rbs_with_data:
                        frame_slot_data['rbs_with_data'].add(rb_index)
                        # Track maximum RB index with actual data
                        if rb_index > analysis_data.get('max_rb_index_with_data', 0):
                            analysis_data['max_rb_index_with_data'] = rb_index
        
        # Add timestamps from original batch entries
        for batch_idx, batch in enumerate(packet_batches):
            for packet_data_entry in batch:
                timestamp = packet_data_entry.get('timestamp')
                if timestamp is not None:
                    analysis_data['packet_timestamps'].append(timestamp)
        
        print("Merging complete.\n")
    
    # Return both IQ data and analysis data
    return iq_data, analysis_data, total_packets

def print_analysis_report(analysis_data, total_packets, start_symbol=None, end_symbol=None):
    """Print the analysis report using the collected analysis data"""
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
    print(f"  Total Packets:        {total_packets:,}")
    
    # When filtering by overall symbol, show only packets that match the filtered symbols
    if start_symbol is not None or end_symbol is not None:
        # Use the sum of overall_symbol_counts as the accurate count of filtered packets
        filtered_packet_count = sum(analysis_data['overall_symbol_counts'].values())
        filtered_samples_count = sum(analysis_data['overall_symbol_samples'].values())
        print(f"  IQ Data Packets:      {filtered_packet_count:,}")
        print(f"  Total IQ Samples:      {filtered_samples_count:,}")
    else:
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
        print("=" * 110)
        print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10} {'Max I/Q':<15} {'Est. IQ Backoff':<18}")
        print("=" * 110)
        for eaxc_id in eaxc_list:
            max_iq = analysis_data['max_iq_values'][eaxc_id]['max_abs']
            max_iq_str = f"{max_iq:.2f}" if max_iq > 0 else "N/A"
            dbfs = calculate_dbfs(max_iq)
            # Negate dBFS for backoff display: positive = backoff, negative = boost
            dbfs_str = f"{-dbfs:.2f} dBFS" if dbfs is not None else "N/A"
            for direction in ['UL', 'DL']:
                stats = analysis_data['eaxc_stats'][eaxc_id][direction]
                # When filtering, use stats only from filtered packets
                if start_symbol is not None or end_symbol is not None:
                    # Calculate filtered stats for this eAxC ID and direction
                    filtered_packets = 0
                    for overall_sym in analysis_data['overall_symbol_eaxc_counts']:
                        if eaxc_id in analysis_data['overall_symbol_eaxc_counts'][overall_sym]:
                            filtered_packets += analysis_data['overall_symbol_eaxc_counts'][overall_sym][eaxc_id]
                    # Estimate samples based on average samples per packet for this eAxC/direction
                    if filtered_packets > 0:
                        if stats['packets'] > 0:
                            avg_samples_per_packet = stats['samples'] / stats['packets']
                            filtered_samples = int(filtered_packets * avg_samples_per_packet)
                        else:
                            filtered_samples = 0
                        print(f"{eaxc_id:<10} {direction:<12} {filtered_samples:<15,} {filtered_packets:<10} {max_iq_str:<15} {dbfs_str:<18}")
                elif stats['packets'] > 0:
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
    if start_symbol is not None or end_symbol is not None:
        # When filtering by overall symbol, show overall symbols
        if analysis_data['overall_symbol_counts']:
            overall_symbol_list = sorted(analysis_data['overall_symbol_counts'].keys())
            first_overall_symbol = analysis_data.get('first_overall_symbol')
            if first_overall_symbol is None:
                first_overall_symbol = min(overall_symbol_list) if overall_symbol_list else 0
            
            # Calculate relative symbol range
            min_relative = min(overall_symbol_list) - first_overall_symbol if overall_symbol_list else 0
            max_relative = max(overall_symbol_list) - first_overall_symbol if overall_symbol_list else 0
            
            print(f"  Relative Symbol Numbers: {min_relative} to {max_relative} ({len(overall_symbol_list)} unique symbols)")
            print(f"  (Absolute: {min(overall_symbol_list)} to {max(overall_symbol_list)})")
            print(f"  Packets per relative symbol:")
            for overall_sym in overall_symbol_list:
                relative_sym = overall_sym - first_overall_symbol
                total_count = analysis_data['overall_symbol_counts'][overall_sym]
                unique_combos = len(analysis_data['overall_symbol_unique_combos'][overall_sym])
                eaxc_breakdown = analysis_data['overall_symbol_eaxc_counts'][overall_sym]
                
                print(f"    Relative Symbol {relative_sym:3d} (Abs: {overall_sym}): {total_count:4d} packets ({unique_combos} unique frame/subframe/slot/symbol/eAxC combos)")
                
                # Show the actual unique combinations to understand why there are multiple
                if unique_combos > 1 and unique_combos <= 20:  # Only show if reasonable number
                    print(f"      Unique combos for relative symbol {relative_sym}:")
                    for combo in sorted(analysis_data['overall_symbol_unique_combos'][overall_sym]):
                        frame_id, subframe_id, slot_id, symbol_id, eaxc_id = combo
                        print(f"        Frame {frame_id}, Subframe {subframe_id}, Slot {slot_id}, Symbol {symbol_id}, eAxC {eaxc_id}")
                
                if len(eaxc_breakdown) > 1:
                    # Show breakdown by eAxC ID if multiple eAxC IDs
                    for eaxc_id in sorted(eaxc_breakdown.keys()):
                        eaxc_count = eaxc_breakdown[eaxc_id]
                        print(f"      eAxC ID {eaxc_id}: {eaxc_count:4d} packets")
        else:
            print("  No overall symbol data found")
    else:
        # When not filtering, show symbol_ids within slots
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
    
    # Print detected maximum PRBs
    max_declared_prbs = analysis_data.get('max_num_prbc', 0)
    max_rb_index_with_data = analysis_data.get('max_rb_index_with_data', 0)
    
    if max_declared_prbs > 0:
        if max_rb_index_with_data > 0 and max_rb_index_with_data + 1 < max_declared_prbs:
            print(f"Detected maximum declared PRBs: {max_declared_prbs}")
            print(f"  (Maximum RB index with actual IQ data: {max_rb_index_with_data}, {max_rb_index_with_data + 1} RBs with data)")
        else:
            print(f"Detected maximum PRBs: {max_declared_prbs}\n")
    
    # Print compression warnings if any were detected
    if _compression_warnings:
        print("=" * 80)
        print("COMPRESSION SETTINGS WARNING")
        print("=" * 80)
        # Print the highest confidence warning (most reliable)
        best_warning = max(_compression_warnings, key=lambda x: x['confidence'])
        for warning in best_warning['warnings']:
            print(warning)
        print("=" * 80)
        print()

def save_separated_data(iq_data, output_base):
    """Save IQ data separated by eAxC ID and direction"""
    for eaxc_id in sorted(iq_data.keys()):
        # Save UL data
        if len(iq_data[eaxc_id]['UL']) > 0:
            ul_array = np.array(iq_data[eaxc_id]['UL'])
            filename = f"{output_base}_eAxC{eaxc_id}_UL"
            np.save(f"{filename}.npy", ul_array)
            print(f"Saved: {filename}.npy ({len(ul_array):,} samples)")
            
            # Save UL statistics
            avg_power = np.mean(np.abs(ul_array)**2)
            peak_power = np.max(np.abs(ul_array)**2)
            full_scale = 32767.0  # Full scale for 16-bit signed integers
            full_scale_power = full_scale ** 2
            avg_power_dbfs = 10 * math.log10(avg_power / full_scale_power) if avg_power > 0 else float('-inf')
            peak_power_dbfs = 10 * math.log10(peak_power / full_scale_power) if peak_power > 0 else float('-inf')
            
            # Calculate I and Q statistics in dBFS
            i_mean_abs = np.mean(np.abs(ul_array.real))
            i_max_abs = np.max(np.abs(ul_array.real))
            i_mean_dbfs = 20 * math.log10(i_mean_abs / full_scale) if i_mean_abs > 0 else float('-inf')
            i_max_dbfs = 20 * math.log10(i_max_abs / full_scale) if i_max_abs > 0 else float('-inf')
            
            q_mean_abs = np.mean(np.abs(ul_array.imag))
            q_max_abs = np.max(np.abs(ul_array.imag))
            q_mean_dbfs = 20 * math.log10(q_mean_abs / full_scale) if q_mean_abs > 0 else float('-inf')
            q_max_dbfs = 20 * math.log10(q_max_abs / full_scale) if q_max_abs > 0 else float('-inf')
            
            with open(f"{filename}_stats.txt", 'w') as f:
                f.write(f"eAxC ID: {eaxc_id}\n")
                f.write(f"Direction: Uplink (UL)\n")
                f.write(f"Total samples: {len(ul_array):,}\n")
                f.write(f"I - Mean: {i_mean_abs:.2f}, Max: {i_max_abs:.2f}\n")
                f.write(f"I - Mean (dBFS): {i_mean_dbfs:.2f}, Max (dBFS): {i_max_dbfs:.2f}\n")
                f.write(f"Q - Mean: {q_mean_abs:.2f}, Max: {q_max_abs:.2f}\n")
                f.write(f"Q - Mean (dBFS): {q_mean_dbfs:.2f}, Max (dBFS): {q_max_dbfs:.2f}\n")
                f.write(f"Average Power: {avg_power_dbfs:.2f} dBFS\n")
                f.write(f"Peak Power: {peak_power_dbfs:.2f} dBFS\n")
        
        # Save DL data
        if len(iq_data[eaxc_id]['DL']) > 0:
            dl_array = np.array(iq_data[eaxc_id]['DL'])
            filename = f"{output_base}_eAxC{eaxc_id}_DL"
            np.save(f"{filename}.npy", dl_array)
            print(f"Saved: {filename}.npy ({len(dl_array):,} samples)")
            
            # Save DL statistics
            avg_power = np.mean(np.abs(dl_array)**2)
            peak_power = np.max(np.abs(dl_array)**2)
            full_scale = 32767.0  # Full scale for 16-bit signed integers
            full_scale_power = full_scale ** 2
            avg_power_dbfs = 10 * math.log10(avg_power / full_scale_power) if avg_power > 0 else float('-inf')
            peak_power_dbfs = 10 * math.log10(peak_power / full_scale_power) if peak_power > 0 else float('-inf')
            
            # Calculate I and Q statistics in dBFS
            i_mean_abs = np.mean(np.abs(dl_array.real))
            i_max_abs = np.max(np.abs(dl_array.real))
            i_mean_dbfs = 20 * math.log10(i_mean_abs / full_scale) if i_mean_abs > 0 else float('-inf')
            i_max_dbfs = 20 * math.log10(i_max_abs / full_scale) if i_max_abs > 0 else float('-inf')
            
            q_mean_abs = np.mean(np.abs(dl_array.imag))
            q_max_abs = np.max(np.abs(dl_array.imag))
            q_mean_dbfs = 20 * math.log10(q_mean_abs / full_scale) if q_mean_abs > 0 else float('-inf')
            q_max_dbfs = 20 * math.log10(q_max_abs / full_scale) if q_max_abs > 0 else float('-inf')
            
            with open(f"{filename}_stats.txt", 'w') as f:
                f.write(f"eAxC ID: {eaxc_id}\n")
                f.write(f"Direction: Downlink (DL)\n")
                f.write(f"Total samples: {len(dl_array):,}\n")
                f.write(f"I - Mean: {i_mean_abs:.2f}, Max: {i_max_abs:.2f}\n")
                f.write(f"I - Mean (dBFS): {i_mean_dbfs:.2f}, Max (dBFS): {i_max_dbfs:.2f}\n")
                f.write(f"Q - Mean: {q_mean_abs:.2f}, Max: {q_max_abs:.2f}\n")
                f.write(f"Q - Mean (dBFS): {q_mean_dbfs:.2f}, Max (dBFS): {q_max_dbfs:.2f}\n")
                f.write(f"Average Power: {avg_power_dbfs:.2f} dBFS\n")
                f.write(f"Peak Power: {peak_power_dbfs:.2f} dBFS\n")
        
        # Save metadata
        metadata_file = f"{output_base}_eAxC{eaxc_id}_metadata.json"
        # Write JSON to string first
        json_str = json.dumps(iq_data[eaxc_id]['metadata'], indent=2)
        
        # Compress rb_exponents arrays to single line using regex
        # Pattern matches: "rb_exponents": [\n        <numbers>,\n        ...\n      ]
        def compress_rb_exponents(match):
            indent = match.group(1)  # Capture the indentation before "rb_exponents"
            array_content = match.group(2)  # Capture all the array content (numbers, commas, newlines)
            # Extract all numbers from the array content
            numbers = re.findall(r'\d+', array_content)
            # Join them with comma and space
            compressed = ', '.join(numbers)
            return f'{indent}"rb_exponents": [{compressed}]'
        
        # Pattern to match rb_exponents arrays with multiline formatting
        # Uses a more general approach: match everything between [ and ] for rb_exponents
        # This handles any formatting within the array
        pattern = r'(\s+)"rb_exponents": \[([^\]]+)\]'
        json_str = re.sub(pattern, compress_rb_exponents, json_str, flags=re.DOTALL)
        
        with open(metadata_file, 'w') as f:
            f.write(json_str)
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
    
    Args:
        start_symbol: Relative symbol number (start) - relative to first symbol in capture
        end_symbol: Relative symbol number (end) - relative to first symbol in capture
    
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
    
    # Use input symbols directly as relative symbols
    if start_symbol is None:
        start_symbol = 0
    if end_symbol is None:
        end_symbol = float('inf')
    
    # Build mask by checking each packet's relative overall symbol
    current_sample_index = 0
    
    for m in metadata:
        relative_symbol = m.get('relative_symbol')
        if relative_symbol is None:
            # Skip if we can't determine relative symbol
            mask[current_sample_index:current_sample_index + m['num_samples']] = True
            current_sample_index += m['num_samples']
            continue
        
        num_samples = m['num_samples']
        
        # Check if this relative symbol is in our range
        if start_symbol <= relative_symbol <= end_symbol:
            mask[current_sample_index:current_sample_index + num_samples] = True
        
        current_sample_index += num_samples
    
    return mask

def plot_comparison(iq_data, output_file, max_samples=10000, start_symbol=None, end_symbol=None, plots_dir=None, show_plot=False):
    """Create comparison plots for UL vs DL"""
    import matplotlib.pyplot as plt
    import os
    
    # If plots_dir is provided, update output_file to be in that directory
    if plots_dir is not None:
        os.makedirs(plots_dir, exist_ok=True)
        output_filename = os.path.basename(output_file)
        output_file = os.path.join(plots_dir, output_filename)
    
    # Find an eAxC ID that has both UL and DL data
    eaxc_with_both = None
    for eaxc_id in sorted(iq_data.keys()):
        if len(iq_data[eaxc_id]['UL']) > 0 and len(iq_data[eaxc_id]['DL']) > 0:
            eaxc_with_both = eaxc_id
            break
    
    if eaxc_with_both is None:
        print("No eAxC ID with both UL and DL data for comparison plot")
        return
    
    # Get all samples first
    ul_all_array = np.array(iq_data[eaxc_with_both]['UL'])
    dl_all_array = np.array(iq_data[eaxc_with_both]['DL'])
    ul_total_count = len(ul_all_array)
    dl_total_count = len(dl_all_array)
    
    # Get samples, filtering by symbol range if specified
    if start_symbol is not None or end_symbol is not None:
        ul_mask = get_sample_mask_for_symbols(iq_data, eaxc_with_both, 'UL', start_symbol, end_symbol)
        dl_mask = get_sample_mask_for_symbols(iq_data, eaxc_with_both, 'DL', start_symbol, end_symbol)
        ul_samples = ul_all_array[ul_mask]
        dl_samples = dl_all_array[dl_mask]
        # Apply max_samples limit if needed (0 means plot all)
        if max_samples > 0:
            if len(ul_samples) > max_samples:
                ul_samples = ul_samples[:max_samples]
            if len(dl_samples) > max_samples:
                dl_samples = dl_samples[:max_samples]
    else:
        # Apply max_samples limit if needed (0 means plot all)
        if max_samples > 0:
            if ul_total_count > max_samples:
                ul_samples = ul_all_array[:max_samples]
            else:
                ul_samples = ul_all_array
            if dl_total_count > max_samples:
                dl_samples = dl_all_array[:max_samples]
            else:
                dl_samples = dl_all_array
        else:
            ul_samples = ul_all_array
            dl_samples = dl_all_array
    
    # Create title with symbol range if specified
    title = f'UL vs DL Comparison (eAxC ID: {eaxc_with_both})'
    if start_symbol is not None or end_symbol is not None:
        symbol_range = f"Symbols {start_symbol if start_symbol is not None else 0}-{end_symbol if end_symbol is not None else 'end'}"
        title += f" - {symbol_range}"
    
    # Add sample count info to title
    ul_plotted = len(ul_samples)
    dl_plotted = len(dl_samples)
    if start_symbol is not None or end_symbol is not None:
        # When filtering, show filtered counts
        title += f"\n(UL: {ul_plotted:,} samples, DL: {dl_plotted:,} samples)"
    else:
        # Show plotted vs total
        if ul_plotted < ul_total_count or dl_plotted < dl_total_count:
            title += f"\n(UL: {ul_plotted:,} of {ul_total_count:,}, DL: {dl_plotted:,} of {dl_total_count:,} samples shown)"
        else:
            title += f"\n(UL: {ul_total_count:,}, DL: {dl_total_count:,} samples)"
    
    # Create Magnitude comparison plot
    ul_mag = np.abs(ul_samples)
    dl_mag = np.abs(dl_samples)
    
    fig_mag, axes_mag = plt.subplots(2, 1, figsize=(12, 10))
    fig_mag.suptitle(f'{title} - Magnitude', fontsize=14, fontweight='bold')
    
    axes_mag[0].plot(ul_mag, color='blue', alpha=0.7)
    axes_mag[0].set_xlabel('Sample Index')
    axes_mag[0].set_ylabel('Magnitude')
    axes_mag[0].set_title(f'Uplink Magnitude (Mean: {np.mean(ul_mag):.1f})')
    axes_mag[0].grid(True, alpha=0.3)
    
    axes_mag[1].plot(dl_mag, color='red', alpha=0.7)
    axes_mag[1].set_xlabel('Sample Index')
    axes_mag[1].set_ylabel('Magnitude')
    axes_mag[1].set_title(f'Downlink Magnitude (Mean: {np.mean(dl_mag):.1f})')
    axes_mag[1].grid(True, alpha=0.3)
    
    plt.tight_layout()
    mag_output_file = output_file.replace('.png', '_magnitude.png')
    plt.savefig(mag_output_file, dpi=200, bbox_inches='tight')
    print(f"Saved magnitude comparison plot: {mag_output_file}")
    
    if show_plot:
        print("Displaying magnitude comparison plot...")
        # Don't call plt.show() here to allow multiple plots
    else:
        plt.close()
    
    # Create Constellation comparison plot - plot all samples
    ul_const_title = f'Uplink Constellation ({len(ul_samples):,} samples)'
    dl_const_title = f'Downlink Constellation ({len(dl_samples):,} samples)'
    
    fig_const, axes_const = plt.subplots(1, 2, figsize=(14, 7))
    fig_const.suptitle(f'{title} - Constellation', fontsize=14, fontweight='bold')
    
    # UL Constellation
    axes_const[0].scatter(ul_samples.real, ul_samples.imag, alpha=0.3, s=1, c='blue')
    axes_const[0].set_xlabel('I (In-phase)')
    axes_const[0].set_ylabel('Q (Quadrature)')
    axes_const[0].set_title(ul_const_title)
    axes_const[0].grid(True, alpha=0.3)
    axes_const[0].axis('equal')
    
    # DL Constellation
    axes_const[1].scatter(dl_unique.real, dl_unique.imag, alpha=0.6, s=5, c='red')
    axes_const[1].set_xlabel('I (In-phase)')
    axes_const[1].set_ylabel('Q (Quadrature)')
    axes_const[1].set_title(dl_const_title)
    axes_const[1].grid(True, alpha=0.3)
    axes_const[1].axis('equal')
    
    if show_plot and mplcursors:
        try:
            cursor = mplcursors.cursor(axes_const[0].collections[0], hover=True)
            @cursor.connect("add")
            def on_add(sel):
                pos = sel.target
                idx = sel.index
                count = ul_counts[idx]
                sel.annotation.set_text(f"I: {pos[0]:.4f}\nQ: {pos[1]:.4f}\nCount: {count}")
                
            cursor2 = mplcursors.cursor(axes_const[1].collections[0], hover=True)
            @cursor2.connect("add")
            def on_add2(sel):
                pos = sel.target
                idx = sel.index
                count = dl_counts[idx]
                sel.annotation.set_text(f"I: {pos[0]:.4f}\nQ: {pos[1]:.4f}\nCount: {count}")
        except Exception as e:
            print(f"Warning: Could not enable interactive cursor: {e}")
    
    plt.tight_layout()
    const_output_file = output_file.replace('.png', '_constellation.png')
    plt.savefig(const_output_file, dpi=200, bbox_inches='tight')
    print(f"Saved constellation comparison plot: {const_output_file}\n")
    
    if show_plot:
        print("Displaying constellation comparison plot...")
        # Don't call plt.show() here to allow multiple plots
    else:
        plt.close()

def plot_all_eaxc(iq_data, output_base, max_samples=10000, start_symbol=None, end_symbol=None, plots_dir=None, show_plot=False):
    """Create individual plots for each eAxC ID"""
    import matplotlib.pyplot as plt
    import os
    
    # Use provided plots_dir or create Plots directory in workspace root
    if plots_dir is None:
        workspace_root = os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.'
        plots_dir = os.path.join(workspace_root, 'Plots')
    os.makedirs(plots_dir, exist_ok=True)
    
    for eaxc_id in sorted(iq_data.keys()):
        for direction in ['UL', 'DL']:
            if len(iq_data[eaxc_id][direction]) == 0:
                continue
            
            # Get all samples first
            all_samples_array = np.array(iq_data[eaxc_id][direction])
            total_samples_count = len(all_samples_array)
            
            # Get samples, filtering by symbol range if specified
            if start_symbol is not None or end_symbol is not None:
                mask = get_sample_mask_for_symbols(iq_data, eaxc_id, direction, start_symbol, end_symbol)
                samples = all_samples_array[mask]
                # Apply max_samples limit if needed (0 means plot all)
                if max_samples > 0 and len(samples) > max_samples:
                    samples = samples[:max_samples]
            else:
                # Apply max_samples limit if needed (0 means plot all)
                if max_samples > 0 and total_samples_count > max_samples:
                    samples = all_samples_array[:max_samples]
                else:
                    samples = all_samples_array
            
            # Create title with symbol range if specified
            title = f'eAxC ID: {eaxc_id} - {direction}'
            if start_symbol is not None or end_symbol is not None:
                symbol_range = f"Symbols {start_symbol if start_symbol is not None else 0}-{end_symbol if end_symbol is not None else 'end'}"
                title += f" - {symbol_range}"
            
            # Add sample count info to title
            samples_plotted = len(samples)
            if samples_plotted < total_samples_count:
                sample_info = f"({samples_plotted:,} of {total_samples_count:,} samples shown)"
            else:
                sample_info = f"({total_samples_count:,} samples)"
            
            # Create Magnitude plot
            magnitude = np.abs(samples)
            fig_mag, ax_mag = plt.subplots(1, 1, figsize=(10, 6))
            ax_mag.plot(magnitude, color='purple')
            ax_mag.set_xlabel('Sample Index')
            ax_mag.set_ylabel('Magnitude')
            ax_mag.set_title(f'{title} - Magnitude\n{sample_info}\nMean: {np.mean(magnitude):.1f}')
            ax_mag.grid(True, alpha=0.3)
            plt.tight_layout()
            plot_file_mag = os.path.join(plots_dir, f"{output_base}_eAxC{eaxc_id}_{direction}_magnitude.png")
            plt.savefig(plot_file_mag, dpi=150, bbox_inches='tight')
            print(f"Saved magnitude plot: {plot_file_mag}")
            
            if show_plot:
                print(f"Displaying magnitude plot for eAxC {eaxc_id} {direction}...")
                # Don't call plt.show() here to allow multiple plots
            else:
                plt.close()
            
            # Create Constellation plot - plot unique samples without density coloring
            const_title = f'{title} - Constellation\n{sample_info}'
            
            # Get unique samples and counts for tooltip display
            unique_vals, counts = np.unique(samples, return_counts=True)
            
            fig_const, ax_const = plt.subplots(1, 1, figsize=(10, 10))
            ax_const.scatter(unique_vals.real, unique_vals.imag, alpha=0.6, s=5)
            ax_const.set_xlabel('I (In-phase)')
            ax_const.set_ylabel('Q (Quadrature)')
            ax_const.set_title(const_title)
            ax_const.grid(True, alpha=0.3)
            ax_const.axis('equal')
            
            if show_plot and mplcursors:
                try:
                    cursor = mplcursors.cursor(ax_const.collections[0], hover=True)
                    @cursor.connect("add")
                    def on_add(sel):
                        pos = sel.target
                        idx = sel.index
                        count = counts[idx]
                        sel.annotation.set_text(f"I: {pos[0]:.4f}\nQ: {pos[1]:.4f}\nCount: {count}")
                except Exception as e:
                    print(f"Warning: Could not enable interactive cursor: {e}")
            
            plt.tight_layout()
            plot_file_const = os.path.join(plots_dir, f"{output_base}_eAxC{eaxc_id}_{direction}_constellation.png")
            plt.savefig(plot_file_const, dpi=150, bbox_inches='tight')
            print(f"Saved constellation plot: {plot_file_const}")
            
            if show_plot:
                print(f"Displaying constellation plot for eAxC {eaxc_id} {direction}...")
                # Don't call plt.show() here to allow multiple plots
            else:
                plt.close()
    
    print()

def analyze_pcap(pcap_file, force_bfp=False, bfp_exponent=None, start_symbol=None, end_symbol=None, restrict_to_first_combo=False):
    """Analyze PCAP file and display summary information without extracting full data (using pyshark)
    
    Args:
        pcap_file: Path to PCAP file
        force_bfp: Force BFP decompression
        bfp_exponent: BFP exponent value
        start_symbol: Start overall symbol number for filtering (inclusive, across all slots)
        end_symbol: End overall symbol number for filtering (inclusive, across all slots)
    """
    # Clear compression warnings for this run
    global _compression_warnings
    _compression_warnings.clear()
    
    # Normalize path to handle relative paths correctly
    pcap_file = os.path.normpath(os.path.abspath(pcap_file))
    print(f"Analyzing {pcap_file} with pyshark...")
    if start_symbol is not None or end_symbol is not None:
        filter_msg = "Overall symbol filtering: "
        if start_symbol is not None:
            filter_msg += f"from overall symbol {start_symbol} "
        if end_symbol is not None:
            filter_msg += f"to overall symbol {end_symbol}"
        print(f"{filter_msg}\n")
    
    # 5G NR typically has 14 symbols per slot (for normal cyclic prefix)
    # This can be adjusted if needed, but 14 is standard
    SYMBOLS_PER_SLOT = 14
    # 5G NR has 10 subframes per frame
    SUBFRAMES_PER_FRAME = 10
    # Slots per subframe depends on numerology (0 = 1 slot, 1 = 2 slots)
    # Default to 1 slot per subframe if NUMEROLOGY is not set
    SLOTS_PER_SUBFRAME = 2 if NUMEROLOGY == 1 else 1
    
    # Track the first (frame, subframe, slot) combination for filtering
    # Only restrict to first frame/subframe/slot when restrict_to_first_combo is True (i.e., when using --symbols)
    # When using --symbols N, we want the first N overall symbols from the first frame/subframe/slot
    # When using --start-symbol/--end-symbol, we want symbols from ANY frame/subframe/slot in that range
    first_frame_subframe_slot = None
    
    try:
        # First, read and display current ORAN FH CUS protocol preferences
        print("\nCurrent ORAN FH CUS protocol preferences:")
        print("-" * 60)
        pref_names = [
            'oran_fh_cus.oran.ud_comp_up',
            'oran_fh_cus.oran.iq_bitwidth_up',
            'oran_fh_cus.oran.ud_comp_down',
            'oran_fh_cus.oran.iq_bitwidth_down',
        ]
        
        current_prefs = {}
        try:
            result = subprocess.run(
                ['tshark', '-G', 'defaultprefs'],
                capture_output=True,
                text=True,
                check=True
            )
            
            for pref_name in pref_names:
                for line in result.stdout.split('\n'):
                    if line.strip().startswith('#' + pref_name + ':'):
                        value = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                        current_prefs[pref_name] = value
                        print(f"  {pref_name}: {value}")
                        break
        except Exception as e:
            print(f"  Warning: Could not read current preferences: {e}")
        
        print("-" * 60)
        
        # Set ORAN FH CUS protocol preferences based on compression type
        # This ensures Wireshark/TShark dissects packets correctly
        # Use override_prefs (dictionary) instead of custom_parameters (command-line flags)
        # for a cleaner Python API
        
        # Set compression method preference for ORAN FH CUS
        # Use string values as specified in TShark preferences (case-insensitive)
        # Valid values: "COMP_NONE", "COMP_BLOCK_FP", "No Compression", "Block Floating Point Compression", etc.
        # Use arguments if provided, otherwise fall back to globals
        use_bfp = force_bfp if force_bfp else (FORCE_COMPRESSION_TYPE.upper() == 'BFP')
        bitwidth = bfp_bitwidth if bfp_bitwidth is not None else FORCE_BFP_BITWIDTH
        
        if use_bfp:
            compression_pref = 'COMP_BLOCK_FP'  # or 'Block Floating Point Compression'
            iq_bitwidth = str(bitwidth)
        else:
            compression_pref = 'COMP_NONE'  # or 'No Compression'
            iq_bitwidth = '16'
        
        # Create dictionary of ORAN FH CUS preferences for both uplink and downlink
        # override_prefs expects string values
        override_prefs = {
            'oran_fh_cus.oran.ud_comp_up': compression_pref,
            'oran_fh_cus.oran.iq_bitwidth_up': iq_bitwidth,
            'oran_fh_cus.oran.ud_comp_down': compression_pref,
            'oran_fh_cus.oran.iq_bitwidth_down': iq_bitwidth,
        }
        
        print(f"\nSetting ORAN FH CUS protocol preferences (based on FORCE_COMPRESSION_TYPE='{FORCE_COMPRESSION_TYPE}'):")
        print("-" * 60)
        for pref_name, pref_value in override_prefs.items():
            if "ud_comp" in pref_name:
                if pref_value == "COMP_BLOCK_FP" or pref_value == "Block Floating Point Compression":
                    comp_desc = "Block Floating Point Compression"
                elif pref_value == "COMP_NONE" or pref_value == "No Compression":
                    comp_desc = "No Compression"
                else:
                    comp_desc = pref_value
                print(f"  {pref_name}: {comp_desc} ({pref_value})")
            else:
                print(f"  {pref_name}: {pref_value}")
        print("-" * 60)
        print()
        
        # Set decode_as to decode UDP packets as ORAN FH CUS
        # This ensures packets are properly dissected even if not auto-detected
        decode_as = None  # Disable decode_as to avoid TShark crashes - let Wireshark auto-detect
        # If you know the specific UDP port, uncomment and set it:
        # decode_as = {'udp.port==1234': 'oran_fh_cus'}  # Replace 1234 with actual port
        print("decode_as: Using Wireshark auto-detection for ORAN FH CUS protocol")
        print("  (If packets aren't detected, specify decode_as with known UDP port)")
        print()
        
        # IMPORTANT: Use custom_parameters with -o flags to ensure preferences are actually applied
        # override_prefs may not always work correctly, so we'll use both methods
        # Build custom_parameters list with -o flags for preferences (more reliable)
        custom_params = []
        for pref_name, pref_value in override_prefs.items():
            custom_params.extend(['-o', f'{pref_name}:{pref_value}'])
        
        print("Also setting preferences via custom_parameters (-o flags) for reliability:")
        print("-" * 60)
        for i in range(0, len(custom_params), 2):
            if i+1 < len(custom_params):
                print(f"  {custom_params[i]} {custom_params[i+1]}")
        print("-" * 60)
        print()
        
        # Try with use_json and include_raw for better raw data access
        # Don't use display filter as it can cause TShark crashes
        try:
            cap = pyshark.FileCapture(
                pcap_file, 
                use_json=True, 
                include_raw=True,
                override_prefs=override_prefs,
                custom_parameters=custom_params if custom_params else None,
                decode_as=decode_as if decode_as else {}
            )
        except:
            try:
                cap = pyshark.FileCapture(
                    pcap_file, 
                    use_json=True,
                    override_prefs=override_prefs,
                    custom_parameters=custom_params if custom_params else None,
                    decode_as=decode_as if decode_as else {}
                )
            except:
                try:
                    cap = pyshark.FileCapture(
                        pcap_file,
                        override_prefs=override_prefs,
                        custom_parameters=custom_params if custom_params else None,
                        decode_as=decode_as if decode_as else {}
                    )
                except:
                    # Last resort: basic capture without preferences
                    cap = pyshark.FileCapture(pcap_file)
        
        # Verify preferences were set by querying them again
        print("Verifying ORAN FH CUS protocol preferences (session-specific):")
        print("-" * 60)
        try:
            # Note: These preferences are session-specific to this FileCapture instance
            # We can't directly query what FileCapture is using, but we can show what
            # preferences were applied to this session
            print("  Preferences applied to this session:")
            for pref_name, pref_value in override_prefs.items():
                if "ud_comp" in pref_name:
                    if pref_value == "COMP_BLOCK_FP" or pref_value == "Block Floating Point Compression":
                        comp_desc = "Block Floating Point Compression"
                    elif pref_value == "COMP_NONE" or pref_value == "No Compression":
                        comp_desc = "No Compression"
                    else:
                        comp_desc = pref_value
                    print(f"    {pref_name}: {comp_desc} ({pref_value})")
                else:
                    print(f"    {pref_name}: {pref_value}")
            print("  (Note: These preferences are active for this FileCapture session only)")
        except Exception as e:
            print(f"  Warning: Could not verify preferences: {e}")
        print("-" * 60)
        print()
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        return {}
    
    # We'll count packets as we process them (removed duplicate pass to improve performance)
    total_packets = 0
    
    # Helper function to create a new dict with a new set for rbs_with_data
    def make_frame_slot_data():
        return {'packets': 0, 'samples': 0, 'start_prbc': None, 'num_prbc': None, 'rbs_with_data': set()}
    
    # Collect analysis data
    analysis_data = {
        'eaxc_ids': set(),  # Using RU Port ID as eaxc_id
        'directions': set(),
        'frames': set(),
        'subframes': set(),
        'slots': set(),
        'slots_seen_in_fields': set(),  # Track all slots seen in field extraction (before filtering)
        'symbols': set(),
        'packet_timestamps': [],
        'packet_count': 0,
        'total_samples': 0,
        'eaxc_stats': defaultdict(lambda: {'UL': {'packets': 0, 'samples': 0}, 'DL': {'packets': 0, 'samples': 0}}),
        'symbol_counts': defaultdict(int),
        'overall_symbol_counts': defaultdict(int),  # Track overall symbol counts when filtering
        'overall_symbol_unique_combos': defaultdict(set),  # Track unique (frame, subframe, slot, symbol, eaxc) combos per overall symbol
        'overall_symbol_eaxc_counts': defaultdict(lambda: defaultdict(int)),  # Track packets per overall symbol per eAxC ID
        'overall_symbol_samples': defaultdict(int),  # Track total samples per overall symbol when filtering
        'symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: {'packets': 0, 'samples': 0})),
        'slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(int))),
        'frame_subframe_slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(make_frame_slot_data))))),
        'compression_types': set(),
        'max_iq_values': defaultdict(lambda: {'max_i': 0.0, 'max_q': 0.0, 'max_abs': 0.0}),
        'max_num_prbc': 0,  # Track maximum num_prbc seen across all packets
        'max_rb_index_with_data': 0  # Maximum RB index that actually has IQ data
    }
    
    for packet in cap:
        total_packets += 1  # Count packets as we process them (single pass)
        try:
            # Skip non-ORAN FH packets early
            # Check if packet has ORAN_FH_CUS layer
            has_oran_fh_cus = False
            
            # First, try checking with 'in' operator (pyshark typically uses lowercase)
            layer_checks = ['oran_fh_cus', 'ORAN_FH_CUS', 'oran', 'ORAN']
            for layer_name in layer_checks:
                try:
                    if layer_name in packet:
                        has_oran_fh_cus = True
                        break
                except:
                    pass
            
            # Also check all layer names directly (more reliable)
            if not has_oran_fh_cus and hasattr(packet, 'layers'):
                for layer in packet.layers:
                    layer_name = layer.layer_name
                    layer_name_lower = layer_name.lower()
                    # Check for ORAN_FH_CUS or similar
                    if 'oran' in layer_name_lower and 'fh' in layer_name_lower:
                        has_oran_fh_cus = True
                        break
                    elif 'oran' in layer_name_lower or 'fh_cus' in layer_name_lower or 'cus' in layer_name_lower:
                        has_oran_fh_cus = True
                        break
            
            if not has_oran_fh_cus:
                continue
            
            # Get ORAN FH CUS fields from packet
            fields = get_oran_fh_cus_fields_from_packet(packet)
            
            # If we couldn't parse ORAN FH fields, skip this packet
            if not fields:
                continue
            
            # Extract ORAN FH CUS fields using the actual field names from extraction
            section_id = int(fields.get('sectionId', 0)) if 'sectionId' in fields else 0
            # Use RU Port ID as eAxC ID (not section_id)
            ru_port_id = fields.get('ru_port_id', 0) if 'ru_port_id' in fields else 0
            eaxc_id = ru_port_id  # Use RU Port ID as eAxC ID
            frame_id = fields.get('frame_id', 0)
            subframe_id = fields.get('subframe_id', 0)
            slot_id = fields.get('slot_id', 0)
            start_symbol_id = fields.get('start_symbol_id', 0)
            
            # Track ALL slots seen in fields extraction (before filtering)
            # This ensures we capture all slots even if they're filtered out later
            analysis_data['slots_seen_in_fields'].add(slot_id)
            
            # Calculate overall symbol number: count continuously across frames, subframes, slots, and symbols
            # Formula: (frame * SUBFRAMES_PER_FRAME * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) +
            #          (subframe * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) +
            #          (slot * SYMBOLS_PER_SLOT) +
            #          symbol_id
            # This represents the absolute symbol number across all frames/subframes/slots
            overall_symbol = (frame_id * SUBFRAMES_PER_FRAME * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                            (subframe_id * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                            (slot_id * SYMBOLS_PER_SLOT) + \
                            start_symbol_id
            
            # Track minimum overall symbol seen (for analyze_pcap entry point)
            if 'first_overall_symbol' not in analysis_data:
                analysis_data['first_overall_symbol'] = overall_symbol
            
            # Also track min for compatibility
            if 'min_overall_symbol' not in analysis_data:
                analysis_data['min_overall_symbol'] = overall_symbol
            elif overall_symbol < analysis_data['min_overall_symbol']:
                analysis_data['min_overall_symbol'] = overall_symbol
            
            # Calculate relative symbol
            relative_symbol = overall_symbol - analysis_data['first_overall_symbol']
            
            # Filter by relative symbol number if specified (must happen BEFORE incrementing packet_count)
            if start_symbol is not None or end_symbol is not None:
                if start_symbol is not None and relative_symbol < start_symbol:
                    continue
                if end_symbol is not None and relative_symbol > end_symbol:
                    continue
                
                # Only restrict to first frame/subframe/slot when using --symbols (not --start-symbol/--end-symbol)
                # When --symbols is used, we want the first N overall symbols from the first frame/subframe/slot
                # When --start-symbol/--end-symbol is used directly, we want symbols from ANY frame/subframe/slot
                if restrict_to_first_combo:
                    # Identify the first (frame, subframe, slot) combination that matches the range
                    if first_frame_subframe_slot is None:
                        first_frame_subframe_slot = (frame_id, subframe_id, slot_id)
                    
                    # Only include packets from the first frame/subframe/slot combination
                    current_combo = (frame_id, subframe_id, slot_id)
                    if current_combo != first_frame_subframe_slot:
                        continue  # Skip packets not from the first frame/subframe/slot
            
            # Increment packet count only after filtering - this should match the sum of overall_symbol_counts
            analysis_data['packet_count'] += 1
            
            # Get packet timestamp
            try:
                if hasattr(packet, 'sniff_timestamp'):
                    timestamp = float(packet.sniff_timestamp)
                    analysis_data['packet_timestamps'].append(timestamp)
            except:
                pass
            
            # Calculate num_symbols from sym_inc or use default
            sym_inc = fields.get('sym_inc', 0)
            num_symbols = sym_inc + 1 if sym_inc > 0 else 1
            start_prbc = fields.get('start_prbc', 0)
            # Get num_prbc from fields (dynamically determined from ORAN section tree)
            num_prbc = fields.get('num_prbc', None)
            
            # Track maximum num_prbc and validate
            if num_prbc is not None:
                # Check if this packet exceeds the current maximum before updating
                if analysis_data.get('max_num_prbc', 0) > 0 and num_prbc > analysis_data['max_num_prbc']:
                    print(f"ERROR: Packet has {num_prbc} PRBs, which exceeds detected maximum of {analysis_data['max_num_prbc']} PRBs!")
                    print(f"  Frame: {frame_id}, Subframe: {subframe_id}, Slot: {slot_id}, Symbol: {start_symbol_id}, eAxC ID: {eaxc_id}")
                # Update maximum
                if num_prbc > analysis_data.get('max_num_prbc', 0):
                    analysis_data['max_num_prbc'] = num_prbc
            
            # Get compression method and width from fields (hardcoded from top variables)
            # Default to BFP if not set
            compression_method = fields.get('compression_method', 1 if FORCE_COMPRESSION_TYPE.upper() == 'BFP' else 0)
            compression_width = fields.get('compression_width', FORCE_BFP_BITWIDTH)
            prb_raw = fields.get('prb_raw', None)
            
            # Determine direction from data_direction field (1 = DL, 0 = UL)
            data_direction = fields.get('data_direction', 1)
            direction = 'DL' if data_direction == 1 else 'UL'
            
            # Use max_num_prbc for parsing limits, default to calculated if not available
            current_max_rbs = analysis_data.get('max_num_prbc', 0) if analysis_data.get('max_num_prbc', 0) > 0 else (num_prbc if num_prbc is not None else 106)
            
            # Extract IQ samples from prb_raw if available
            if prb_raw is not None:
                samples, compression_type, num_samples, exponents_list = parse_iq_from_prb_raw(
                    prb_raw, compression_method, compression_width, max_rbs=current_max_rbs)
            else:
                # Fallback: try to get raw ORAN FH data
                oran_data = extract_oran_fh_data_from_packet(packet)
                if oran_data is None or len(oran_data) < 8:
                    continue
                
                # ORAN FH CUS header is at least 8 bytes, IQ data starts after header
                iq_offset = 8
                # Parse IQ samples (handles both uncompressed and BFP compressed)
                samples, compression_type, num_samples, exponents_list = parse_iq_samples(
                    oran_data, iq_offset, 0, 0,
                    force_bfp=force_bfp, bfp_exponent=bfp_exponent, max_rbs=current_max_rbs)
            
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
            
            # Update statistics (using RU Port ID as eaxc_id)
            analysis_data['eaxc_ids'].add(eaxc_id)
            analysis_data['directions'].add(direction)
            analysis_data['frames'].add(frame_id)
            analysis_data['subframes'].add(subframe_id)
            analysis_data['slots'].add(slot_id)
            analysis_data['symbols'].add(start_symbol_id)
            analysis_data['total_samples'] += num_samples
            analysis_data['eaxc_stats'][eaxc_id][direction]['packets'] += 1
            analysis_data['eaxc_stats'][eaxc_id][direction]['samples'] += num_samples
            
            # Track symbol counts: use overall_symbol when filtering is active, otherwise use start_symbol_id
            if start_symbol is not None or end_symbol is not None:
                # When filtering by overall symbol, track overall symbols
                analysis_data['overall_symbol_counts'][overall_symbol] += 1
                # Track samples for this overall symbol
                analysis_data['overall_symbol_samples'][overall_symbol] += num_samples
                # Track unique (frame, subframe, slot, symbol, eaxc) combinations per overall symbol
                combo = (frame_id, subframe_id, slot_id, start_symbol_id, eaxc_id)
                analysis_data['overall_symbol_unique_combos'][overall_symbol].add(combo)
                # Track packets per overall symbol per eAxC ID
                analysis_data['overall_symbol_eaxc_counts'][overall_symbol][eaxc_id] += 1
            else:
                # When not filtering, track symbol_ids within slots
                analysis_data['symbol_counts'][start_symbol_id] += 1
            
            analysis_data['symbol_eaxc_data'][start_symbol_id][eaxc_id]['packets'] += 1
            analysis_data['symbol_eaxc_data'][start_symbol_id][eaxc_id]['samples'] += num_samples
            analysis_data['slot_symbol_eaxc_data'][slot_id][start_symbol_id][eaxc_id] += 1
            frame_slot_data = analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][start_symbol_id][eaxc_id]
            frame_slot_data['packets'] += 1
            frame_slot_data['samples'] += num_samples
            # Store start_prbc and num_prbc (use first non-None value or update if different)
            if frame_slot_data['start_prbc'] is None:
                frame_slot_data['start_prbc'] = start_prbc
            if frame_slot_data['num_prbc'] is None:
                frame_slot_data['num_prbc'] = num_prbc
            
            # Track which RBs have non-zero IQ data (12 samples per RB)
            # Optimized: Use numpy for faster non-zero detection
            if len(samples) > 0:
                samples_per_rb = 12
                num_rbs_in_samples = len(samples) // samples_per_rb
                
                if num_rbs_in_samples > 0:
                    # Convert samples to numpy array once for efficient processing
                    samples_array = np.array(samples[:num_rbs_in_samples * samples_per_rb], dtype=complex)
                    # Reshape to [num_rbs, samples_per_rb] for batch processing
                    rb_samples_2d = samples_array.reshape(num_rbs_in_samples, samples_per_rb)
                    # Compute magnitude for each sample, then check if any sample per RB is non-zero
                    # This is much faster than looping and using 'any()' for each RB
                    magnitudes = np.abs(rb_samples_2d)
                    has_nonzero_per_rb = np.any(magnitudes > 1e-10, axis=1)
                    
                    # Only iterate through RBs that have non-zero data
                    for rb_idx in np.where(has_nonzero_per_rb)[0]:
                        actual_rb_index = start_prbc + rb_idx
                        frame_slot_data['rbs_with_data'].add(actual_rb_index)
                        # Track maximum RB index with actual data
                        if actual_rb_index > analysis_data.get('max_rb_index_with_data', 0):
                            analysis_data['max_rb_index_with_data'] = actual_rb_index
            
        except Exception as e:
            continue
    
    cap.close()
    
    # Calculate duration
    duration_sec = 0
    if len(analysis_data['packet_timestamps']) > 1:
        duration_sec = max(analysis_data['packet_timestamps']) - min(analysis_data['packet_timestamps'])
    
    # Print analysis report (same format as original)
    print("=" * 80)
    print("PCAP FILE ANALYSIS REPORT")
    print("=" * 80)
    print()
    
    print("OVERVIEW:")
    print(f"  Total Packets:        {total_packets:,}")
    
    # When filtering by overall symbol, show only packets that match the filtered symbols
    if start_symbol is not None or end_symbol is not None:
        # Use the sum of overall_symbol_counts as the accurate count of filtered packets
        filtered_packet_count = sum(analysis_data['overall_symbol_counts'].values())
        filtered_samples_count = sum(analysis_data['overall_symbol_samples'].values())
        print(f"  IQ Data Packets:      {filtered_packet_count:,}")
        print(f"  Total IQ Samples:      {filtered_samples_count:,}")
    else:
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
        print("=" * 110)
        print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10} {'Max I/Q':<15} {'Est. IQ Backoff':<18}")
        print("=" * 110)
        for eaxc_id in eaxc_list:
            max_iq = analysis_data['max_iq_values'][eaxc_id]['max_abs']
            max_iq_str = f"{max_iq:.2f}" if max_iq > 0 else "N/A"
            dbfs = calculate_dbfs(max_iq)
            dbfs_str = f"{dbfs:.2f} dBFS" if dbfs is not None else "N/A"
            for direction in ['UL', 'DL']:
                stats = analysis_data['eaxc_stats'][eaxc_id][direction]
                # When filtering, use stats only from filtered packets
                if start_symbol is not None or end_symbol is not None:
                    # Calculate filtered stats for this eAxC ID and direction
                    # Need to track samples per eAxC ID per direction per overall symbol
                    # For now, use the overall stats but show filtered packet count
                    filtered_packets = 0
                    for overall_sym in analysis_data['overall_symbol_eaxc_counts']:
                        if eaxc_id in analysis_data['overall_symbol_eaxc_counts'][overall_sym]:
                            filtered_packets += analysis_data['overall_symbol_eaxc_counts'][overall_sym][eaxc_id]
                    # Estimate samples based on average samples per packet for this eAxC/direction
                    if filtered_packets > 0:
                        if stats['packets'] > 0:
                            avg_samples_per_packet = stats['samples'] / stats['packets']
                            filtered_samples = int(filtered_packets * avg_samples_per_packet)
                        else:
                            filtered_samples = 0
                        print(f"{eaxc_id:<10} {direction:<12} {filtered_samples:<15,} {filtered_packets:<10} {max_iq_str:<15} {dbfs_str:<18}")
                elif stats['packets'] > 0:
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
    if start_symbol is not None or end_symbol is not None:
        # When filtering by overall symbol, show overall symbols
        if analysis_data['overall_symbol_counts']:
            overall_symbol_list = sorted(analysis_data['overall_symbol_counts'].keys())
            first_overall_symbol = analysis_data.get('first_overall_symbol')
            if first_overall_symbol is None:
                first_overall_symbol = min(overall_symbol_list) if overall_symbol_list else 0
            
            # Calculate relative symbol range
            min_relative = min(overall_symbol_list) - first_overall_symbol if overall_symbol_list else 0
            max_relative = max(overall_symbol_list) - first_overall_symbol if overall_symbol_list else 0
            
            print(f"  Relative Symbol Numbers: {min_relative} to {max_relative} ({len(overall_symbol_list)} unique symbols)")
            print(f"  (Absolute: {min(overall_symbol_list)} to {max(overall_symbol_list)})")
            print(f"  Packets per relative symbol:")
            for overall_sym in overall_symbol_list:
                relative_sym = overall_sym - first_overall_symbol
                total_count = analysis_data['overall_symbol_counts'][overall_sym]
                unique_combos = len(analysis_data['overall_symbol_unique_combos'][overall_sym])
                eaxc_breakdown = analysis_data['overall_symbol_eaxc_counts'][overall_sym]
                
                print(f"    Relative Symbol {relative_sym:3d} (Abs: {overall_sym}): {total_count:4d} packets ({unique_combos} unique frame/subframe/slot/symbol/eAxC combos)")
                
                # Show the actual unique combinations to understand why there are multiple
                if unique_combos > 1 and unique_combos <= 20:  # Only show if reasonable number
                    print(f"      Unique combos for relative symbol {relative_sym}:")
                    for combo in sorted(analysis_data['overall_symbol_unique_combos'][overall_sym]):
                        frame_id, subframe_id, slot_id, symbol_id, eaxc_id = combo
                        print(f"        Frame {frame_id}, Subframe {subframe_id}, Slot {slot_id}, Symbol {symbol_id}, eAxC {eaxc_id}")
                
                if len(eaxc_breakdown) > 1:
                    # Show breakdown by eAxC ID if multiple eAxC IDs
                    for eaxc_id in sorted(eaxc_breakdown.keys()):
                        eaxc_count = eaxc_breakdown[eaxc_id]
                        print(f"      eAxC ID {eaxc_id}: {eaxc_count:4d} packets")
        else:
            print("  No overall symbol data found")
    else:
        # When not filtering, show symbol_ids within slots
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
    
    # Print detected maximum PRBs
    max_declared_prbs = analysis_data.get('max_num_prbc', 0)
    max_rb_index_with_data = analysis_data.get('max_rb_index_with_data', 0)
    
    if max_declared_prbs > 0:
        if max_rb_index_with_data > 0 and max_rb_index_with_data + 1 < max_declared_prbs:
            print(f"Detected maximum declared PRBs: {max_declared_prbs}")
            print(f"  (Maximum RB index with actual IQ data: {max_rb_index_with_data}, {max_rb_index_with_data + 1} RBs with data)")
        else:
            print(f"Detected maximum PRBs: {max_declared_prbs}\n")
    
    # Print compression warnings if any were detected
    if _compression_warnings:
        print("=" * 80)
        print("COMPRESSION SETTINGS WARNING")
        print("=" * 80)
        # Print the highest confidence warning (most reliable)
        best_warning = max(_compression_warnings, key=lambda x: x['confidence'])
        for warning in best_warning['warnings']:
            print(warning)
        print("=" * 80)
        print()
    
    # Create resource allocation plot (reuse function from original)
    if analysis_data['packet_count'] > 0:
        plot_resource_allocation(analysis_data, pcap_file)
    
    return analysis_data

def plot_resource_allocation(analysis_data, pcap_file, show_plot=False, start_symbol=None, end_symbol=None):
    """Create separate resource allocation plots for each eAxC ID showing symbols vs Resource Blocks (RBs)"""
    import matplotlib.pyplot as plt
    from matplotlib.colors import ListedColormap
    import os
    
    if not analysis_data['symbols'] or not analysis_data['eaxc_ids']:
        print("Insufficient data for resource allocation plot")
        return
    
    if NUMEROLOGY is None:
        raise ValueError("NUMEROLOGY must be set")
    if NUMEROLOGY not in [0, 1]:
        raise ValueError(f"Invalid NUMEROLOGY: {NUMEROLOGY}")
    
    symbol_list = sorted(analysis_data['symbols'])
    eaxc_list = sorted(analysis_data['eaxc_ids'])
    
    samples_per_rb = 12
    # Use dynamically determined max_num_prbc from analysis_data
    max_rbs_limit = analysis_data.get('max_num_prbc', 106) if analysis_data.get('max_num_prbc', 0) > 0 else 106
    
    # Get base name and directory for output files
    # Create Plots directory in the workspace root (PCAP_Analysis folder)
    workspace_root = os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.'
    plots_dir = os.path.join(workspace_root, 'Plots')
    os.makedirs(plots_dir, exist_ok=True)
    
    base_name = os.path.basename(pcap_file)
    base_name = base_name.replace('.pcap', '')
    
    # Create a separate plot for each eAxC ID
    for eaxc_id in eaxc_list:
        # Collect all unique (frame, subframe, slot, symbol) combinations for this eAxC ID
        # First, collect slots that have data for this eAxC ID
        slots_with_data = set()  # (frame, subframe, slot) combinations that have data
        combination_data = {}  # (frame, subframe, slot, symbol) -> {'samples': X, 'rbs': Y, 'start_prbc': Z, 'rbs_with_data': set()}
        
        # Iterate directly over existing combinations in the data structure (only filtered data is present)
        for frame_id in analysis_data['frame_subframe_slot_symbol_eaxc_data']:
            for subframe_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id]:
                for slot_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id]:
                    slot_key = (frame_id, subframe_id, slot_id)
                    has_data_for_slot = False
                    
                    for symbol_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id]:
                        # Only process combinations for this eAxC ID
                        if eaxc_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][symbol_id]:
                            symbol_data = analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][symbol_id][eaxc_id]
                            total_samples = symbol_data['samples']
                            packet_count = symbol_data['packets']
                            
                            if total_samples > 0:
                                combo = (frame_id, subframe_id, slot_id, symbol_id)
                                has_data_for_slot = True
                                
                                # Use start_prbc and num_prbc from ORAN section tree if available
                                start_prbc_val = symbol_data.get('start_prbc', 0) if symbol_data.get('start_prbc') is not None else 0
                                num_prbc_val = symbol_data.get('num_prbc', None) if symbol_data.get('num_prbc') is not None else None
                                
                                # Calculate num_rbs: use num_prbc if available, otherwise estimate from samples
                                if num_prbc_val is not None and num_prbc_val > 0:
                                    num_rbs = num_prbc_val
                                else:
                                    # Fallback: estimate from samples
                                    expected_samples_for_max_rbs = max_rbs_limit * 12
                                    if total_samples > expected_samples_for_max_rbs * 1.5:
                                        ratio = expected_samples_for_max_rbs / total_samples
                                        estimated_active_subcarriers = total_samples * ratio
                                        num_rbs = int(np.ceil(estimated_active_subcarriers / samples_per_rb))
                                    else:
                                        num_rbs = int(np.ceil(total_samples / samples_per_rb))
                                
                                if num_rbs > max_rbs_limit:
                                    num_rbs = max_rbs_limit
                                
                                # Get RBs with data for this combination
                                rbs_with_data = symbol_data.get('rbs_with_data', set())
                                combination_data[combo] = {'samples': total_samples, 'rbs': num_rbs, 'packets': packet_count, 'start_prbc': start_prbc_val, 'rbs_with_data': rbs_with_data}
                    
                    # If this slot has any data, mark it for inclusion
                    if has_data_for_slot:
                        slots_with_data.add(slot_key)
        
        # Now create unique_combinations that includes ONLY symbols that have data
        # This avoids showing empty symbols (e.g., symbols 6-13 when capture ends at symbol 5)
        unique_combinations = []
        
        for slot_key in sorted(slots_with_data):
            frame_id, subframe_id, slot_id = slot_key
            # Only include symbols that actually have data for this slot
            for symbol_id in range(14):  # Check all possible symbols (0-13)
                combo = (frame_id, subframe_id, slot_id, symbol_id)
                # Only add this combination if it has data
                if combo in combination_data:
                    # Check if this symbol is within the requested range
                    # Calculate overall symbol number
                    SUBFRAMES_PER_FRAME = 10
                    SLOTS_PER_SUBFRAME = 2 if NUMEROLOGY == 1 else 1
                    SYMBOLS_PER_SLOT = 14
                    
                    overall_sym = (frame_id * SUBFRAMES_PER_FRAME * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                                  (subframe_id * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                                  (slot_id * SYMBOLS_PER_SLOT) + \
                                  symbol_id
                    
                    first_overall_symbol = analysis_data.get('first_overall_symbol')
                    if first_overall_symbol is not None:
                        relative_sym = overall_sym - first_overall_symbol
                    else:
                        relative_sym = 0 # Should not happen if data exists
                    
                    # Filter based on start_symbol and end_symbol (relative)
                    if start_symbol is not None and relative_sym < start_symbol:
                        continue
                    if end_symbol is not None and relative_sym > end_symbol:
                        continue
                    
                    # This symbol has data and is in range, add it
                    unique_combinations.append(combo)
        
        if len(unique_combinations) == 0:
            continue  # Skip this eAxC ID if no data
        
        # Find maximum RB index (start_prbc + num_rbs - 1) across all combinations to determine grid size
        max_rb_index = 0
        for combo_info in combination_data.values():
            start_prbc_val = combo_info.get('start_prbc', 0)
            num_rbs_val = combo_info['rbs']
            end_rb_index = start_prbc_val + num_rbs_val - 1
            if end_rb_index > max_rb_index:
                max_rb_index = end_rb_index
        
        # Cap at maximum RBs limit
        if max_rb_index >= max_rbs_limit:
            max_rb_index = max_rbs_limit - 1
        
        # Grid size: rows = 0 to max_rb_index (inclusive)
        max_rbs = max_rb_index + 1
        
        if max_rbs == 0:
            continue
        
        # Create a 2D grid: rows = RBs, columns = unique (frame, slot, symbol) combinations
        num_columns = len(unique_combinations)
        grid = np.zeros((max_rbs, num_columns))
        
        # Fill grid - mark allocated RBs using actual RB indices from start_prbc
        for col_idx, combo in enumerate(unique_combinations):
            if len(combo) == 4:  # (frame_id, subframe_id, slot_id, symbol_id)
                frame_id, subframe_id, slot_id, symbol_id = combo
            else:  # Backward compatibility
                frame_id, slot_id, symbol_id = combo
            combo_info = combination_data[combo]
            num_rbs_for_combo = combo_info['rbs']
            start_prbc_val = combo_info.get('start_prbc', 0)
            
            # Only mark RBs that have non-zero IQ data
            rbs_with_data = combo_info.get('rbs_with_data', set())
            if not rbs_with_data:
                # Fallback: if rbs_with_data not tracked, mark all RBs in the allocated range
                # (for backward compatibility with data processed before this change)
                for rb_offset in range(num_rbs_for_combo):
                    rb_index = start_prbc_val + rb_offset
                    if rb_index < max_rbs:
                        grid[rb_index, col_idx] = rb_index + 1
            else:
                # Only mark RBs that have actual non-zero data
                for rb_index in rbs_with_data:
                    if rb_index < max_rbs:
                        grid[rb_index, col_idx] = rb_index + 1  # Each RB gets its actual index + 1
        
        # Create colormap - each RB gets a distinct color
        unallocated_color = '#f0f0f0'  # Light gray for unallocated
        
        # Create distinct colors for each RB using a colormap
        if max_rbs <= 20:
            base_colors = plt.cm.tab20(np.linspace(0, 1, 20))
        else:
            # Use hsv but shuffle to ensure high contrast between adjacent indices
            # This makes boundaries much easier to distinguish
            palette = plt.cm.hsv(np.linspace(0, 0.9, max_rbs))  # 0.9 to avoid wrapping back to red
            np.random.seed(42) # For reproducibility
            np.random.shuffle(palette)
            base_colors = palette
        
        # Create color list: unallocated (index 0) + distinct colors for each RB
        colors = [unallocated_color]
        for i in range(max_rbs):
            color = base_colors[i % len(base_colors)]
            if isinstance(color, np.ndarray) and len(color) == 4:
                r, g, b, a = color
                hex_color = '#{:02x}{:02x}{:02x}'.format(int(r*255), int(g*255), int(b*255))
                colors.append(hex_color)
            else:
                colors.append(color)
        
        cmap = ListedColormap(colors[:max_rbs + 1])
        
        # Create figure - adjust height based on number of RBs, make it bigger
        fig_height = max(10, min(24, max_rbs * 0.4))
        fig_width = min(30, max(12, num_columns * 0.6))  # Capped at 30, reduced multiplier
        fig, ax = plt.subplots(figsize=(fig_width, fig_height))
        
        # Create the heatmap with better aspect control
        im = ax.imshow(grid, aspect='auto', cmap=cmap, interpolation='nearest', 
                       vmin=0, vmax=max_rbs)
        
        # Adjust x-axis limits to prevent stretching of last column
        ax.set_xlim(-0.5, num_columns - 0.5)
        
        # Set ticks and labels - only show first, last, and symbols with symbol_id = 0
        ax.set_xticks(range(num_columns))
        column_labels = []
        for col_idx, combo in enumerate(unique_combinations):
            is_first = (col_idx == 0)
            is_last = (col_idx == len(unique_combinations) - 1)
            
            if len(combo) == 4:  # (frame_id, subframe_id, slot_id, symbol_id)
                frame_id, subframe_id, slot_id, symbol_id = combo
                if is_first or is_last or symbol_id == 0:
                    column_labels.append(f'F{frame_id}SF{subframe_id}S{slot_id}Sym{symbol_id}')
                else:
                    column_labels.append('')  # Empty label for other symbols
            else:  # Backward compatibility
                frame_id, slot_id, symbol_id = combo
                if is_first or is_last or symbol_id == 0:
                    column_labels.append(f'F{frame_id}S{slot_id}Sym{symbol_id}')
                else:
                    column_labels.append('')  # Empty label for other symbols
        ax.set_xticklabels(column_labels, fontsize=11, rotation=45, ha='right')
        
        # Set Y-axis labels for RBs - show every 10th RB only, ensure max is shown
        y_ticks = list(range(0, max_rbs, 10))
        if max_rbs not in y_ticks:
            y_ticks.append(max_rbs)
        ax.set_yticks(y_ticks)
        ax.set_yticklabels([f'RB {i}' for i in y_ticks], fontsize=11)
        ax.set_ylim(-0.5, max_rbs - 0.5)
        
        # Add grid lines
        ax.set_xticks(np.arange(num_columns) - 0.5, minor=True)
        ax.set_yticks(np.arange(max_rbs) - 0.5, minor=True)
        ax.grid(which='minor', color='black', linestyle='-', linewidth=0.8, alpha=0.6)
        
        # Labels with larger fonts
        ax.set_xlabel('Frame/Subframe/Slot/Symbol', fontsize=14, fontweight='bold')
        ax.set_ylabel('Resource Block (RB) Index', fontsize=14, fontweight='bold')
        ax.set_title(f'Resource Allocation: eAxC ID {eaxc_id}\n(Each column = unique Frame/Subframe/Slot/Symbol, Each cell = 1 RB = 12 subcarriers)', 
                     fontsize=16, fontweight='bold', pad=20)
        
        plt.tight_layout(pad=3.0)
        
        # Save plot with higher DPI in Plots directory
        output_file = os.path.join(plots_dir, f'{base_name}_eAxC{eaxc_id}_resource_allocation.png')
        plt.savefig(output_file, dpi=200, bbox_inches='tight')
        print(f"Saved resource allocation plot for eAxC {eaxc_id}: {output_file}")
        
        if show_plot:
            print(f"Displaying resource allocation plot for eAxC {eaxc_id}...")
            # Don't call plt.show() here to allow multiple plots
            
            if mplcursors:
                try:
                    cursor = mplcursors.cursor(im, hover=True)
                    @cursor.connect("add")
                    def on_add(sel):
                        x, y = sel.target
                        col_idx = int(x + 0.5)
                        row_idx = int(y + 0.5)
                        
                        # Ensure indices are within bounds
                        if 0 <= col_idx < len(unique_combinations) and 0 <= row_idx < max_rbs:
                            combo = unique_combinations[col_idx]
                            if len(combo) == 4:
                                f, sf, sl, sym = combo
                                
                                # Calculate overall symbol number
                                # Replicate logic from analyze_pcap
                                SYMBOLS_PER_SLOT = 14
                                SUBFRAMES_PER_FRAME = 10
                                SLOTS_PER_SUBFRAME = 2 if NUMEROLOGY == 1 else 1
                                
                                overall_sym = (f * SUBFRAMES_PER_FRAME * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                                              (sf * SLOTS_PER_SUBFRAME * SYMBOLS_PER_SLOT) + \
                                              (sl * SYMBOLS_PER_SLOT) + \
                                              sym
                                
                                # Use first_overall_symbol for relative calc
                                first_overall_symbol = analysis_data.get('first_overall_symbol')
                                if first_overall_symbol is not None:
                                    relative_overall_sym = overall_sym - first_overall_symbol
                                    timing_str = f"Frame: {f}\nSubframe: {sf}\nSlot: {sl}\nSymbol: {sym}\nRelative Symbol: {relative_overall_sym}\n(Absolute: {overall_sym})"
                                else:
                                    timing_str = f"Frame: {f}\nSubframe: {sf}\nSlot: {sl}\nSymbol: {sym}\nOverall Symbol: {overall_sym}"
                            else:
                                f, sl, sym = combo
                                timing_str = f"Frame: {f}\nSlot: {sl}\nSymbol: {sym}"
                            
                            val = grid[row_idx, col_idx]
                            status = "Allocated" if val > 0 else "Empty"
                            
                            sel.annotation.set_text(f"{timing_str}\nRB Index: {row_idx}\nStatus: {status}")
                        else:
                            sel.annotation.set_text(f"X: {col_idx}\nY: {row_idx}")
                except Exception as e:
                    print(f"Warning: Could not enable interactive cursor for allocation plot: {e}")
        else:
            plt.close()
    
    print()  # Add blank line after all plots

if __name__ == "__main__":
    # Enable line buffering for stdout to ensure GUI gets updates immediately
    sys.stdout.reconfigure(line_buffering=True)
    
    import argparse
    
    # Record start time
    start_time = time.time()
    
    parser = argparse.ArgumentParser(
        description='Extract IQ samples from 5G NR Fronthaul PCAP files (Wireshark-based)'
    )
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('output_base', nargs='?', default='iq_separated',
                       help='Base name for output files (default: iq_separated)')
    parser.add_argument('--symbols', type=int, metavar='N',
                       help='Number of overall symbols to analyze/plot (across all slots)')
    parser.add_argument('--samples', type=int, default=0, metavar='N',
                       help='Number of samples to plot (default: 0, use 0 to plot all samples)')
    parser.add_argument('--start-symbol', type=int, metavar='N',
                       help='Start relative symbol number (0 = first symbol in capture)')
    parser.add_argument('--end-symbol', type=int, metavar='N',
                       help='End relative symbol number (relative to first symbol in capture)')
    parser.add_argument('--bfp', action='store_true',
                       help='Force BFP decompression')
    parser.add_argument('--bfp-exponent', type=int, metavar='N',
                       help='BFP exponent value (0-15)')
    parser.add_argument('--bitwidth', type=int, default=None, metavar='N',
                       help=f'Bitwidth: 8-14 for BFP, 16 for uncompressed (default: {FORCE_BFP_BITWIDTH})')
    parser.add_argument('--no-parallel', action='store_true',
                       help='Disable parallel processing (process packets sequentially)')
    parser.add_argument('--show-plots', action='store_true',
                       help='Show plots in interactive windows instead of just saving them')
    
    args = parser.parse_args()
    
    # Determine symbol filtering parameters
    # Note: These refer to overall symbol numbers across all slots (not symbol_id)
    # Overall symbol = slot_id * SYMBOLS_PER_SLOT + symbol_id
    start_symbol = args.start_symbol
    end_symbol = args.end_symbol
    
    # If --symbols is specified, calculate end_symbol from start_symbol and symbols count
    # This limits to the first N overall symbols
    if args.symbols is not None and args.symbols > 0:
        if start_symbol is not None:
            # Start from specified overall symbol, use N overall symbols
            end_symbol = start_symbol + args.symbols - 1
        else:
            # Start from overall symbol 0, use first N overall symbols
            start_symbol = 0
            end_symbol = args.symbols - 1
    
    # Validate symbol range if provided
    # Note: Overall symbol numbers can go much higher than 63 since they span multiple slots
    if start_symbol is not None and end_symbol is not None:
        if start_symbol > end_symbol:
            print(f"Error: --start-symbol ({start_symbol}) must be <= --end-symbol ({end_symbol})")
            sys.exit(1)
        if start_symbol < 0:
            print(f"Error: Start symbol must be >= 0")
            sys.exit(1)
    
    # When --symbols is used, restrict to first frame/subframe/slot
    # When --start-symbol/--end-symbol is used directly, allow any frame/subframe/slot
    # restrict_to_first = (args.symbols is not None and args.symbols > 0)
    # Disable restriction to first combo to allow symbols to span across slots
    restrict_to_first = False
    
    # Use global variables as defaults ONLY if no compression arguments provided at all
    # If any compression argument is provided, use those explicitly
    if not args.bfp and args.bitwidth is None:
        # No compression arguments provided - use globals
        force_bfp_setting = (FORCE_COMPRESSION_TYPE.upper() == 'BFP')
        bfp_bitwidth_setting = FORCE_BFP_BITWIDTH
    else:
        # Compression arguments provided - use them explicitly
        force_bfp_setting = args.bfp
        bfp_bitwidth_setting = args.bitwidth if args.bitwidth is not None else FORCE_BFP_BITWIDTH
    
    # Extract IQ samples with metadata (also collects analysis data in a single pass)
    use_parallel = not args.no_parallel  # Default to parallel, disable if --no-parallel is set
    iq_data, analysis_data, total_packets = extract_iq_with_metadata(
        args.pcap_file, force_bfp=force_bfp_setting, bfp_exponent=args.bfp_exponent, bfp_bitwidth=bfp_bitwidth_setting,
        start_symbol=start_symbol, end_symbol=end_symbol, restrict_to_first_combo=restrict_to_first,
        use_parallel=use_parallel)
    
    if len(iq_data) == 0:
        print("No IQ data found!")
        print("Check Compression Settings!")
        sys.exit(1)
    
    # Print analysis report (uses data collected during extraction)
    print_analysis_report(analysis_data, total_packets, start_symbol=start_symbol, end_symbol=end_symbol)
    
    # Create resource allocation plot
    if analysis_data['packet_count'] > 0:
        plot_resource_allocation(analysis_data, args.pcap_file, show_plot=args.show_plots, start_symbol=start_symbol, end_symbol=end_symbol)
    
    # Create Plots directory in workspace root
    workspace_root = os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.'
    plots_dir = os.path.join(workspace_root, 'Plots')
    os.makedirs(plots_dir, exist_ok=True)
    
    # Save separated data
    print("Saving data files...")
    save_separated_data(iq_data, args.output_base)
    
    # Determine max_samples based on symbols or samples parameter
    # Note: start_symbol and end_symbol may have been set by --symbols above
    # If --samples is 0, it means plot all samples (no limit)
    max_samples = args.samples if args.samples > 0 else 0
    # Only calculate samples per symbol if --symbols was specified but start/end weren't explicitly set
    if args.symbols is not None and args.start_symbol is None and args.end_symbol is None:
        # Find the first eAxC ID with data to calculate samples per symbol
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
            if max_samples > 0:
                print(f"Warning: Could not determine samples per symbol, using default {max_samples:,} samples")
            else:
                print(f"Warning: Could not determine samples per symbol, plotting all samples")
    elif start_symbol is not None or end_symbol is not None:
        # Symbol range specified - calculate max_samples for display purposes
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
            if max_samples > 0:
                print(f"Warning: Could not determine samples per symbol, using default {max_samples:,} samples")
            else:
                print(f"Warning: Could not determine samples per symbol, plotting all samples")
    
    # Create comparison plot
    print("Creating comparison plot...")
    plot_comparison(iq_data, f"{args.output_base}_UL_vs_DL.png", max_samples=max_samples, 
                    start_symbol=start_symbol, end_symbol=end_symbol, plots_dir=plots_dir,
                    show_plot=args.show_plots)
    
    # Create individual plots for each eAxC/direction
    print("Creating individual plots...")
    plot_all_eaxc(iq_data, args.output_base, max_samples=max_samples, 
                  start_symbol=start_symbol, end_symbol=end_symbol, plots_dir=plots_dir,
                  show_plot=args.show_plots)
    
    print("Done!")
    
    # Check for low IQ backoff and print warning
    low_backoff_eaxcs = []
    if analysis_data and 'max_iq_values' in analysis_data and analysis_data['max_iq_values']:
        for eaxc_id in analysis_data['max_iq_values']:
            max_iq = analysis_data['max_iq_values'][eaxc_id]['max_abs']
            dbfs = calculate_dbfs(max_iq)
            if dbfs is not None:
                backoff = -dbfs  # Negate to get backoff (positive = backoff)
                if backoff < 3.0:
                    low_backoff_eaxcs.append((eaxc_id, backoff))
    
    if low_backoff_eaxcs:
        print()
        print("=" * 80)
        print("WARNING: LOW IQ BACKOFF DETECTED")
        print("=" * 80)
        for eaxc_id, backoff in low_backoff_eaxcs:
            print(f"  eAxC {eaxc_id}: IQ Backoff is {backoff:.2f} dBFS (less than 3 dBFS)")
        print()
        print("  WARNING: IQ Backoff is less than 3 dBFS. This might cause saturation,")
        print("           impacting BLER (Block Error Rate).")
        print("=" * 80)
    
    # Calculate and print execution time
    end_time = time.time()
    execution_time = end_time - start_time
    print(f"\nExecution time: {execution_time:.2f} seconds ({execution_time/60:.2f} minutes)")
    
    # Show all plots at once if interactive mode is enabled
    if args.show_plots:
        import matplotlib.pyplot as plt
        print("Displaying all plots...")
        plt.show()


