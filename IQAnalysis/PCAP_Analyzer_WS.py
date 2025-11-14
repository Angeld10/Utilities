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
from collections import defaultdict
try:
    import pyshark
except ImportError:
    print("Error: pyshark library not found. Please install it with: pip install pyshark")
    sys.exit(1)

# Import helper functions from the original script
# We'll copy the helper functions that don't depend on scapy

FORCE_COMPRESSION_TYPE = 'BFP'  # 'BFP' or 'uncompressed'
FORCE_BFP_BITWIDTH = 9                  # 8-14 for BFP compression
NUMEROLOGY = 1                            # 0 (15 kHz SCS) or 1 (30 kHz SCS)
MAX_RBS = 106                            # Maximum Resource Blocks in 5G NR
ENDIAN = 'big'                        # 'little' or 'big' endian for byte order

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

def parse_iq_samples(ecpri_data, iq_offset, payload_version, filter_index, force_bfp=False, bfp_exponent=None, bfp_bitwidth=None):
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
        if FORCE_BFP_BITWIDTH is None:
            raise ValueError("FORCE_BFP_BITWIDTH must be set")
        if FORCE_BFP_BITWIDTH < 8 or FORCE_BFP_BITWIDTH > 14:
            raise ValueError(f"Invalid FORCE_BFP_BITWIDTH: {FORCE_BFP_BITWIDTH}")
        
        bfp_bits = FORCE_BFP_BITWIDTH
        samples_per_rb = 12
        max_rbs = MAX_RBS
        
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
    
    return samples, compression_type, num_samples, exponents_list

def parse_iq_from_prb_raw(prb_raw, compression_method, compression_width):
    """
    Parse IQ samples from prb_raw list structure.
    
    Args:
        prb_raw: List of lists, where each inner list contains [hex_string, offset, length, ...]
        compression_method: Compression method (1 = BFP, 0 = uncompressed)
        compression_width: Compression width in bits (for BFP: 8-14)
    
    Returns:
        tuple: (samples_list, compression_type, num_samples, exponents_list)
    """
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
                # Remove spaces/colons and convert to bytes
                hex_clean = hex_str.replace(':', '').replace(' ', '')
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
        max_rbs = MAX_RBS
        
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

def extract_iq_with_metadata(pcap_file, force_bfp=False, bfp_exponent=None):
    """Extract IQ samples with direction and eAxC ID information using pyshark"""
    # Normalize path to handle relative paths correctly
    pcap_file = os.path.normpath(os.path.abspath(pcap_file))
    print(f"Reading {pcap_file} with pyshark...")
    
    try:
        # Open pcap file with pyshark
        # Try without display filter first, then filter in Python
        # Display filters can cause issues with some TShark versions
        try:
            cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
        except:
            try:
                cap = pyshark.FileCapture(pcap_file, use_json=True)
            except:
                # Fallback to basic capture
                cap = pyshark.FileCapture(pcap_file)
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        return {}
    
    # Organize by eAxC ID and direction
    iq_data = defaultdict(lambda: {'UL': [], 'DL': [], 'metadata': []})
    # Track maximum uncompressed I/Q values per eAxC ID
    max_iq_values = defaultdict(lambda: {'max_i': 0, 'max_q': 0, 'max_abs': 0})
    
    print("Processing packets...")
    packet_count = 0
    for packet in cap:
        try:
            # Skip non-ORAN FH packets early
            # Check if packet has ORAN_FH_CUS layer
            # pyshark layer names can vary, so check both 'in' operator and layer names directly
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
                print("no ORAN FH CUS layer found")
                continue
            
            
            # Get ORAN FH CUS fields from packet
            fields = get_oran_fh_cus_fields_from_packet(packet)

            # If we couldn't parse ORAN FH fields, skip this packet
            if not fields:
                continue
            
            # Extract ORAN FH CUS fields using the actual field names from extraction
            section_id = int(fields.get('sectionId', 0)) if 'sectionId' in fields else 0
            frame_id = fields.get('frame_id', 0)
            subframe_id = fields.get('subframe_id', 0)
            slot_id = fields.get('slot_id', 0)
            start_symbol_id = fields.get('start_symbol_id', 0)
            # Calculate num_symbols from sym_inc or use default
            sym_inc = fields.get('sym_inc', 0)
            num_symbols = sym_inc + 1 if sym_inc > 0 else 1
            start_prbc = fields.get('start_prbc', 0)
            # Get compression method and width from fields (hardcoded from top variables)
            # Default to BFP if not set
            compression_method = fields.get('compression_method', 1 if FORCE_COMPRESSION_TYPE.upper() == 'BFP' else 0)
            compression_width = fields.get('compression_width', FORCE_BFP_BITWIDTH)
            prb_raw = fields.get('prb_raw', None)
            
            # Determine direction from data_direction field (1 = DL, 0 = UL)
            data_direction = fields.get('data_direction', 1)
            direction = 'DL' if data_direction == 1 else 'UL'
            
            # Extract IQ samples from prb_raw if available
            if prb_raw is not None:
                samples, compression_type, num_samples, exponents_list = parse_iq_from_prb_raw(
                    prb_raw, compression_method, compression_width)
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
                    force_bfp=force_bfp, bfp_exponent=bfp_exponent)
            
            # Store samples by section_id (equivalent to eAxC ID) and direction
            iq_data[section_id][direction].extend(samples)
            
            # Track maximum uncompressed I/Q values for this eAxC ID
            if len(samples) > 0:
                max_i, max_q, max_abs = calculate_max_iq(samples)
                
                # Update maximums for this section_id
                if max_abs > max_iq_values[section_id]['max_abs']:
                    max_iq_values[section_id]['max_i'] = max_i
                    max_iq_values[section_id]['max_q'] = max_q
                    max_iq_values[section_id]['max_abs'] = max_abs
            
            # Use the exponents list directly if BFP (already one per RB)
            rb_exponents = None
            if compression_type.startswith('BFP') and exponents_list is not None:
                # exponents_list already contains one exponent per RB
                rb_exponents = [int(exp) for exp in exponents_list]
            
            # Store metadata for this packet (ORAN FH CUS format)
            metadata_entry = {
                'direction': direction,
                'section_id': section_id,
                'frame_id': frame_id,
                'subframe_id': subframe_id,
                'slot_id': slot_id,
                'start_symbol_id': start_symbol_id,
                'num_symbols': num_symbols,
                'start_prbc': start_prbc,
                'sym_inc': sym_inc,
                'num_samples': num_samples,
                'compression_type': compression_type,
                'compression_method': compression_method,
                'compression_width': compression_width
            }
            
            # Add RB exponents array if BFP compression is used
            if rb_exponents is not None:
                metadata_entry['rb_exponents'] = rb_exponents
            
            iq_data[section_id]['metadata'].append(metadata_entry)
            packet_count += 1
            
        except Exception as e:
            # Skip packets that cause errors
            continue
    
    cap.close()
    print(f"Processed {packet_count} IQ data packets\n")
    
    # Print summary by eAxC ID
    print("=" * 110)
    print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10} {'Max I/Q':<15} {'Est. IQ Backoff':<18}")
    print("=" * 110)
    
    total_ul = 0
    total_dl = 0
    
    for section_id in sorted(iq_data.keys()):
        ul_samples = len(iq_data[section_id]['UL'])
        dl_samples = len(iq_data[section_id]['DL'])
        max_iq = max_iq_values[section_id]['max_abs']
        
        if ul_samples > 0:
            ul_packets = sum(1 for m in iq_data[section_id]['metadata'] if m['direction'] == 'UL')
            max_iq_str = f"{max_iq:.0f}" if max_iq > 0 else "N/A"
            dbfs = calculate_dbfs(max_iq)
            dbfs_str = f"{dbfs:.1f} dBFS" if dbfs is not None else "N/A"
            print(f"{section_id:<10} {'UL':<12} {ul_samples:<15,} {ul_packets:<10} {max_iq_str:<15} {dbfs_str:<18}")
            total_ul += ul_samples
        
        if dl_samples > 0:
            dl_packets = sum(1 for m in iq_data[section_id]['metadata'] if m['direction'] == 'DL')
            max_iq_str = f"{max_iq:.0f}" if max_iq > 0 else "N/A"
            dbfs = calculate_dbfs(max_iq)
            dbfs_str = f"{dbfs:.1f} dBFS" if dbfs is not None else "N/A"
            print(f"{section_id:<10} {'DL':<12} {dl_samples:<15,} {dl_packets:<10} {max_iq_str:<15} {dbfs_str:<18}")
            total_dl += dl_samples
    
    print("=" * 110)
    print(f"{'TOTAL':<10} {'UL':<12} {total_ul:<15,}")
    print(f"{'TOTAL':<10} {'DL':<12} {total_dl:<15,}")
    print("=" * 110)
    print()
    
    return iq_data

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
            full_scale_power = 32767.0 ** 2  # Full scale power for 16-bit signed integers
            avg_power_dbfs = 10 * math.log10(avg_power / full_scale_power) if avg_power > 0 else float('-inf')
            with open(f"{filename}_stats.txt", 'w') as f:
                f.write(f"eAxC ID: {eaxc_id}\n")
                f.write(f"Direction: Uplink (UL)\n")
                f.write(f"Total samples: {len(ul_array):,}\n")
                f.write(f"I - Mean: {np.mean(ul_array.real):.2f}, Std: {np.std(ul_array.real):.2f}\n")
                f.write(f"Q - Mean: {np.mean(ul_array.imag):.2f}, Std: {np.std(ul_array.imag):.2f}\n")
                f.write(f"Magnitude - Mean: {np.mean(np.abs(ul_array)):.2f}, Max: {np.max(np.abs(ul_array)):.2f}\n")
                f.write(f"Average Power: {avg_power_dbfs:.2f} dBFS\n")
        
        # Save DL data
        if len(iq_data[eaxc_id]['DL']) > 0:
            dl_array = np.array(iq_data[eaxc_id]['DL'])
            filename = f"{output_base}_eAxC{eaxc_id}_DL"
            np.save(f"{filename}.npy", dl_array)
            print(f"Saved: {filename}.npy ({len(dl_array):,} samples)")
            
            # Save DL statistics
            avg_power = np.mean(np.abs(dl_array)**2)
            full_scale_power = 32767.0 ** 2  # Full scale power for 16-bit signed integers
            avg_power_dbfs = 10 * math.log10(avg_power / full_scale_power) if avg_power > 0 else float('-inf')
            with open(f"{filename}_stats.txt", 'w') as f:
                f.write(f"eAxC ID: {eaxc_id}\n")
                f.write(f"Direction: Downlink (DL)\n")
                f.write(f"Total samples: {len(dl_array):,}\n")
                f.write(f"I - Mean: {np.mean(dl_array.real):.2f}, Std: {np.std(dl_array.real):.2f}\n")
                f.write(f"Q - Mean: {np.mean(dl_array.imag):.2f}, Std: {np.std(dl_array.imag):.2f}\n")
                f.write(f"Magnitude - Mean: {np.mean(np.abs(dl_array)):.2f}, Max: {np.max(np.abs(dl_array)):.2f}\n")
                f.write(f"Average Power: {avg_power_dbfs:.2f} dBFS\n")
        
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

def plot_comparison(iq_data, output_file, max_samples=10000, start_symbol=None, end_symbol=None, plots_dir=None):
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

def plot_all_eaxc(iq_data, output_base, max_samples=10000, start_symbol=None, end_symbol=None, plots_dir=None):
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
            plot_file = os.path.join(plots_dir, f"{output_base}_eAxC{eaxc_id}_{direction}.png")
            plt.savefig(plot_file, dpi=150, bbox_inches='tight')
            print(f"Saved plot: {plot_file}")
            plt.close()
    
    print()

def analyze_pcap(pcap_file, force_bfp=False, bfp_exponent=None):
    """Analyze PCAP file and display summary information without extracting full data (using pyshark)"""
    # Normalize path to handle relative paths correctly
    pcap_file = os.path.normpath(os.path.abspath(pcap_file))
    print(f"Analyzing {pcap_file} with pyshark...")
    
    try:
        # Try with use_json and include_raw for better raw data access
        # Don't use display filter as it can cause TShark crashes
        try:
            cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
        except:
            try:
                cap = pyshark.FileCapture(pcap_file, use_json=True)
            except:
                cap = pyshark.FileCapture(pcap_file)
        
        total_packets = 0
        for _ in cap:
            total_packets += 1
        cap.close()
        
        # Reopen for processing
        try:
            cap = pyshark.FileCapture(pcap_file, use_json=True, include_raw=True)
        except:
            try:
                cap = pyshark.FileCapture(pcap_file, use_json=True)
            except:
                cap = pyshark.FileCapture(pcap_file)
    except Exception as e:
        print(f"Error opening pcap file: {e}")
        return {}
    
    print(f"Found {total_packets} total packets\n")
    
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
        'symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: {'packets': 0, 'samples': 0})),
        'slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(int))),
        'frame_subframe_slot_symbol_eaxc_data': defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: defaultdict(lambda: {'packets': 0, 'samples': 0}))))),
        'compression_types': set(),
        'max_iq_values': defaultdict(lambda: {'max_i': 0.0, 'max_q': 0.0, 'max_abs': 0.0})
    }
    
    for packet in cap:
        try:
            # Get eCPRI fields from Wireshark's parsed data
            fields = get_ecpri_fields_from_packet(packet)
            
            # If Wireshark didn't parse it, try manual extraction
            if not fields:
                ecpri_data = extract_ecpri_data_from_packet(packet)
                if ecpri_data is None or len(ecpri_data) < 16:
                    continue
                
                # Parse manually
                fields = {}
                fields['msg_type'] = ecpri_data[1]
                fields['eaxc_id'] = struct.unpack('!H', ecpri_data[4:6])[0]
                radio_start = 8
                if len(ecpri_data) > radio_start + 7:
                    fields['data_direction'] = (ecpri_data[radio_start] >> 7) & 0x01
                    fields['payload_version'] = (ecpri_data[radio_start] >> 4) & 0x07
                    fields['filter_index'] = ecpri_data[radio_start] & 0x0F
                    fields['frame_id'] = ecpri_data[radio_start + 1]
                    fields['subframe_id'] = (ecpri_data[radio_start + 2] >> 4) & 0x0F
                    fields['slot_id'] = ((ecpri_data[radio_start + 2] & 0x0F) << 2) | ((ecpri_data[radio_start + 3] >> 6) & 0x03)
                    fields['symbol_id'] = ecpri_data[radio_start + 3] & 0x3F
            
            # Check if this is an IQ data message (type 0x00)
            if fields.get('msg_type', -1) != 0x00:
                continue
            
            analysis_data['packet_count'] += 1
            
            # Get packet timestamp
            try:
                if hasattr(packet, 'sniff_timestamp'):
                    timestamp = float(packet.sniff_timestamp)
                    analysis_data['packet_timestamps'].append(timestamp)
            except:
                pass
            
            # Extract fields
            eaxc_id = fields.get('eaxc_id', 0)
            data_direction = fields.get('data_direction', 0)
            payload_version = fields.get('payload_version', 0)
            filter_index = fields.get('filter_index', 0)
            frame_id = fields.get('frame_id', 0)
            subframe_id = fields.get('subframe_id', 0)
            slot_id = fields.get('slot_id', 0)
            symbol_id = fields.get('symbol_id', 0)
            
            direction = 'DL' if data_direction == 1 else 'UL'
            
            # Get raw eCPRI data
            ecpri_data = extract_ecpri_data_from_packet(packet)
            if ecpri_data is None or len(ecpri_data) < 16:
                continue
            
            # Skip headers to get IQ data
            iq_offset = 16
            # Parse IQ samples (handles both uncompressed and BFP compressed)
            samples, compression_type, num_samples, exponents_list = parse_iq_samples(
                ecpri_data, iq_offset, payload_version, filter_index, 
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
            analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][symbol_id][eaxc_id]['packets'] += 1
            analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][symbol_id][eaxc_id]['samples'] += num_samples
            
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
    
    # Create resource allocation plot (reuse function from original)
    if analysis_data['packet_count'] > 0:
        plot_resource_allocation(analysis_data, pcap_file)
    
    return analysis_data

def plot_resource_allocation(analysis_data, pcap_file):
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
    max_rbs_limit = MAX_RBS
    
    # Get base name and directory for output files
    # Create Plots directory in the workspace root (IQAnalysis folder)
    workspace_root = os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.'
    plots_dir = os.path.join(workspace_root, 'Plots')
    os.makedirs(plots_dir, exist_ok=True)
    
    base_name = os.path.basename(pcap_file)
    base_name = base_name.replace('.pcap', '')
    
    # Create a separate plot for each eAxC ID
    for eaxc_id in eaxc_list:
        # Collect all unique (frame, subframe, slot, symbol) combinations for this eAxC ID
        unique_combinations = []
        combination_data = {}  # (frame, subframe, slot, symbol) -> {'samples': X, 'rbs': Y}
        
        for frame_id in sorted(analysis_data['frames']):
            for subframe_id in sorted(analysis_data['subframes']):
                for slot_id in sorted(analysis_data['slots']):
                    for symbol_id in sorted(analysis_data['symbols']):
                        if (frame_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'] and
                            subframe_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id] and
                            slot_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id] and
                            symbol_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id] and
                            eaxc_id in analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][symbol_id]):
                            
                            symbol_data = analysis_data['frame_subframe_slot_symbol_eaxc_data'][frame_id][subframe_id][slot_id][symbol_id][eaxc_id]
                            total_samples = symbol_data['samples']
                            packet_count = symbol_data['packets']
                            
                            if total_samples > 0:
                                combo = (frame_id, subframe_id, slot_id, symbol_id)
                                unique_combinations.append(combo)
                                
                                expected_samples_for_max_rbs = MAX_RBS * 12
                                
                                if total_samples > expected_samples_for_max_rbs * 1.5:
                                    ratio = expected_samples_for_max_rbs / total_samples
                                    estimated_active_subcarriers = total_samples * ratio
                                    num_rbs = int(np.ceil(estimated_active_subcarriers / samples_per_rb))
                                else:
                                    num_rbs = int(np.ceil(total_samples / samples_per_rb))
                                
                                if num_rbs > max_rbs_limit:
                                    num_rbs = max_rbs_limit
                                combination_data[combo] = {'samples': total_samples, 'rbs': num_rbs, 'packets': packet_count}
        
        if len(unique_combinations) == 0:
            continue  # Skip this eAxC ID if no data
        
        # Find maximum number of RBs across all combinations
        max_rbs = max(combo_data['rbs'] for combo_data in combination_data.values())
        
        # Cap at maximum RBs
        if max_rbs > max_rbs_limit:
            max_rbs = max_rbs_limit
        
        if max_rbs == 0:
            continue
        
        # Create a 2D grid: rows = RBs, columns = unique (frame, slot, symbol) combinations
        num_columns = len(unique_combinations)
        grid = np.zeros((max_rbs, num_columns))
        
        # Fill grid - mark allocated RBs with their RB index + 1
        for col_idx, combo in enumerate(unique_combinations):
            if len(combo) == 4:  # (frame_id, subframe_id, slot_id, symbol_id)
                frame_id, subframe_id, slot_id, symbol_id = combo
            else:  # Backward compatibility
                frame_id, slot_id, symbol_id = combo
            combo_info = combination_data[combo]
            num_rbs_for_combo = combo_info['rbs']
            
            for rb_idx in range(num_rbs_for_combo):
                if rb_idx < max_rbs:
                    grid[rb_idx, col_idx] = rb_idx + 1  # Each RB gets unique value
        
        # Create colormap - each RB gets a distinct color
        unallocated_color = '#f0f0f0'  # Light gray for unallocated
        
        # Create distinct colors for each RB using a colormap
        if max_rbs <= 20:
            base_colors = plt.cm.tab20(np.linspace(0, 1, 20))
        elif max_rbs <= 50:
            base_colors = plt.cm.Set3(np.linspace(0, 1, 12))
        else:
            base_colors = plt.cm.hsv(np.linspace(0, 1, max_rbs))
        
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
        
        # Set ticks and labels - only show labels for first symbol of each slot
        ax.set_xticks(range(num_columns))
        column_labels = []
        seen_slots = set()  # Track (frame, subframe, slot) combinations we've labeled
        for combo in unique_combinations:
            if len(combo) == 4:  # (frame_id, subframe_id, slot_id, symbol_id)
                frame_id, subframe_id, slot_id, symbol_id = combo
                slot_key = (frame_id, subframe_id, slot_id)
                # Only label the first symbol of each slot
                if slot_key not in seen_slots:
                    column_labels.append(f'F{frame_id}SF{subframe_id}S{slot_id}')
                    seen_slots.add(slot_key)
                else:
                    column_labels.append('')  # Empty label for other symbols in the slot
            else:  # Backward compatibility
                frame_id, slot_id, symbol_id = combo
                slot_key = (frame_id, slot_id)
                if slot_key not in seen_slots:
                    column_labels.append(f'F{frame_id}S{slot_id}')
                    seen_slots.add(slot_key)
                else:
                    column_labels.append('')
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
        ax.set_xlabel('Frame/Subframe/Slot (labeled at first symbol of each slot)', fontsize=14, fontweight='bold')
        ax.set_ylabel('Resource Block (RB) Index', fontsize=14, fontweight='bold')
        ax.set_title(f'Resource Allocation: eAxC ID {eaxc_id}\n(Each column = unique Frame/Subframe/Slot/Symbol, Each cell = 1 RB = 12 subcarriers)', 
                     fontsize=16, fontweight='bold', pad=20)
        
        plt.tight_layout(pad=3.0)
        
        # Save plot with higher DPI in Plots directory
        output_file = os.path.join(plots_dir, f'{base_name}_eAxC{eaxc_id}_resource_allocation.png')
        plt.savefig(output_file, dpi=200, bbox_inches='tight')
        print(f"Saved resource allocation plot for eAxC {eaxc_id}: {output_file}")
        plt.close()
    
    print()  # Add blank line after all plots

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Extract IQ samples from 5G NR Fronthaul PCAP files (Wireshark-based)'
    )
    parser.add_argument('pcap_file', help='Path to PCAP file')
    parser.add_argument('output_base', nargs='?', default='iq_separated',
                       help='Base name for output files (default: iq_separated)')
    parser.add_argument('--symbols', type=int, metavar='N',
                       help='Number of symbols to plot')
    parser.add_argument('--samples', type=int, default=10000, metavar='N',
                       help='Number of samples to plot (default: 10000)')
    parser.add_argument('--start-symbol', type=int, metavar='N',
                       help='Start symbol ID (0-63)')
    parser.add_argument('--end-symbol', type=int, metavar='N',
                       help='End symbol ID (0-63)')
    parser.add_argument('--analyze', action='store_true',
                       help='Analyze PCAP file only')
    parser.add_argument('--force-bfp', action='store_true',
                       help='Force BFP decompression')
    parser.add_argument('--bfp-exponent', type=int, metavar='N',
                       help='BFP exponent value (0-15)')
    
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
    
    # Create Plots directory in workspace root
    workspace_root = os.path.dirname(os.path.abspath(__file__)) if os.path.dirname(os.path.abspath(__file__)) else '.'
    plots_dir = os.path.join(workspace_root, 'Plots')
    os.makedirs(plots_dir, exist_ok=True)
    
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
    max_samples = args.samples
    if start_symbol is None and end_symbol is None and args.symbols is not None:
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
            print(f"Warning: Could not determine samples per symbol, using default {max_samples:,} samples")
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
            print(f"Warning: Could not determine samples per symbol, using default {max_samples:,} samples")
    
    # Create comparison plot
    print("Creating comparison plot...")
    plot_comparison(iq_data, f"{args.output_base}_UL_vs_DL.png", max_samples=max_samples, 
                    start_symbol=start_symbol, end_symbol=end_symbol, plots_dir=plots_dir)
    
    # Create individual plots for each eAxC/direction
    print("Creating individual plots...")
    plot_all_eaxc(iq_data, args.output_base, max_samples=max_samples, 
                  start_symbol=start_symbol, end_symbol=end_symbol, plots_dir=plots_dir)
    
    print("Done!")

