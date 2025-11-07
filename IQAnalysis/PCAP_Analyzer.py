"""
Enhanced 5G NR Fronthaul IQ Extractor
Separates IQ samples by direction (UL/DL) and eAxC ID
"""
import sys
import struct
import numpy as np
from scapy.all import rdpcap
from scapy.layers.l2 import Dot1Q
from collections import defaultdict

def extract_iq_with_metadata(pcap_file):
    """Extract IQ samples with direction and eAxC ID information"""
    print(f"Reading {pcap_file}...")
    packets = rdpcap(pcap_file)
    print(f"Found {len(packets)} packets\n")
    
    # Organize by eAxC ID and direction
    iq_data = defaultdict(lambda: {'UL': [], 'DL': [], 'metadata': []})
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
                iq_data_bytes = ecpri_data[iq_offset:]
                
                # Parse 16-bit I/Q samples (big-endian signed integers)
                num_samples = len(iq_data_bytes) // 4
                
                samples = []
                for i in range(num_samples):
                    i_val = struct.unpack('!h', iq_data_bytes[i*4:i*4+2])[0]
                    q_val = struct.unpack('!h', iq_data_bytes[i*4+2:i*4+4])[0]
                    samples.append(complex(i_val, q_val))
                
                # Store samples by eAxC ID and direction
                iq_data[eaxc_id][direction].extend(samples)
                
                # Store metadata for this packet
                iq_data[eaxc_id]['metadata'].append({
                    'direction': direction,
                    'seq_id': seq_id,
                    'frame_id': frame_id,
                    'subframe_id': subframe_id,
                    'slot_id': slot_id,
                    'symbol_id': symbol_id,
                    'num_samples': num_samples,
                    'filter_index': filter_index
                })
    
    print(f"Processed {packet_count} IQ data packets\n")
    
    # Print summary by eAxC ID
    print("=" * 70)
    print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10}")
    print("=" * 70)
    
    total_ul = 0
    total_dl = 0
    
    for eaxc_id in sorted(iq_data.keys()):
        ul_samples = len(iq_data[eaxc_id]['UL'])
        dl_samples = len(iq_data[eaxc_id]['DL'])
        
        if ul_samples > 0:
            ul_packets = sum(1 for m in iq_data[eaxc_id]['metadata'] if m['direction'] == 'UL')
            print(f"{eaxc_id:<10} {'UL':<12} {ul_samples:<15,} {ul_packets:<10}")
            total_ul += ul_samples
            
        if dl_samples > 0:
            dl_packets = sum(1 for m in iq_data[eaxc_id]['metadata'] if m['direction'] == 'DL')
            print(f"{eaxc_id:<10} {'DL':<12} {dl_samples:<15,} {dl_packets:<10}")
            total_dl += dl_samples
    
    print("=" * 70)
    print(f"{'TOTAL':<10} {'UL':<12} {total_ul:<15,}")
    print(f"{'TOTAL':<10} {'DL':<12} {total_dl:<15,}")
    print("=" * 70)
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

def plot_comparison(iq_data, output_file, max_samples=10000):
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
    
    ul_samples = np.array(iq_data[eaxc_with_both]['UL'][:max_samples])
    dl_samples = np.array(iq_data[eaxc_with_both]['DL'][:max_samples])
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f'UL vs DL Comparison (eAxC ID: {eaxc_with_both})', fontsize=14, fontweight='bold')
    
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

def plot_all_eaxc(iq_data, output_base, max_samples=10000):
    """Create individual plots for each eAxC ID"""
    import matplotlib.pyplot as plt
    
    for eaxc_id in sorted(iq_data.keys()):
        for direction in ['UL', 'DL']:
            if len(iq_data[eaxc_id][direction]) == 0:
                continue
            
            samples = np.array(iq_data[eaxc_id][direction][:max_samples])
            
            fig, axes = plt.subplots(2, 2, figsize=(12, 10))
            fig.suptitle(f'eAxC ID: {eaxc_id} - {direction}', fontsize=14, fontweight='bold')
            
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
    if len(sys.argv) < 2:
        print("Usage: python PCAP_Analyzer.py <pcap_file> [output_base_name]")
        print("Example: python PCAP_Analyzer.py capture.pcap iq_data")
        print("\nExtracts IQ samples separated by eAxC ID and direction (UL/DL)")
        sys.exit(1)
    
    pcap_file = sys.argv[1]
    output_base = sys.argv[2] if len(sys.argv) > 2 else "iq_separated"
    
    # Extract IQ samples with metadata
    iq_data = extract_iq_with_metadata(pcap_file)
    
    if len(iq_data) == 0:
        print("No IQ data found!")
        sys.exit(1)
    
    # Save separated data
    print("Saving data files...")
    save_separated_data(iq_data, output_base)
    
    # Create comparison plot
    print("Creating comparison plot...")
    plot_comparison(iq_data, f"{output_base}_UL_vs_DL.png")
    
    # Create individual plots for each eAxC/direction
    print("Creating individual plots...")
    plot_all_eaxc(iq_data, output_base)
    
    print("Done!")

