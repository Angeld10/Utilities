"""
Enhanced 5G NR Fronthaul IQ Extractor
Separates IQ samples by direction (UL/DL) and eAxC ID
"""
import sys
import struct
import numpy as np
#import pyshark
import os
import subprocess, shutil
from pathlib import Path
from scapy.all import rdpcap
from scapy.layers.l2 import Dot1Q
from collections import defaultdict

output = "iq_data"
pcap_file = "PCAP_Files/fh_1x1.pcap"

DEFAULT_CONFIG = {
    "method": "bfp",      # or "int16"
    "mant_bits": 9,
    "prb_len": 12,
    "byteorder": "big",
    "iq_interleaved": True,
    # path fallback (can be overwritten per file)
    "pcap_path": None,
}

# --- Capture-specific config (tie settings to the file you pick) ---
# Add more entries if you switch PCAPs frequently.
PCAP_CONFIGS = {
    Path("PCAP_Files/fh_2x2_-3_2frames.pcap"): {
        **DEFAULT_CONFIG,
        "method": "bfp",
        "mant_bits": 9,
        "pcap_path": Path("PCAP_Files/fh_1x1.pcap"),
    },
    # Example uncompressed:
    Path("PCAP_Files/uncompressed_example.pcap"): {
        **DEFAULT_CONFIG,
        "method": "int16",
        "pcap_path": Path("PCAP_Files/fh_2x2_-3_2frames.pcap"),
    },
}
# Pick the one matching pcap_file; if not found, default to int16:
default_pcap_file = Path("PCAP_Files/fh_2x2_-3_2frames.pcap")


def _twos_to_signed(u, nbits):
    sign = 1 << (nbits - 1)
    return ((u ^ sign) - sign).astype(np.int32)

def decode_uncompressed_int16(payload: bytes, byteorder="big", iq_interleaved=True) -> np.ndarray:
    """Uncompressed signed 16-bit IQ → complex64."""
    # Each IQ pair is 4 bytes: 2 for I, 2 for Q
    n = (len(payload) // 4) * 4
    if n == 0:
        return np.zeros(0, dtype=np.complex64)
    dtype = ">i2" if byteorder == "big" else "<i2"
    data = np.frombuffer(payload[:n], dtype=dtype)
    if iq_interleaved:
        I = data[0::2].astype(np.float32)
        Q = data[1::2].astype(np.float32)
    else:
        half = len(data) // 2
        I = data[:half].astype(np.float32)
        Q = data[half:].astype(np.float32)
    return (I + 1j*Q).astype(np.complex64)

def decode_bfp_iq(payload: bytes, mant_bits: int, exp_prb: np.ndarray, prb_len: int = 12) -> np.ndarray:
    """Decompress O-RAN BFP (block-floating) IQ → complex64."""
    bits_per_pair = 2 * mant_bits
    bits_per_prb  = bits_per_pair * prb_len

    b = np.frombuffer(payload, dtype=np.uint8)
    bits = np.unpackbits(b, bitorder='big')  # MSB-first inside each byte

    n_prb_payload = len(bits) // bits_per_prb
    if n_prb_payload == 0:
        return np.zeros(0, dtype=np.complex64)

    bits = bits[: n_prb_payload * bits_per_prb].reshape(n_prb_payload, bits_per_prb)
    w = (1 << np.arange(mant_bits - 1, -1, -1, dtype=np.int64))  # MSB..LSB weights

    out = np.empty(n_prb_payload * prb_len, dtype=np.complex64)
    for p in range(n_prb_payload):
        e = int(exp_prb[p]) if p < len(exp_prb) else 0  # safety fallback
        prb_bits = bits[p].reshape(prb_len, bits_per_pair)
        I_bits = prb_bits[:, :mant_bits]
        Q_bits = prb_bits[:, mant_bits:mant_bits*2]
        Iu = (I_bits * w).sum(axis=1, dtype=np.int64)
        Qu = (Q_bits * w).sum(axis=1, dtype=np.int64)
        I = _twos_to_signed(Iu, mant_bits).astype(np.float32)
        Q = _twos_to_signed(Qu, mant_bits).astype(np.float32)
        scale = np.float32(2.0 ** e)   # exponent per PRB
        out[p*prb_len:(p+1)*prb_len] = (I*scale + 1j*Q*scale).astype(np.complex64)
    return out

def decode_iq_bytes(payload: bytes, cfg: dict, *, exp_prb: np.ndarray | None = None) -> np.ndarray:
    """
    Unified entry point controlled by cfg['method'].
    - method == 'int16' : ignores exp_prb
    - method == 'bfp'   : requires exp_prb (per-PRB exponents)
    """
    method = cfg.get("method", "int16").lower()
    if method == "int16":
        return decode_uncompressed_int16(
            payload,
            byteorder=cfg.get("byteorder", "big"),
            iq_interleaved=cfg.get("iq_interleaved", True),
        )
    elif method == "bfp":
        if exp_prb is None:
            raise ValueError("BFP decoding requires exp_prb (per-PRB exponents).")
        return decode_bfp_iq(
            payload,
            mant_bits=int(cfg.get("mant_bits", 9)),
            exp_prb=exp_prb,
            prb_len=int(cfg.get("prb_len", 12)),
        )
    else:
        raise ValueError(f"Unknown method in config: {method}")

def debug_tshark_call(cmd, pcap_path=None, cwd=None):
    # 1) Show CWD and PATH
    print(f"[debug] CWD: {os.getcwd()}")
    print(f"[debug] cwd override: {cwd}")
    print(f"[debug] PATH has tshark? {shutil.which('tshark')}")
    # 2) Check the pcap path
    if pcap_path is not None:
        p = Path(pcap_path).resolve()
        print(f"[debug] PCAP: {p}")
        print(f"[debug] exists: {p.exists()}  size: {p.stat().st_size if p.exists() else 'N/A'}")
    # 3) Show the exact command
    print("[debug] cmd:", cmd)

    # 4) Try a version probe first
    try:
        ver = subprocess.run(
            ["tshark", "-v"], capture_output=True, text=True, check=True
        )
        print("[debug] tshark -v OK\n", ver.stdout.splitlines()[0])
    except FileNotFoundError:
        print("[error] tshark not found in PATH. Install Wireshark or set full path to tshark.exe")
        return None
    except subprocess.CalledProcessError as e:
        print("[error] tshark -v failed:", e.stderr)
        return None

    # 5) Run the real command, capture stdout/stderr
    try:
        res = subprocess.run(
            cmd, capture_output=True, text=True, check=True, cwd=cwd
        )
        print("[debug] stdout lines:", len(res.stdout.splitlines()))
        if res.stderr:
            print("[debug] stderr:\n", res.stderr[:500])
        return res.stdout
    except FileNotFoundError as e:
        print("[error] Executable not found:", e)
    except subprocess.CalledProcessError as e:
        print("[error] tshark returned non-zero exit code:", e.returncode)
        print("[stderr]\n", (e.stderr or "")[:1000])
        print("[stdout]\n", (e.stdout or "")[:1000])
    return None
def collect_bfp_exponents_tshark(pcap_path, tshark_path=None):
    p = Path(pcap_path).resolve()
    exe = tshark_path or shutil.which("tshark") or "tshark"
    
    cmd = [
        str(exe),
        "-r", str(pcap_file),
        "-Y", "oran_fh_cus.u-plane",
        "-T", "fields",
        "-E", "header=n",
        "-E", "separator=\t",
        "-E", "occurrence=a",
        "-e", "oran_fh_cus.sequence_id",          # IQ-Data SEQ_ID
        "-e", "oran_fh_cus.c_eaxc_id",               # eAxC
        "-e", "oran_fh_cus.exponent",  # per-PRB exponent(s)
    ]
    out = debug_tshark_call(cmd, pcap_path=p)
    if out is None:
        raise RuntimeError("tshark call failed; see debug output above.")

    exps = {}          # seq_id -> np.array of exponents
    pcid_by_seq = {}   # seq_id -> eaxc16 (downcast if you like)

    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) < 2:
            continue
        try:
            seq_id = int(parts[0])
            pcid   = int(parts[1]) if parts[1] else 0
        except ValueError:
            continue
        params = parts[2] if len(parts) > 2 else ""
        vals = [int(v) for v in params.split(",") if v]
        exps[seq_id] = np.asarray(vals, dtype=np.int32)
        pcid_by_seq[seq_id] = (pcid & 0xFFFF)  # downcast to 16-bit “eAxC id”
    return exps, pcid_by_seq


def extract_iq_with_metadata(pcap_file, cfg=None):
    """Extract IQ samples with direction and eAxC ID information"""
    cfg = cfg or PCAP_CONFIGS.get(Path(pcap_file), DEFAULT_CONFIG)
    # Ensure cfg["pcap_path"] is set:
    if not cfg.get("pcap_path"):
        # prefer the key from PCAP_CONFIGS if present; else use the arg
        cfg["pcap_path"] = next((k for k in PCAP_CONFIGS if k == Path(pcap_file)), Path(pcap_file))
    
    use_bfp = cfg.get("method", "int16").lower() == "bfp"
    
    # Pre-collect exponents if we're in BFP mode
    exp_lookup = collect_bfp_exponents_tshark(cfg["pcap_path"]) if use_bfp else {}

    print(f"Reading {pcap_file}...")
    packets = rdpcap(str(pcap_file))
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
                
                # Extract PC_ID/eAxC ID and sequence ID
                # AFTER (use seq_id to join)
                seq_id  = struct.unpack('!H', ecpri_data[6:8])[0]
                # prefer tshark’s PCID/eAxC for consistency with Wireshark
                eaxc_id = pcid_by_seq.get(seq_id,structt.unpack('!H', ecpri_data[4:6])[0])  # fallback

                
                # Radio application header starts at byte 8
                radio_start    = 8
                data_direction = (ecpri_data[radio_start] >> 7) & 0x01
                payload_version= (ecpri_data[radio_start] >> 4) & 0x07
                filter_index   =  ecpri_data[radio_start] & 0x0F
                frame_id       =  ecpri_data[radio_start + 1]
                subframe_id    = (ecpri_data[radio_start + 2] >> 4) & 0x0F
                slot_id        = ((ecpri_data[radio_start + 2] & 0x0F) << 2) | ((ecpri_data[radio_start + 3] >> 6) & 0x03)
                symbol_id      =  ecpri_data[radio_start + 3] & 0x3F
                
                direction = 'DL' if data_direction == 1 else 'UL'
                
                # Skip eCPRI(4) + PC_ID/SeqID(4) + radio header(8) = 16 bytes
                iq_offset = 16  # eCPRI(4) + PC_ID/SeqID(4) + radio header(8)
                iq_payload = ecpri_data[iq_offset:]

                cfg = cfg or PCAP_CONFIGS.get(Path(pcap_file), DEFAULT_CONFIG)
                
                if use_bfp:
                    key = (eaxc_id, seq_id)
                    exp_prb = exp_lookup.get(key)
                if exp_prb is None or len(exp_prb) == 0:
                    # fallback: estimate PRB count from payload length, assume exp=0
                    bits_per_pair = 2 * cfg["mant_bits"]
                    bits_per_prb  = bits_per_pair * cfg.get("prb_len", 12)
                    n_prb_payload = (len(iq_payload) * 8) // bits_per_prb
                    exp_prb = np.zeros(n_prb_payload, dtype=np.int32)
                    samples_vec = decode_iq_bytes(iq_payload, cfg, exp_prb=exp_prb)
                else:
                    samples_vec = decode_iq_bytes(iq_payload, cfg, exp_prb=exp_prb)

                iq_data[eaxc_id][direction].extend(samples_vec.tolist())
                
                # Store metadata for this packet
                iq_data[eaxc_id]['metadata'].append({
                    'direction': direction,
                    'seq_id': seq_id,
                    'frame_id': frame_id,
                    'subframe_id': subframe_id,
                    'slot_id': slot_id,
                    'symbol_id': symbol_id,
                    'num_samples': len(samples_vec),
                    'filter_index': filter_index
                })
    
    print(f"Processed {packet_count} IQ data packets\n")
    
    # Summary header (fill with your own stats later)
    print("=" * 100)
    print(f"{'eAxC ID':<10} {'Direction':<12} {'Samples':<15} {'Packets':<10} {'Max Value':<15} {'Estimated IQ Backoff'}")
    print("=" * 100)
    
    total_ul = 0
    total_dl = 0
    
    for eaxc_id in sorted(iq_data.keys()):
        ul_samples = len(iq_data[eaxc_id]['UL'])
        dl_samples = len(iq_data[eaxc_id]['DL'])
        ul_data = iq_data[eaxc_id]['UL']
        dl_data = iq_data[eaxc_id]['DL']
        max_ul = 0
        max_dl = 0
        if ul_samples > 0:
            max_ul_real = max(x.real for x in ul_data)
            max_ul_imag = max(x.imag for x in ul_data)
            max_ul = max(max_ul_real, max_ul_imag)
            #calculate dB of max IQ relative to FS
            scale_ratio_ul = max_ul / 32767
            ratio_ul_db = np.round(20 * np.log10(scale_ratio_ul), decimals=3)
        if dl_samples > 0:
            max_dl_real = max(x.real for x in dl_data)
            max_dl_imag = max(x.imag for x in dl_data)
            max_dl = max(max_dl_real, max_dl_imag)
            #calculate dB of max IQ relative to FS
            scale_ratio_dl = max_dl / 32767
            ratio_dl_db = np.round(20 * np.log10(scale_ratio_dl), decimals=3)
        
        
        if ul_samples > 0:
            ul_packets = sum(1 for m in iq_data[eaxc_id]['metadata'] if m['direction'] == 'UL')
            print(f"{eaxc_id:<10} {'UL':<12} {ul_samples:<15,} {ul_packets:<10} {max_ul:<15} {ratio_ul_db}")
            total_ul += ul_samples
            
        if dl_samples > 0:
            dl_packets = sum(1 for m in iq_data[eaxc_id]['metadata'] if m['direction'] == 'DL')
            print(f"{eaxc_id:<10} {'DL':<12} {dl_samples:<15,} {dl_packets:<10} {max_dl:<15} {ratio_dl_db}")
            total_dl += dl_samples
    
    print("=" * 100)
    print(f"{'TOTAL':<10} {'UL':<12} {total_ul:<15,}")
    print(f"{'TOTAL':<10} {'DL':<12} {total_dl:<15,}")
    print("=" * 100)
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
            phase = np.angle(samples, deg=True)
            axes[1, 0].plot(phase, color='green')
            axes[1, 0].set_xlabel('Sample Index')
            axes[1, 0].set_ylabel('Phase (degrees)')
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
    # if len(sys.argv) < 2:
    #     print("Usage: python PCAP_Analyzer.py <pcap_file> [output_base_name]")
    #     print("Example: python PCAP_Analyzer.py capture.pcap iq_data")
    #     print("\nExtracts IQ samples separated by eAxC ID and direction (UL/DL)")
    #     sys.exit(1)
    
    #pcap_file = sys.argv[1]
    output_base = output#sys.argv[2] if len(sys.argv) > 2 else "iq_separated"
    cfg = PCAP_CONFIGS.get(Path(pcap_file), DEFAULT_CONFIG)
    
    # Extract IQ samples with metadata
    print(default_pcap_file.absolute())
    iq_data = extract_iq_with_metadata(default_pcap_file.absolute(), cfg=cfg)
    
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

