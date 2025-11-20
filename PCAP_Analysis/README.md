# 5G NR Fronthaul IQ Analyzer

Python tool for extracting and analyzing IQ samples from 5G NR Fronthaul PCAP files.

## Features

- Extract IQ samples from ORAN Fronthaul PCAP captures
- Separate data by eAxC ID and direction (UL/DL)
- Support for BFP compression and uncompressed formats (STATIC COMPRESSION ONLY)
- Generate resource allocation plots
- Export to NumPy format with metadata
- Interactive GUI and command-line interface

## Requirements

- Python 3.7+
- Wireshark 4.6.0 or later (must be installed separately)

Install Python dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### GUI (Recommended)

```bash
python IQ_Analyzer_GUI.py
```

Drag and drop your PCAP file, configure compression settings, and click "Run Analysis".

### Command Line

```bash
python PCAP_Analyzer_WS.py <pcap_file> [options]
```

**Options:**
- `--bfp` - Force BFP decompression
- `--bitwidth N` - Bitwidth (8-14 for BFP, 16 for uncompressed)
- `--start-symbol N` - Start symbol for analysis
- `--end-symbol N` - End symbol for analysis
- `--symbols N` - Number of symbols to plot
- `--output NAME` - Output file base name
- `--show-plots` - Display plots interactively

**Examples:**
```bash
# Basic analysis
python PCAP_Analyzer_WS.py capture.pcap

# BFP 9-bit compression
python PCAP_Analyzer_WS.py capture.pcap --bfp --bitwidth 9

# Analyze specific symbol range
python PCAP_Analyzer_WS.py capture.pcap --start-symbol 20 --end-symbol 50

# Show plots interactively
python PCAP_Analyzer_WS.py capture.pcap --show-plots
```

## Output Files

```
output_name_eAxC0_DL.npy              # IQ samples (NumPy array)
output_name_eAxC0_DL_stats.txt        # Statistics
output_name_eAxC0_metadata.json       # Packet metadata
output_name_eAxC0_DL_magnitude.png    # Magnitude plot
output_name_eAxC0_DL_constellation.png # Constellation diagram
output_name_eAxC0_resource_allocation.png # Resource allocation
```

## Using Extracted Data

```python
import numpy as np

# Load IQ samples
iq_data = np.load('output_name_eAxC0_DL.npy')

# Access I and Q components
I = iq_data.real
Q = iq_data.imag

# Calculate metrics
magnitude = np.abs(iq_data)
phase = np.angle(iq_data)
power_dbfs = 20 * np.log10(np.max(magnitude) / 32767.0)
```

## Compression Settings

The tool supports both compressed (BFP) and uncompressed IQ data:

- **Uncompressed**: 16-bit signed integers (default)
- **BFP (Block Floating Point)**: 8-14 bit compression

Configure compression in the GUI or use `--bfp` and `--bitwidth` command-line options.

## Troubleshooting

**No IQ data found:**
- Verify compression settings match your PCAP file
- Check PCAP contains ORAN FH CUS packets

**Low IQ Backoff Warning:**
- Indicates signal is close to saturation
- May impact BLER (Block Error Rate)
- Consider adjusting transmit power

**Large files:**
- Use symbol range filtering: `--start-symbol` and `--end-symbol`
- Use memory mapping: `np.load('file.npy', mmap_mode='r')`

## References

- O-RAN Fronthaul Working Group 4 Specification
- eCPRI Specification v2.0
- 3GPP TS 38.211: Physical channels and modulation
