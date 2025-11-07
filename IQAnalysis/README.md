# 5G NR Fronthaul IQ Extractor

Python tool for extracting IQ samples from 5G NR Fronthaul pcap files using the eCPRI protocol.

## Features

- Extracts IQ samples from eCPRI packets (VLAN-tagged or direct Ethernet)
- Separates data by eAxC ID (antenna/carrier identifier)
- Separates data by direction (Uplink/Downlink)
- Supports 16-bit I/Q sample format
- Exports to NumPy (.npy) format
- Generates statistics per stream
- Creates visualizations (I/Q time domain, magnitude, phase, constellation)
- Extracts detailed metadata (frame, subframe, slot, symbol IDs)

## Installation

```bash
pip install -r requirements.txt
```

Requirements: `scapy`, `numpy`, `matplotlib`

## Usage

### Basic Command

```bash
python PCAP_Analyzer.py <pcap_file> [output_name]
```

### Examples

```bash
# Analyze a capture file
python PCAP_Analyzer.py capture.pcap

# Specify custom output name
python PCAP_Analyzer.py capture.pcap my_data
```

## Output Files

The script creates separate files for each eAxC ID and direction:

```
output_name_eAxC0_DL.npy              # Downlink IQ samples for eAxC 0
output_name_eAxC0_UL.npy              # Uplink IQ samples for eAxC 0 (if present)
output_name_eAxC0_DL_stats.txt        # Statistics
output_name_eAxC0_DL.png              # Visualization
output_name_eAxC0_metadata.json       # Packet metadata
output_name_UL_vs_DL.png              # UL/DL comparison (if both present)
```

## Example Output

Running on a typical 2x2 MIMO capture:

```
======================================================================
eAxC ID    Direction    Samples         Packets   
======================================================================
0          DL           529,152         416       
1          DL           529,152         416       
======================================================================
TOTAL      UL           0              
TOTAL      DL           1,058,304      
======================================================================
```

This shows:
- 2 antenna carriers (eAxC IDs 0 and 1)
- Downlink only traffic
- 529,152 IQ samples per antenna

## Using the Extracted Data

### Load IQ Samples

```python
import numpy as np

# Load specific eAxC ID and direction
iq_data = np.load('output_name_eAxC0_DL.npy')

# Access I and Q components
I = iq_data.real
Q = iq_data.imag

# Calculate metrics
magnitude = np.abs(iq_data)
phase = np.angle(iq_data)
power = np.mean(magnitude ** 2)
```

### Compare Multiple Antennas

```python
import numpy as np

# Load data from different antennas
ant0 = np.load('output_name_eAxC0_DL.npy')
ant1 = np.load('output_name_eAxC1_DL.npy')

# Compare power
power0 = np.mean(np.abs(ant0)**2)
power1 = np.mean(np.abs(ant1)**2)
print(f"Antenna 0 power: {power0:.0f}")
print(f"Antenna 1 power: {power1:.0f}")
print(f"Power ratio: {power0/power1:.2f}")
```

### Access Metadata

```python
import json

# Load metadata
with open('output_name_eAxC0_metadata.json', 'r') as f:
    metadata = json.load(f)

# Example: Find packets for symbol 5
symbol_5_packets = [p for p in metadata if p['symbol_id'] == 5]
print(f"Symbol 5: {len(symbol_5_packets)} packets")

# Analyze timing
for packet in metadata[:5]:
    print(f"Frame {packet['frame_id']}, "
          f"Slot {packet['slot_id']}, "
          f"Symbol {packet['symbol_id']}: "
          f"{packet['num_samples']} samples")
```

## Understanding the Data

### eAxC ID
Equipment Axial Connection ID identifies the logical fronthaul connection:
- Different antenna elements
- Different sectors
- Different carriers/bandwidth parts

### Direction
- **UL (Uplink):** User equipment → Base station
- **DL (Downlink):** Base station → User equipment

### Metadata Fields
- `seq_id` - eCPRI sequence number
- `frame_id` - 5G NR frame number (0-1023)
- `subframe_id` - Subframe within frame (0-9)
- `slot_id` - Slot within subframe
- `symbol_id` - OFDM symbol within slot (0-13 for normal CP)
- `num_samples` - IQ samples in this packet

## Protocol Details

### Packet Structure
```
[Ethernet] → [802.1Q VLAN] → [eCPRI Header] → [IQ Data]
             EtherType: 0xAEFE

eCPRI Header (4 bytes):
  Byte 1: Message Type (0x00 = IQ Data)

eCPRI Message:
  Bytes 4-5: eAxC ID
  Bytes 6-7: Sequence ID
  Bytes 8-15: Radio Application Header
    Byte 8 bit 7: Direction (0=UL, 1=DL)
    Bytes 9-11: Frame/slot/symbol timing
  Bytes 16+: IQ samples (16-bit signed, big-endian)
```

### Supported Formats
- eCPRI IQ Data (Message Type 0x00)
- 16-bit signed I/Q samples
- VLAN-tagged Ethernet (802.1Q)
- Direct eCPRI over Ethernet (EtherType 0xAEFE)
- eCPRI over UDP (ports 0xAEC0+)

## Advanced Examples

### FFT Analysis

```python
import numpy as np
import matplotlib.pyplot as plt

iq = np.load('output_name_eAxC0_DL.npy')

# Take FFT of 1024 samples
fft_result = np.fft.fftshift(np.fft.fft(iq[5000:6024]))
freq = np.fft.fftshift(np.fft.fftfreq(1024))

plt.plot(freq, 20*np.log10(np.abs(fft_result)))
plt.xlabel('Normalized Frequency')
plt.ylabel('Magnitude (dB)')
plt.title('Spectrum')
plt.savefig('spectrum.png')
```

### Power Over Time

```python
import numpy as np
import matplotlib.pyplot as plt

iq = np.load('output_name_eAxC0_DL.npy')

# Calculate power in blocks
block_size = 1000
num_blocks = len(iq) // block_size
power_blocks = []

for i in range(num_blocks):
    block = iq[i*block_size:(i+1)*block_size]
    power = np.mean(np.abs(block)**2)
    power_blocks.append(power)

plt.plot(power_blocks)
plt.xlabel('Block Number')
plt.ylabel('Average Power')
plt.savefig('power_vs_time.png')
```

### Per-Symbol Analysis

```python
import json
import numpy as np

# Load data and metadata
iq = np.load('output_name_eAxC0_DL.npy')
with open('output_name_eAxC0_metadata.json') as f:
    metadata = json.load(f)

# Analyze each symbol
offset = 0
for sym in range(14):
    sym_packets = [p for p in metadata if p['symbol_id'] == sym]
    sym_samples = sum(p['num_samples'] for p in sym_packets)
    print(f"Symbol {sym}: {len(sym_packets)} packets, {sym_samples} samples")
```

## Troubleshooting

**No IQ data found:**
- Verify eCPRI packets exist with: `tshark -r file.pcap -Y "vlan.etype == 0xaefe"`
- Check that message type is 0x00 (IQ data)

**Missing eAxC IDs:**
- Some captures contain only DL or only UL
- Check your RU/DU configuration

**Different sample format:**
- Default parser assumes 16-bit big-endian signed integers
- For other formats, modify the `struct.unpack()` calls in the script

**Large files:**
- Plots automatically limit to 2000-5000 samples
- Use NumPy memory mapping for very large files: `np.load('file.npy', mmap_mode='r')`

## Technical References

- eCPRI Specification v2.0: [www.cpri.info](http://www.cpri.info/spec.html)
- O-RAN Fronthaul WG4 specification
- 3GPP TS 38.211: Physical channels and modulation
- IEEE 802.1Q: VLAN tagging
