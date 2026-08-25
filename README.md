# TPM 2.0 Measurement and Quote Simulator

A Python simulator for TPM 2.0 measurement and attestation operations. Implements PCR (Platform Configuration Register) management, event logging, quote generation with signature verification, and boot sequence simulation.

## What This Actually Does

This is a **simulation** of TPM 2.0 concepts using Python's `hashlib` and `hmac` modules. It does **not** interface with real TPM hardware. PCR extend operations use real SHA-256/SHA-1 hashing. Quote signatures use HMAC-SHA256 (a real TPM would use RSA/ECC keys in a protected hierarchy).

## Features

### PCR Management
- **PCR Banks**: SHA-1 (20-byte) and SHA-256 (32-byte) banks
- **PCR Extend**: `PCR[i] = Hash(PCR[i] || event_data)` — the actual TPM algorithm
- **24 PCR registers** per bank (indices 0-23)
- **Reset**: Restore all PCRs to initial all-zeros state

### Measurement Log
- TCG-standard event log format
- Event types matching TCG/EV_* constants (PRE_BOOT_CERT, EFI_BOOT_SERVICES_APPLICATION, etc.)
- Each entry records: PCR index, event type, digest, event data
- Digest verification against event data

### Quote Generation & Verification
- **Quote**: Signed statement of selected PCR values with anti-replay nonce
- **Signature**: HMAC-SHA256 over canonical quote data
- **Verification**: Checks signature, nonce, and PCR values against expected

### Boot Sequence Simulation
- Simulates UEFI Secure Boot measurement chain
- Measures SRTM, platform config, option ROMs, boot loader, secure boot policy, kernel

## Quick Start

```bash
# Simulate a boot sequence
python cli.py boot

# Extend a PCR manually
python cli.py extend --pcr 0 --data "my-measurement" --event-id "test-001"

# Read PCR values
python cli.py read --bank sha256 --nonzero-only

# Generate a quote
python cli.py quote --pcr-indices "0,1,2,4,7,8" --output quote.json

# Verify a quote
python cli.py verify --input quote.json

# Show event log
python cli.py log

# Reset all PCRs
python cli.py reset
```

## Python API

```python
from simulator import TPMSimulator, EventType

# Create simulator
tpm = TPMSimulator()

# Extend PCRs
tpm.extend_pcr(0, b'BIOS-v2.0', EventType.S_CRTM_CONTENTS, 'SRTM')
tpm.extend_pcr(7, b'secure-boot-enabled', EventType.EFI_VARIABLE_DRIVER_CONFIG, 'SB-Policy')

# Read PCR
value = tpm.read_pcr(0, bank='sha256')

# Generate quote
nonce = b'\xde\xad\xbe\xef' * 8
quote = tpm.generate_quote(pcr_indices=[0, 7], nonce=nonce)

# Verify
valid, errors = tpm.verify_quote(quote, nonce)
```

## PCR Index Assignments (TCG Standard)

| Index | Purpose |
|-------|---------|
| 0 | SRTM, BIOS, Platform Extensions |
| 1 | Platform Configuration |
| 2 | Option ROM Code |
| 3 | Option ROM Configuration |
| 4 | IPL Code (MBR) |
| 5 | IPL Partition Data |
| 6 | Boot Debug |
| 7 | Secure Boot Policy |
| 8 | Boot Loader |
| 9 | Boot Authority |
| 10-23 | OS/Application use |

## Requirements

Python 3.10+ stdlib only (no external dependencies).

## License

MIT
