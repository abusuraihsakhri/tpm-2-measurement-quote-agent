# TPM 2 Measurement Quote Agent

> **Domain:** Hardware Security & Trusted Platform Module Simulation
> **Standard:** TCG TPM 2.0 Library Specification

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.9%2B-3776AB.svg?logo=python&logoColor=white)

</div>

---

## Overview

A Python-based TPM 2.0 measurement and quote simulation framework. This project provides:

- **PCR (Platform Configuration Register) Simulation**: SHA-1 and SHA-256 PCR banks with extend operations
- **Measurement Event Log**: Tamper-evident logging of all PCR extensions
- **Quote Generation & Verification**: HMAC-signed PCR quotes with anti-replay nonces
- **Boot Sequence Simulation**: Realistic UEFI boot measurement workflow
- **Multi-Agent Audit System**: Coordinated security assessment with specialized sub-agents
- **Enrichment Suite**: Domain-specific verification engines for TPM 2.0 operations

---

## Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/tpm-2-measurement-quote-agent.git
cd tpm-2-measurement-quote-agent

# Install dependencies (Python 3.9+ required)
pip install -e .

# Optional: Install FastAPI/uvicorn for REST API server
pip install fastapi uvicorn
```

---

## Usage

### TPM Simulator CLI

```bash
# Simulate a UEFI boot sequence
python cli.py boot

# Extend a PCR with event data
python cli.py extend --pcr 0 --data "firmware-v1.0"

# Read PCR values
python cli.py read --pcr 0 --bank sha256

# Generate a TPM quote
python cli.py quote --pcr-indices "0,1,7" --nonce "aabbccdd" --output quote.json

# Verify a quote
python cli.py verify --input quote.json --nonce "aabbccdd"

# View measurement event log
python cli.py log

# Reset all PCRs
python cli.py reset
```

### Audit Supervisor CLI

```bash
# Run a single task audit
python -m tpm2_attestation.cli audit --task-id TASK-001 --primary 28.4 --secondary 14.2 --critical --status DISCORDANT

# Query the supervisory system
python -m tpm2_attestation.cli chat "What standard is applied?"

# Batch process from CSV
python -m tpm2_attestation.cli batch -i sample.csv -o results.csv

# Launch REST API server
python -m tpm2_attestation.cli serve --host 127.0.0.1 --port 8000
```

### REST API Endpoints

| Endpoint | Method | Description |
|:---------|:-------|:------------|
| `/health` | GET | System health check |
| `/api/audit` | POST | Submit task for audit evaluation |
| `/api/chat` | POST | Query supervisory system |

---

## Architecture

```
tpm-2-measurement-quote-agent/
├── simulator.py              # Core TPM 2.0 simulation engine
├── cli.py                    # TPM simulator CLI
├── enrichment.py             # Domain-specific verification engines
├── tpm2_attestation/         # Audit supervisor package
│   ├── models.py             # Data models (FrontierPayload, Alerts)
│   ├── engine.py             # Core evaluation engine
│   ├── agents.py             # Specialized audit sub-agents
│   ├── cli.py                # Audit supervisor CLI
│   └── server.py             # FastAPI REST server
├── tests/                    # Test suite
│   ├── test_tpm_2_measurement_quote_agent.py
│   ├── test_tpm2_attestation.py
│   └── test_enrichment.py
└── sample.csv                # Sample batch input data
```

---

## Security Features

- **Constant-time nonce comparison** to prevent timing attacks on quote verification
- **Input validation** on PCR indices, bank names, and nonce lengths
- **HMAC-SHA256 signing** for attestation key operations
- **Anti-replay protection** via cryptographically random nonces

---

## Testing

```bash
# Run full test suite
pytest -v

# Run specific test modules
pytest tests/test_tpm_2_measurement_quote_agent.py -v
pytest tests/test_tpm2_attestation.py -v
pytest tests/test_enrichment.py -v
```

---

## License

MIT License - see [LICENSE](LICENSE) for details.
