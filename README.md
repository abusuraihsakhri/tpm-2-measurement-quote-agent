# TPM 2.0 Measurement & Quote Simulator

Educational tools for PCR measurements, event logs, and HMAC-based quote demonstrations. **Not a hardware TPM attestation verifier.** Simulated quotes are not the TCG TPM2_Quote binary structure and do not establish device identity or a chain of trust.

## Browser demo

The standalone [web/index.html](web/index.html) implements software SHA-1/SHA-256 PCR extension, sample UEFI measurements, in-session quote signing/checking with Web Crypto, nonce comparison, and JSON download/import. No backend, tracking scripts or data uploads are used.

```bash
python -m http.server 8000 --directory web
# Visit http://localhost:8000
```

The key is session-local and lost on refresh; a previously exported quote cannot be verified after reload. The Pages deployment workflow publishes the `web/` directory when the repository's Pages configuration permits it. This browser app uses JavaScript/Web Crypto rather than Pyodide.

## Python setup

```bash
git clone https://github.com/abusuraihsakhri/tpm-2-measurement-quote-agent.git
cd tpm-2-measurement-quote-agent
python -m pip install -e ".[server,test]"
python -m pytest -q
```

The standard-library simulator also works with `pip install -e .` alone. Python 3.9+ is supported by the package metadata; CI tests 3.10–3.12.

## Simulator CLI

```bash
python cli.py boot
python cli.py extend --pcr 0 --data firmware-v1
python cli.py read --bank sha256
python cli.py log
python cli.py quote --pcr-indices 0,1,7 --nonce 00112233445566778899aabbccddeeff --key-file local-demo.key --output quote.json
python cli.py verify --input quote.json --nonce 00112233445566778899aabbccddeeff --key-file local-demo.key
```

A new in-memory TPM is created for each command. The `extend` command therefore does not persist state into later `read`, `log` or `quote` invocations. Import `TPMSimulator` from `simulator.py` to perform a multi-step measurement workflow in one Python process.

The simulator uses `Hash(previous_PCR || Hash(event_data))` for PCR extension. The quote CLI uses a locally protected 32-byte HMAC secret; treat the `--key-file` as sensitive and never commit it. The verifier must independently supply a fresh challenge nonce. The timestamp is informational, not a signed freshness guarantee.

## Rule-based API

The separate `agents/` and `tpm2_attestation/` packages implement simple numeric threshold and descriptor rules; they **do not parse and validate actual hardware TPM quotes**, PCR event logs or AK certificate chains. Chat responses are mocked.

```bash
python -m uvicorn agents.api:app --host 127.0.0.1 --port 8000
# or: docker compose up --build
```

The API exposes `/health`, `/metrics`, `/api/audit`, `/api/chat` and `/api/audit/logs`. The alternative `tpm2_attestation` CLI supports `audit`, `chat`, `batch` and `serve`.

The API has no authentication or persistent storage. Keep it on trusted local networks. The audit trail is held in memory and uses a process-generated secret unless `AUDIT_SECRET_KEY` is provided. Its pattern-based identifier check does not guarantee de-identification or regulatory compliance.

## Verification and privacy

```bash
python -m pip check
python -m pytest -q
python -m compileall -q .
```

For production remote attestation, use a TPM-aware verifier supporting the TCG attestation structure, AK public-key trust, event-log PCR replay and verifier-issued nonce checking.

## License

MIT — see [LICENSE](LICENSE).
