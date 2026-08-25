"""
CLI for TPM 2.0 Measurement and Quote Simulator.

Commands:
- extend: Extend a PCR with event data
- read: Read PCR values
- quote: Generate a TPM quote
- verify: Verify a TPM quote
- log: Show the measurement event log
- boot: Simulate a boot measurement sequence
- reset: Reset all PCR values
"""
import argparse
import json
import sys

from simulator import TPMSimulator, EventType, PCRBank


def _get_sim(args):
    """Create or load a TPM simulator."""
    return TPMSimulator(num_pcrs=getattr(args, 'pcrs', 24))


def cmd_extend(args):
    """Extend a PCR with event data."""
    sim = _get_sim(args)
    event_data = args.data.encode() if isinstance(args.data, str) else args.data.encode()
    event_type = int(args.event_type, 0) if args.event_type else EventType.ACTION

    results = sim.extend_pcr(
        pcr_index=args.pcr,
        event_data=event_data,
        event_type=event_type,
        event_id=args.event_id or f"cli-event-{args.pcr}",
    )

    print(f"Extended PCR[{args.pcr}] with: {args.data}")
    for bank, val in results.items():
        print(f"  {bank}: {val.hex()}")
    return 0


def cmd_read(args):
    """Read PCR values."""
    sim = _get_sim(args)
    if args.pcr is not None:
        val = sim.read_pcr(args.pcr, args.bank)
        print(f"PCR[{args.pcr}] ({args.bank}): {val.hex()}")
    else:
        pcrs = sim.read_all_pcrs(args.bank)
        print(f"All PCRs ({args.bank}):")
        for idx, val in sorted(pcrs.items()):
            if args.nonzero_only and val == b'\x00' * len(val):
                continue
            print(f"  PCR[{idx:2d}]: {val.hex()}")
    return 0


def cmd_quote(args):
    """Generate a TPM quote."""
    sim = _get_sim(args)

    # Parse PCR indices
    indices = [int(x) for x in args.pcr_indices.split(',')]

    nonce = bytes.fromhex(args.nonce) if args.nonce else None
    quote = sim.generate_quote(pcr_indices=indices, nonce=nonce, bank=args.bank)

    print(f"TPM Quote Generated:")
    print(f"  Bank: {quote.pcr_bank}")
    print(f"  PCR indices: {quote.pcr_indices}")
    print(f"  Nonce: {quote.nonce.hex()}")
    print(f"  AK ID: {quote.attestation_key_id}")
    print(f"  Signature: {quote.signature.hex()[:32]}...")
    print(f"  PCR values:")
    for idx, val in sorted(quote.pcr_values.items()):
        print(f"    PCR[{idx}]: {val.hex()}")

    if args.output:
        with open(args.output, 'w') as f:
            json.dump(quote.to_dict(), f, indent=2)
        print(f"  Saved to: {args.output}")
    return 0


def cmd_verify(args):
    """Verify a TPM quote."""
    sim = _get_sim(args)

    if args.input:
        with open(args.input, 'r') as f:
            data = json.load(f)
        # Reconstruct Quote from JSON
        from simulator import Quote
        quote = Quote(
            pcr_bank=data['pcr_bank'],
            pcr_indices=data['pcr_indices'],
            pcr_values={int(k): bytes.fromhex(v) for k, v in data['pcr_values'].items()},
            nonce=bytes.fromhex(data['nonce']),
            signature=bytes.fromhex(data['signature']),
            timestamp=data['timestamp'],
            attestation_key_id=data['attestation_key_id'],
        )
    else:
        print("Error: --input required for verification")
        return 1

    nonce = bytes.fromhex(args.nonce) if args.nonce else quote.nonce
    valid, errors = sim.verify_quote(quote, nonce)

    print(f"Quote Verification:")
    print(f"  Valid: {valid}")
    if errors:
        for err in errors:
            print(f"  ERROR: {err}")
    else:
        print(f"  All checks passed")
    return 0 if valid else 1


def cmd_log(args):
    """Show the measurement event log."""
    sim = _get_sim(args)
    log = sim.event_log

    entries = log.get_entries(pcr_index=args.pcr)
    print(f"Measurement Event Log ({len(entries)} entries):")
    for entry in entries:
        etype_name = f"0x{entry.event_type:08X}"
        try:
            etype_name = EventType(entry.event_type).name
        except ValueError:
            pass
        print(f"  PCR[{entry.pcr_index}] {etype_name}: {entry.event_id}")
        print(f"    Digest: {entry.digest.hex()[:32]}...")
        print(f"    Data:   {entry.event_data.decode('utf-8', errors='replace')[:64]}")
    return 0


def cmd_boot(args):
    """Simulate a full boot measurement sequence."""
    sim = _get_sim(args)
    print("Simulating UEFI boot measurement sequence...")
    results = sim.simulate_boot_sequence()
    print(f"  Measured {len(results)} events across PCRs 0-8")
    print()

    # Show final PCR values
    for bank_name in ['sha256', 'sha1']:
        print(f"  PCR Bank: {bank_name}")
        pcrs = sim.read_all_pcrs(bank_name)
        for idx in [0, 1, 2, 4, 7, 8]:
            val = pcrs[idx]
            if val != b'\x00' * len(val):
                print(f"    PCR[{idx}]: {val.hex()[:32]}...")

    # Generate and verify a quote
    print()
    nonce = b'\xde\xad\xbe\xef' * 8
    quote = sim.generate_quote(pcr_indices=[0, 1, 2, 4, 7, 8], nonce=nonce)
    valid, errors = sim.verify_quote(quote, nonce)
    print(f"  Quote verification: {'PASS' if valid else 'FAIL'}")
    if errors:
        for e in errors:
            print(f"    {e}")
    return 0


def cmd_reset(args):
    """Reset all PCR values."""
    sim = _get_sim(args)
    sim.reset()
    print("All PCRs reset to initial values (all zeros)")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog='tpm2-simulator',
        description='TPM 2.0 Measurement and Quote Simulator'
    )
    parser.add_argument('--pcrs', type=int, default=24, help='Number of PCRs (default: 24)')
    sub = parser.add_subparsers(dest='command', required=True)

    # extend
    p = sub.add_parser('extend', help='Extend a PCR with event data')
    p.add_argument('--pcr', type=int, required=True, help='PCR index (0-23)')
    p.add_argument('--data', type=str, required=True, help='Event data string')
    p.add_argument('--event-type', type=str, default=None, help='Event type (hex or name)')
    p.add_argument('--event-id', type=str, default=None, help='Event identifier')
    p.set_defaults(func=cmd_extend)

    # read
    p = sub.add_parser('read', help='Read PCR values')
    p.add_argument('--pcr', type=int, default=None, help='PCR index (omit for all)')
    p.add_argument('--bank', choices=['sha1', 'sha256'], default='sha256')
    p.add_argument('--nonzero-only', action='store_true', help='Show only non-zero PCRs')
    p.set_defaults(func=cmd_read)

    # quote
    p = sub.add_parser('quote', help='Generate a TPM quote')
    p.add_argument('--pcr-indices', type=str, required=True, help='Comma-separated PCR indices')
    p.add_argument('--bank', choices=['sha1', 'sha256'], default='sha256')
    p.add_argument('--nonce', type=str, default=None, help='Nonce (hex)')
    p.add_argument('--output', type=str, default=None, help='Output JSON file')
    p.set_defaults(func=cmd_quote)

    # verify
    p = sub.add_parser('verify', help='Verify a TPM quote')
    p.add_argument('--input', type=str, required=True, help='Quote JSON file')
    p.add_argument('--nonce', type=str, default=None, help='Expected nonce (hex)')
    p.set_defaults(func=cmd_verify)

    # log
    p = sub.add_parser('log', help='Show measurement event log')
    p.add_argument('--pcr', type=int, default=None, help='Filter by PCR index')
    p.set_defaults(func=cmd_log)

    # boot
    p = sub.add_parser('boot', help='Simulate boot measurement sequence')
    p.set_defaults(func=cmd_boot)

    # reset
    p = sub.add_parser('reset', help='Reset all PCRs')
    p.set_defaults(func=cmd_reset)

    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == '__main__':
    sys.exit(main())
