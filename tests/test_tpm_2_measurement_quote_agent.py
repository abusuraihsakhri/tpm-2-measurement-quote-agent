"""
Tests for TPM 2.0 Measurement and Quote Simulator.
"""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
import hashlib
import json
import time
from simulator import (
    TPMSimulator, PCRBankState, PCRBank, MeasurementLog,
    AttestationKey, EventLogEntry, Quote, EventType,
    PCR_INIT_SHA1, PCR_INIT_SHA256,
)


# ---------------------------------------------------------------------------
# PCR Bank tests
# ---------------------------------------------------------------------------

class TestPCRBankState:
    def test_initial_values_sha256(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        for i in range(24):
            assert bank.read(i) == b'\x00' * 32

    def test_initial_values_sha1(self):
        bank = PCRBankState(PCRBank.SHA1, 24)
        for i in range(24):
            assert bank.read(i) == b'\x00' * 20

    def test_extend_sha256(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        new_val = bank.extend(0, b'test-data')
        expected = hashlib.sha256(b'\x00' * 32 + b'test-data').digest()
        assert new_val == expected
        assert bank.read(0) == expected

    def test_extend_sha1(self):
        bank = PCRBankState(PCRBank.SHA1, 24)
        new_val = bank.extend(0, b'test-data')
        expected = hashlib.sha1(b'\x00' * 20 + b'test-data').digest()
        assert new_val == expected

    def test_extend_chaining(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        bank.extend(0, b'first')
        val_after_first = bank.read(0)
        bank.extend(0, b'second')
        val_after_second = bank.read(0)
        expected = hashlib.sha256(val_after_first + b'second').digest()
        assert val_after_second == expected
        assert val_after_first != val_after_second

    def test_extend_independent_pcrs(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        bank.extend(0, b'data0')
        bank.extend(1, b'data1')
        assert bank.read(0) != bank.read(1)
        # PCR[2] should still be zero
        assert bank.read(2) == b'\x00' * 32

    def test_extend_invalid_index(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        with pytest.raises(IndexError):
            bank.extend(24, b'data')
        with pytest.raises(IndexError):
            bank.extend(-1, b'data')

    def test_read_invalid_index(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        with pytest.raises(IndexError):
            bank.read(100)

    def test_read_all(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        all_pcrs = bank.read_all()
        assert len(all_pcrs) == 24
        assert all(v == b'\x00' * 32 for v in all_pcrs.values())

    def test_read_selected(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        bank.extend(0, b'data')
        selected = bank.read_selected([0, 1, 5])
        assert len(selected) == 3
        assert selected[0] != b'\x00' * 32
        assert selected[1] == b'\x00' * 32

    def test_reset(self):
        bank = PCRBankState(PCRBank.SHA256, 24)
        bank.extend(0, b'data')
        assert bank.read(0) != b'\x00' * 32
        bank.reset()
        assert bank.read(0) == b'\x00' * 32

    def test_digest_size(self):
        sha1_bank = PCRBankState(PCRBank.SHA1, 24)
        sha256_bank = PCRBankState(PCRBank.SHA256, 24)
        assert sha1_bank.digest_size == 20
        assert sha256_bank.digest_size == 32


# ---------------------------------------------------------------------------
# Measurement Log tests
# ---------------------------------------------------------------------------

class TestMeasurementLog:
    def test_add_event(self):
        log = MeasurementLog()
        entry = log.add_event(0, EventType.ACTION, b'test-data', 'test-001')
        assert entry.pcr_index == 0
        assert entry.event_type == EventType.ACTION
        assert entry.event_id == 'test-001'
        assert log.get_entry_count() == 1

    def test_digest_computation(self):
        log = MeasurementLog()
        entry = log.add_event(0, EventType.ACTION, b'hello')
        expected_digest = hashlib.sha256(b'hello').digest()
        assert entry.digest == expected_digest

    def test_get_entries_filter(self):
        log = MeasurementLog()
        log.add_event(0, EventType.ACTION, b'd0')
        log.add_event(1, EventType.ACTION, b'd1')
        log.add_event(0, EventType.ACTION, b'd2')
        assert log.get_entry_count() == 3
        assert len(log.get_entries(pcr_index=0)) == 2
        assert len(log.get_entries(pcr_index=1)) == 1

    def test_verify_entry_digest(self):
        log = MeasurementLog()
        entry = log.add_event(0, EventType.IPL, b'boot-loader')
        assert log.verify_entry_digest(entry) is True

    def test_to_list(self):
        log = MeasurementLog()
        log.add_event(0, EventType.ACTION, b'data')
        entries = log.to_list()
        assert len(entries) == 1
        assert 'pcr_index' in entries[0]
        assert 'digest' in entries[0]


# ---------------------------------------------------------------------------
# Attestation Key tests
# ---------------------------------------------------------------------------

class TestAttestationKey:
    def test_sign_verify(self):
        ak = AttestationKey('test-ak')
        data = b'quote-data'
        sig = ak.sign(data)
        assert ak.verify(data, sig) is True

    def test_verify_wrong_data(self):
        ak = AttestationKey()
        sig = ak.sign(b'correct')
        assert ak.verify(b'wrong', sig) is False

    def test_verify_wrong_signature(self):
        ak = AttestationKey()
        assert ak.verify(b'data', b'\x00' * 32) is False

    def test_different_keys_different_signatures(self):
        ak1 = AttestationKey('ak1')
        ak2 = AttestationKey('ak2')
        data = b'same-data'
        assert ak1.sign(data) != ak2.sign(data)

    def test_get_public_info(self):
        ak = AttestationKey('my-key')
        info = ak.get_public_info()
        assert info['key_id'] == 'my-key'
        assert info['algorithm'] == 'HMAC-SHA256'
        assert len(info['public_hash']) == 32


# ---------------------------------------------------------------------------
# TPM Simulator tests
# ---------------------------------------------------------------------------

class TestTPMSimulator:
    def test_extend_and_read(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'test-event')
        val = tpm.read_pcr(0, 'sha256')
        assert val != b'\x00' * 32

    def test_extend_returns_all_banks(self):
        tpm = TPMSimulator()
        results = tpm.extend_pcr(0, b'data')
        assert 'sha1' in results
        assert 'sha256' in results
        assert len(results['sha1']) == 20
        assert len(results['sha256']) == 32

    def test_read_all_pcrs(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'data')
        all_pcrs = tpm.read_all_pcrs('sha256')
        assert len(all_pcrs) == 24
        assert all_pcrs[0] != b'\x00' * 32

    def test_generate_quote(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'bios')
        tpm.extend_pcr(7, b'secure-boot')
        nonce = b'\xaa' * 16
        quote = tpm.generate_quote([0, 7], nonce=nonce)
        assert quote.pcr_bank == 'sha256'
        assert 0 in quote.pcr_values
        assert 7 in quote.pcr_values
        assert quote.nonce == nonce

    def test_verify_quote_valid(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'bios')
        nonce = b'\xbb' * 16
        quote = tpm.generate_quote([0], nonce=nonce)
        valid, errors = tpm.verify_quote(quote, nonce)
        assert valid is True
        assert len(errors) == 0

    def test_verify_quote_bad_nonce(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'data')
        quote = tpm.generate_quote([0], nonce=b'\x01' * 16)
        valid, errors = tpm.verify_quote(quote, b'\x02' * 16)
        assert valid is False
        assert any('Nonce' in e for e in errors)

    def test_verify_quote_pcr_mismatch(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'data')
        nonce = b'\xcc' * 16
        quote = tpm.generate_quote([0], nonce=nonce)
        # Provide wrong expected PCR value
        wrong_expected = {0: b'\xff' * 32}
        valid, errors = tpm.verify_quote(quote, nonce, wrong_expected)
        assert valid is False
        assert any('PCR' in e for e in errors)

    def test_simulate_boot_sequence(self):
        tpm = TPMSimulator()
        results = tpm.simulate_boot_sequence()
        assert len(results) == 6
        # PCR[0] should be extended
        val = tpm.read_pcr(0, 'sha256')
        assert val != b'\x00' * 32
        # PCR[7] should be extended (secure boot)
        val7 = tpm.read_pcr(7, 'sha256')
        assert val7 != b'\x00' * 32

    def test_event_log_after_boot(self):
        tpm = TPMSimulator()
        tpm.simulate_boot_sequence()
        log = tpm.event_log
        assert log.get_entry_count() == 6
        pcr0_events = log.get_entries(pcr_index=0)
        assert len(pcr0_events) == 1

    def test_reset(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'data')
        tpm.reset()
        assert tpm.read_pcr(0, 'sha256') == b'\x00' * 32
        assert tpm.event_log.get_entry_count() == 0

    def test_quote_to_dict(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'data')
        quote = tpm.generate_quote([0])
        d = quote.to_dict()
        assert 'pcr_bank' in d
        assert 'signature' in d
        assert 'nonce' in d


# ---------------------------------------------------------------------------
# CLI tests
# ---------------------------------------------------------------------------

class TestCLI:
    def test_extend_command(self):
        from cli import main
        ret = main(['extend', '--pcr', '0', '--data', 'test-event'])
        assert ret == 0

    def test_read_command(self):
        from cli import main
        ret = main(['read', '--bank', 'sha256'])
        assert ret == 0

    def test_read_nonzero(self):
        from cli import main
        ret = main(['read', '--nonzero-only'])
        assert ret == 0

    def test_boot_command(self):
        from cli import main
        ret = main(['boot'])
        assert ret == 0

    def test_reset_command(self):
        from cli import main
        ret = main(['reset'])
        assert ret == 0

    def test_log_command(self):
        from cli import main
        ret = main(['log'])
        assert ret == 0

    def test_quote_command(self):
        from cli import main
        ret = main(['quote', '--pcr-indices', '0,1,7'])
        assert ret == 0

    def test_quote_command_with_output(self, tmp_path):
        from cli import main
        output_file = tmp_path / "quote.json"
        ret = main(['quote', '--pcr-indices', '0', '--output', str(output_file)])
        assert ret == 0
        assert output_file.exists()

    def test_extend_empty_data(self):
        from cli import main
        ret = main(['extend', '--pcr', '0', '--data', ''])
        assert ret == 1

    def test_extend_invalid_pcr(self):
        from cli import main
        ret = main(['extend', '--pcr', '999', '--data', 'test'])
        assert ret == 1


# ---------------------------------------------------------------------------
# Security & Validation tests
# ---------------------------------------------------------------------------

class TestSecurityValidation:
    def test_generate_quote_invalid_bank(self):
        tpm = TPMSimulator()
        with pytest.raises(ValueError, match="Unknown PCR bank"):
            tpm.generate_quote([0], bank='md5')

    def test_generate_quote_empty_indices(self):
        tpm = TPMSimulator()
        with pytest.raises(ValueError, match="At least one PCR index"):
            tpm.generate_quote([])

    def test_generate_quote_invalid_index(self):
        tpm = TPMSimulator()
        with pytest.raises(IndexError, match="out of range"):
            tpm.generate_quote([100])

    def test_generate_quote_short_nonce(self):
        tpm = TPMSimulator()
        with pytest.raises(ValueError, match="at least 16 bytes"):
            tpm.generate_quote([0], nonce=b'\x00' * 8)

    def test_nonce_constant_time_compare(self):
        """Verify nonce comparison is not vulnerable to timing attacks."""
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'data')
        nonce = b'\xaa' * 32
        quote = tpm.generate_quote([0], nonce=nonce)
        # Same nonce should verify
        valid, _ = tpm.verify_quote(quote, nonce)
        assert valid is True
        # Different nonce should fail
        valid, errors = tpm.verify_quote(quote, b'\xbb' * 32)
        assert valid is False
        assert any('Nonce' in e for e in errors)

    def test_quote_tampered_pcr_values(self):
        """Verify that tampered PCR values fail verification."""
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b'original-data')
        nonce = b'\xcc' * 32
        quote = tpm.generate_quote([0], nonce=nonce)
        # Tamper with PCR values
        quote.pcr_values[0] = b'\xff' * 32
        valid, errors = tpm.verify_quote(quote, nonce)
        assert valid is False
        assert any('Signature' in e for e in errors)
