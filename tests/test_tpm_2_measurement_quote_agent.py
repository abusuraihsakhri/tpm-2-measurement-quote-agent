"""Regression tests for the in-memory PCR simulator, CLI and audit demonstration."""
import csv
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from simulator import (
    TPMSimulator, PCRBankState, PCRBank, MeasurementLog, AttestationKey,
    EventType, PCR_INIT_SHA1, PCR_INIT_SHA256,
)


class TestPCRBankState:
    @pytest.mark.parametrize("algorithm,size", [(PCRBank.SHA1, 20), (PCRBank.SHA256, 32)])
    def test_initial_values(self, algorithm, size):
        bank = PCRBankState(algorithm, 24)
        assert all(bank.read(i) == bytes(size) for i in range(24))
        assert bank.digest_size == size

    @pytest.mark.parametrize("algorithm,hash_fn", [(PCRBank.SHA1, hashlib.sha1), (PCRBank.SHA256, hashlib.sha256)])
    def test_extend_uses_measurement_digest(self, algorithm, hash_fn):
        bank = PCRBankState(algorithm, 24)
        measured = hash_fn(b"test-data").digest()
        expected = hash_fn(bytes(hash_fn().digest_size) + measured).digest()
        assert bank.extend(0, b"test-data") == expected
        assert bank.read(0) == expected

    def test_extend_chaining(self):
        bank = PCRBankState(PCRBank.SHA256)
        first = bank.extend(0, b"first")
        second = bank.extend(0, b"second")
        assert second == hashlib.sha256(first + hashlib.sha256(b"second").digest()).digest()
        assert first != second

    def test_independent_pcrs(self):
        bank = PCRBankState(PCRBank.SHA256)
        bank.extend(0, b"data0")
        bank.extend(1, b"data1")
        assert bank.read(0) != bank.read(1)
        assert bank.read(2) == bytes(32)

    def test_invalid_indices(self):
        bank = PCRBankState(PCRBank.SHA256)
        for index in [-1, 24, 100]:
            with pytest.raises(IndexError):
                bank.extend(index, b"test")
            with pytest.raises(IndexError):
                bank.read(index)

    def test_read_selected(self):
        bank = PCRBankState(PCRBank.SHA256)
        bank.extend(0, b"data")
        assert set(bank.read_selected([0, 1, 5])) == {0, 1, 5}
        assert bank.read_selected([0])[0] != bytes(32)

    def test_read_all_is_a_copy(self):
        bank = PCRBankState(PCRBank.SHA256)
        data = bank.read_all()
        assert len(data) == 24
        data[0] = b"altered"
        assert bank.read(0) == bytes(32)

    def test_reset(self):
        bank = PCRBankState(PCRBank.SHA256)
        bank.extend(0, b"data")
        bank.reset()
        assert bank.read(0) == bytes(32)


class TestMeasurementLog:
    def test_add_filter_and_digests(self):
        log = MeasurementLog()
        entry = log.add_event(0, EventType.ACTION, b"test-data", "test-001")
        assert entry.event_type == EventType.ACTION
        assert entry.event_id == "test-001"
        assert entry.digest == hashlib.sha256(b"test-data").digest()
        assert log.verify_entry_digest(entry)
        log.add_event(1, EventType.IPL, b"boot-loader")
        assert log.get_entry_count() == 2
        assert len(log.get_entries(pcr_index=0)) == 1
        assert len(log.get_entries(pcr_index=1)) == 1

    def test_export(self):
        log = MeasurementLog()
        log.add_event(0, EventType.ACTION, b"data")
        entry = log.to_list()[0]
        assert entry["pcr_index"] == 0
        assert entry["digest"] == hashlib.sha256(b"data").hexdigest()


class TestAttestationKey:
    def test_sign_and_verify(self):
        key = AttestationKey("test")
        sig = key.sign(b"quote")
        assert key.verify(b"quote", sig)
        assert not key.verify(b"other", sig)
        assert not key.verify(b"quote", bytes(32))

    def test_distinct_keys(self):
        assert AttestationKey("one").sign(b"same") != AttestationKey("two").sign(b"same")

    def test_public_info(self):
        info = AttestationKey("name").get_public_info()
        assert info["key_id"] == "name"
        assert info["algorithm"] == "HMAC-SHA256"
        assert len(info["public_hash"]) == 32


class TestTPMSimulator:
    def test_extend_all_banks(self):
        tpm = TPMSimulator()
        results = tpm.extend_pcr(0, b"data")
        assert set(results) == {"sha1", "sha256"}
        assert len(results["sha1"]) == 20
        assert len(results["sha256"]) == 32
        assert tpm.read_pcr(0) == results["sha256"]
        assert tpm.read_all_pcrs()["0"] if False else len(tpm.read_all_pcrs()) == 24

    def test_boot_sequence_and_reset(self):
        tpm = TPMSimulator()
        assert len(tpm.simulate_boot_sequence()) == 6
        assert tpm.event_log.get_entry_count() == 6
        assert tpm.read_pcr(7) != bytes(32)
        tpm.reset()
        assert tpm.read_pcr(7) == bytes(32)
        assert tpm.event_log.get_entry_count() == 0

    def test_invalid_extend_is_atomic(self):
        tpm = TPMSimulator()
        with pytest.raises(IndexError):
            tpm.extend_pcr(99, b"invalid")
        assert tpm.event_log.get_entry_count() == 0
        with pytest.raises(TypeError):
            tpm.extend_pcr(0, "not bytes")
        assert tpm.event_log.get_entry_count() == 0

    def test_quote_roundtrip(self):
        tpm = TPMSimulator()
        tpm.extend_pcr(0, b"bios")
        nonce = bytes.fromhex("ab" * 16)
        quote = tpm.generate_quote([0, 7], nonce=nonce)
        assert quote.pcr_bank == "sha256"
        assert quote.nonce == nonce
        assert "signature" in quote.to_dict()
        assert tpm.verify_quote(quote, nonce) == (True, [])

    def test_bad_nonce(self):
        tpm = TPMSimulator()
        quote = tpm.generate_quote([0], nonce=b"a" * 16)
        valid, errors = tpm.verify_quote(quote, b"b" * 16)
        assert not valid and "Nonce" in errors[0]

    def test_pcr_expectation(self):
        tpm = TPMSimulator()
        quote = tpm.generate_quote([0], nonce=b"a" * 16)
        valid, errors = tpm.verify_quote(quote, b"a" * 16, {0: bytes([255]) * 32})
        assert not valid and any("PCR" in e for e in errors)

    def test_tampered_value_fails_signature(self):
        tpm = TPMSimulator()
        quote = tpm.generate_quote([0], nonce=b"a" * 16)
        quote.pcr_values[0] = bytes([255]) * 32
        valid, errors = tpm.verify_quote(quote, b"a" * 16)
        assert not valid and any("Signature" in e for e in errors)

    def test_reject_malformed_quote(self):
        tpm = TPMSimulator()
        with pytest.raises(ValueError, match="Unknown PCR bank"):
            tpm.generate_quote([0], bank="md5")
        with pytest.raises(ValueError, match="At least one PCR"):
            tpm.generate_quote([])
        with pytest.raises(ValueError, match="Duplicate"):
            tpm.generate_quote([0, 0])
        with pytest.raises(IndexError):
            tpm.generate_quote([24])
        with pytest.raises(ValueError, match="at least 16"):
            tpm.generate_quote([0], nonce=b"a" * 8)
        quote = tpm.generate_quote([0, 1], nonce=b"a" * 16)
        quote.pcr_values.pop(1)
        assert not tpm.verify_quote(quote, b"a" * 16)[0]
        quote = tpm.generate_quote([0], nonce=b"a" * 16)
        quote.attestation_key_id = "OTHER"
        assert not tpm.verify_quote(quote, b"a" * 16)[0]


class TestCLI:
    def test_basic_commands(self):
        from cli import main
        assert main(["extend", "--pcr", "0", "--data", "test-event"]) == 0
        assert main(["read", "--bank", "sha256"]) == 0
        assert main(["read", "--nonzero-only"]) == 0
        assert main(["boot"]) == 0
        assert main(["log"]) == 0
        assert main(["reset"]) == 0
        assert main(["quote", "--pcr-indices", "0,1,7"]) == 0

    def test_invalid_inputs(self):
        from cli import main
        assert main(["extend", "--pcr", "0", "--data", ""]) == 1
        assert main(["extend", "--pcr", "999", "--data", "test"]) == 1
        assert main(["quote", "--pcr-indices", "0,0"]) == 1

    def test_cross_process_quote_verification(self, tmp_path):
        from cli import main
        nonce = "aa" * 16
        key_path = tmp_path / "local.key"
        quote_path = tmp_path / "quote.json"
        assert main(["quote", "--pcr-indices", "0,7", "--nonce", nonce,
                     "--key-file", str(key_path), "--output", str(quote_path)]) == 0
        assert len(key_path.read_bytes()) == 32
        if os.name == "posix":
            assert key_path.stat().st_mode & 0o077 == 0
        assert main(["verify", "--input", str(quote_path), "--nonce", nonce,
                     "--key-file", str(key_path)]) == 0
        assert main(["verify", "--input", str(quote_path), "--nonce", "bb" * 16,
                     "--key-file", str(key_path)]) == 1
        quote = json.loads(quote_path.read_text())
        quote["pcr_values"]["0"] = "ff" * 32
        quote_path.write_text(json.dumps(quote))
        assert main(["verify", "--input", str(quote_path), "--nonce", nonce,
                     "--key-file", str(key_path)]) == 1


def test_audit_trail_rejects_modified_entries():
    from agents.base import AuditTrail
    audit = AuditTrail(secret_key="unit-test-secret")
    audit.log("user", "operator", "CHECK", {"status": "SUCCESS"})
    assert audit.verify_integrity()
    exported = audit.get_trail()
    exported[0]["event_type"] = "ALTERED"
    assert audit.verify_integrity()
    audit.logs[0]["event_type"] = "ALTERED"
    assert not audit.verify_integrity()


def test_batch_false_boolean(tmp_path):
    from tpm2_attestation.cli import main
    source = tmp_path / "in.csv"
    output = tmp_path / "out.csv"
    source.write_text(
        "task_id,target_identifier,primary_metric,secondary_metric,is_critical_flag,status_descriptor\n"
        "T1,ID1,1,1,False,NOMINAL\n"
    )
    assert main(["batch", "-i", str(source), "-o", str(output)]) == 0
    with output.open() as f:
        row = next(csv.DictReader(f))
    assert row["overall_status"] == "NOMINAL_OPTIMAL"


def test_api_smoke():
    from fastapi.testclient import TestClient
    from agents.api import app
    client = TestClient(app)
    assert client.get("/health").status_code == 200
    result = client.post("/api/audit", json={
        "task_id": "T1", "target_identifier": "ID1", "primary_metric": 1,
        "secondary_metric": 1, "status_descriptor": "NOMINAL"
    })
    assert result.status_code == 200
    assert result.json()["total_alerts"] == 0
    assert client.post("/api/audit", json={
        "task_id": "T2", "target_identifier": "ID2", "primary_metric": "NaN"
    }).status_code == 422
