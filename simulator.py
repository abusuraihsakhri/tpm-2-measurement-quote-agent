"""
TPM 2.0 Measurement and Quote Simulator.

Implements realistic simulations of TPM 2.0 concepts:
- PCR (Platform Configuration Register) simulation
- PCR extend: PCR[i] = Hash(PCR[i] || event_data)
- SHA-256 and SHA-1 PCR computation
- Measurement log (event log) with event type, digest, data
- Quote generation: sign PCR values with attestation key
- Verification: check PCR values against expected
- PCR bank management (SHA1, SHA256)

Uses only Python stdlib (hashlib, hmac, secrets, struct, json, time).
"""
import hashlib
import hmac
import secrets
import struct
import json
import time
from typing import List, Dict, Optional, Tuple, Any
from enum import Enum
from dataclasses import dataclass, field


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

class PCRBank(Enum):
    SHA1 = "sha1"
    SHA256 = "sha256"


class EventType(int, Enum):
    """TCG-defined event types for the measurement log."""
    PRE_BOOT_CERT = 0x00000000
    POST_CODE = 0x00000001
    NO_ACTION = 0x00000003
    SEPARATOR = 0x00000004
    ACTION = 0x00000005
    EVENT_TAG = 0x00000006
    S_CRTM_CONTENTS = 0x00000007
    S_CRTM_VERSION = 0x00000008
    CPU_MICROCODE = 0x00000009
    PLATFORM_CONFIG_FLAGS = 0x0000000A
    TABLE_OF_DEVICES = 0x0000000B
    COMPACT_HASH = 0x0000000C
    IPL = 0x0000000D
    IPL_PARTITION_DATA = 0x0000000E
    NONHOST_CODE = 0x0000000F
    NONHOST_CONFIG = 0x00000010
    NONHOST_INFO = 0x00000011
    OMIT_BOOT_DEVICE_EVENTS = 0x00000012
    EFI_EVENT_BASE = 0x80000000
    EFI_VARIABLE_DRIVER_CONFIG = 0x80000001
    EFI_VARIABLE_BOOT = 0x80000002
    EFI_BOOT_SERVICES_APPLICATION = 0x80000003
    EFI_BOOT_SERVICES_DRIVER = 0x80000004
    EFI_RUNTIME_SERVICES_DRIVER = 0x80000005
    EFI_GPT_EVENT = 0x80000006
    EFI_ACTION = 0x80000007
    EFI_PLATFORM_FIRMWARE_BLOB = 0x80000008
    EFI_HANDOFF_TABLES = 0x80000009


# Standard PCR indices
PCR_IDX_BIOS = 0       # SRTM, BIOS, Host Platform Extensions
PCR_IDX_PLATFORM = 1   # Platform Configuration
PCR_IDX_OPTION_ROMS = 2  # Option ROM Code
PCR_IDX_OPTION_ROM_CONFIG = 3  # Option ROM Configuration
PCR_IDX_IPL = 4        # IPL Code (MBR)
PCR_IDX_IPL_PARTITION = 5  # IPL Partition Data
PCR_IDX_BOOT_DEBUG = 6  # Boot Debug
PCR_IDX_BOOT_MANAGER = 7  # Secure Boot Policy
PCR_IDX_BOOT_LOADER = 8  # Boot Loader
PCR_IDX_BOOT_AUTHORITY = 9  # Boot Authority
PCR_IDX_KERNEL = 10    # Kernel/OS
PCR_IDX_MAX = 23

# Initial PCR values (all zeros)
PCR_INIT_SHA1 = b'\x00' * 20
PCR_INIT_SHA256 = b'\x00' * 32


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class EventLogEntry:
    """A single entry in the TPM measurement log."""
    pcr_index: int
    event_type: int
    digest: bytes          # Hash of the event data
    event_data: bytes      # The actual measured data
    event_id: str = ""     # Human-readable identifier

    def to_dict(self) -> Dict[str, Any]:
        return {
            'pcr_index': self.pcr_index,
            'event_type': self.event_type,
            'event_type_name': EventType(self.event_type).name if self.event_type in EventType.__members__.values() else f"0x{self.event_type:08X}",
            'digest': self.digest.hex(),
            'event_data': self.event_data.hex(),
            'event_id': self.event_id,
        }


@dataclass
class Quote:
    """A TPM Quote containing signed PCR values."""
    pcr_bank: str
    pcr_indices: List[int]
    pcr_values: Dict[int, bytes]  # index -> hash value
    nonce: bytes                   # Anti-replay nonce
    signature: bytes               # HMAC signature
    timestamp: float
    attestation_key_id: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            'pcr_bank': self.pcr_bank,
            'pcr_indices': self.pcr_indices,
            'pcr_values': {str(k): v.hex() for k, v in self.pcr_values.items()},
            'nonce': self.nonce.hex(),
            'signature': self.signature.hex(),
            'timestamp': self.timestamp,
            'attestation_key_id': self.attestation_key_id,
        }


# ---------------------------------------------------------------------------
# PCR Bank
# ---------------------------------------------------------------------------

class PCRBankState:
    """
    Manages a bank of PCRs for a single hash algorithm.

    Each PCR is a hash-width register that starts at all-zeros and
    is extended by: PCR[i] = Hash(PCR[i] || new_data)
    """

    def __init__(self, algorithm: PCRBank = PCRBank.SHA256, num_pcrs: int = 24):
        self.algorithm = algorithm
        self.num_pcrs = num_pcrs
        self._hash_func = getattr(hashlib, algorithm.value)
        self._digest_size = self._hash_func().digest_size
        self._pcrs: Dict[int, bytes] = {}
        self.reset()

    def reset(self):
        """Reset all PCRs to initial values."""
        init = b'\x00' * self._digest_size
        for i in range(self.num_pcrs):
            self._pcrs[i] = init

    def extend(self, pcr_index: int, data: bytes) -> bytes:
        """
        Extend a PCR: PCR[i] = Hash(PCR[i] || data).

        Returns the new PCR value.
        """
        if not 0 <= pcr_index < self.num_pcrs:
            raise IndexError(f"PCR index {pcr_index} out of range [0, {self.num_pcrs})")
        current = self._pcrs[pcr_index]
        new_value = self._hash_func(current + data).digest()
        self._pcrs[pcr_index] = new_value
        return new_value

    def read(self, pcr_index: int) -> bytes:
        """Read the current value of a PCR."""
        if not 0 <= pcr_index < self.num_pcrs:
            raise IndexError(f"PCR index {pcr_index} out of range [0, {self.num_pcrs})")
        return self._pcrs[pcr_index]

    def read_all(self) -> Dict[int, bytes]:
        """Read all PCR values."""
        return dict(self._pcrs)

    def read_selected(self, indices: List[int]) -> Dict[int, bytes]:
        """Read selected PCR values."""
        return {i: self._pcrs[i] for i in indices if 0 <= i < self.num_pcrs}

    @property
    def digest_size(self) -> int:
        return self._digest_size

    @property
    def algorithm_name(self) -> str:
        return self.algorithm.value


# ---------------------------------------------------------------------------
# Measurement Log
# ---------------------------------------------------------------------------

class MeasurementLog:
    """
    Maintains a TPM-style event log.

    Each entry records:
    - PCR index being extended
    - Event type (TCG-defined)
    - Digest (hash of event data using the PCR bank's algorithm)
    - Event data (the raw data being measured)
    """

    def __init__(self):
        self._entries: List[EventLogEntry] = []
        self._counter = 0

    def add_event(self, pcr_index: int, event_type: int, event_data: bytes,
                  event_id: str = "", hash_algorithm: str = "sha256") -> EventLogEntry:
        """
        Add an event to the log.

        The digest is computed as Hash(event_data) using the specified algorithm.
        """
        h = hashlib.new(hash_algorithm)
        h.update(event_data)
        digest = h.digest()

        entry = EventLogEntry(
            pcr_index=pcr_index,
            event_type=event_type,
            digest=digest,
            event_data=event_data,
            event_id=event_id or f"event-{self._counter}",
        )
        self._entries.append(entry)
        self._counter += 1
        return entry

    def get_entries(self, pcr_index: Optional[int] = None) -> List[EventLogEntry]:
        """Get log entries, optionally filtered by PCR index."""
        if pcr_index is not None:
            return [e for e in self._entries if e.pcr_index == pcr_index]
        return list(self._entries)

    def get_entry_count(self) -> int:
        return len(self._entries)

    def verify_entry_digest(self, entry: EventLogEntry, hash_algorithm: str = "sha256") -> bool:
        """Verify that an entry's digest matches its event data."""
        h = hashlib.new(hash_algorithm)
        h.update(entry.event_data)
        return h.digest() == entry.digest

    def to_list(self) -> List[Dict[str, Any]]:
        """Export log as a list of dicts."""
        return [e.to_dict() for e in self._entries]


# ---------------------------------------------------------------------------
# Attestation Key
# ---------------------------------------------------------------------------

class AttestationKey:
    """
    Simulates a TPM attestation key.

    In a real TPM this would be an RSA or ECC key stored in a protected
    hierarchy.  Here we use HMAC with a secret key for simulation.
    """

    def __init__(self, key_id: str = "AK-001", secret: Optional[bytes] = None):
        self.key_id = key_id
        self._secret = secret or secrets.token_bytes(32)

    def sign(self, data: bytes) -> bytes:
        """Sign data using HMAC-SHA256."""
        return hmac.new(self._secret, data, hashlib.sha256).digest()

    def verify(self, data: bytes, signature: bytes) -> bool:
        """Verify an HMAC-SHA256 signature."""
        expected = hmac.new(self._secret, data, hashlib.sha256).digest()
        return hmac.compare_digest(expected, signature)

    def get_public_info(self) -> Dict[str, str]:
        """Get public key info (simulated)."""
        pub_hash = hashlib.sha256(self._secret).hexdigest()
        return {
            'key_id': self.key_id,
            'algorithm': 'HMAC-SHA256',
            'public_hash': pub_hash[:32],
        }


# ---------------------------------------------------------------------------
# TPM Simulator
# ---------------------------------------------------------------------------

class TPMSimulator:
    """
    Full TPM 2.0 Measurement and Quote simulator.

    Combines PCR banks, measurement log, and attestation key to provide
    a complete measurement → quote → verify workflow.
    """

    def __init__(self, num_pcrs: int = 24):
        self.num_pcrs = num_pcrs
        self.pcr_banks: Dict[str, PCRBankState] = {
            'sha1': PCRBankState(PCRBank.SHA1, num_pcrs),
            'sha256': PCRBankState(PCRBank.SHA256, num_pcrs),
        }
        self.event_log = MeasurementLog()
        self.attestation_key = AttestationKey()
        self._boot_complete = False

    def extend_pcr(self, pcr_index: int, event_data: bytes,
                   event_type: int = EventType.ACTION,
                   event_id: str = "") -> Dict[str, bytes]:
        """
        Extend a PCR in all banks and log the event.

        Returns dict of bank_name -> new_pcr_value.
        """
        # Add to event log
        self.event_log.add_event(
            pcr_index=pcr_index,
            event_type=event_type,
            event_data=event_data,
            event_id=event_id,
        )

        # Extend in each bank
        results = {}
        for bank_name, bank in self.pcr_banks.items():
            new_val = bank.extend(pcr_index, event_data)
            results[bank_name] = new_val
        return results

    def read_pcr(self, pcr_index: int, bank: str = 'sha256') -> bytes:
        """Read a PCR value from a specific bank."""
        return self.pcr_banks[bank].read(pcr_index)

    def read_all_pcrs(self, bank: str = 'sha256') -> Dict[int, bytes]:
        """Read all PCR values from a specific bank."""
        return self.pcr_banks[bank].read_all()

    def generate_quote(self, pcr_indices: List[int],
                       nonce: Optional[bytes] = None,
                       bank: str = 'sha256') -> Quote:
        """
        Generate a TPM Quote.

        A quote is a signed statement of PCR values, including a nonce
        for anti-replay protection.

        The signed data format:
            TPM2_QUOTE_INFO = "QUOT" || pcr_bank || pcr_indices || pcr_values || nonce
        """
        if nonce is None:
            nonce = secrets.token_bytes(32)

        pcr_values = self.pcr_banks[bank].read_selected(pcr_indices)

        # Build the data to sign
        quote_data = self._build_quote_data(bank, pcr_indices, pcr_values, nonce)
        signature = self.attestation_key.sign(quote_data)

        return Quote(
            pcr_bank=bank,
            pcr_indices=pcr_indices,
            pcr_values=pcr_values,
            nonce=nonce,
            signature=signature,
            timestamp=time.time(),
            attestation_key_id=self.attestation_key.key_id,
        )

    def _build_quote_data(self, bank: str, pcr_indices: List[int],
                          pcr_values: Dict[int, bytes], nonce: bytes) -> bytes:
        """Build the canonical data blob that gets signed in a quote."""
        parts = [b'QUOT']
        parts.append(bank.encode())
        for idx in sorted(pcr_indices):
            parts.append(struct.pack('<I', idx))
            parts.append(pcr_values.get(idx, b'\x00' * 32))
        parts.append(nonce)
        return b'|'.join(parts)

    def verify_quote(self, quote: Quote, expected_nonce: bytes,
                     expected_pcr_values: Optional[Dict[int, bytes]] = None) -> Tuple[bool, List[str]]:
        """
        Verify a TPM Quote.

        Checks:
        1. Signature validity
        2. Nonce matches (anti-replay)
        3. PCR values match expected values (if provided)

        Returns (valid: bool, list of error messages).
        """
        errors = []

        # 1. Verify nonce
        if quote.nonce != expected_nonce:
            errors.append("Nonce mismatch: possible replay attack")

        # 2. Verify signature
        quote_data = self._build_quote_data(
            quote.pcr_bank, quote.pcr_indices, quote.pcr_values, quote.nonce
        )
        if not self.attestation_key.verify(quote_data, quote.signature):
            errors.append("Signature verification failed")

        # 3. Verify PCR values against expected
        if expected_pcr_values is not None:
            for idx in quote.pcr_indices:
                if idx in expected_pcr_values:
                    if quote.pcr_values.get(idx) != expected_pcr_values[idx]:
                        errors.append(f"PCR[{idx}] mismatch: expected {expected_pcr_values[idx].hex()}, got {quote.pcr_values.get(idx, b'').hex()}")

        return len(errors) == 0, errors

    def simulate_boot_sequence(self) -> List[Dict[str, bytes]]:
        """
        Simulate a typical UEFI boot measurement sequence.

        Measures:
        - PCR[0]: SRTM (Static Root of Trust for Measurement)
        - PCR[1]: Platform config
        - PCR[2]: Option ROMs
        - PCR[4]: IPL (boot loader)
        - PCR[7]: Secure Boot policy
        - PCR[8]: Boot loader
        """
        results = []

        # SRTM measurement
        r = self.extend_pcr(0, b'SRTM-BIOS-v2.0', EventType.S_CRTM_CONTENTS, 'SRTM')
        results.append(r)

        # Platform config
        r = self.extend_pcr(1, b'platform-config-001', EventType.PLATFORM_CONFIG_FLAGS, 'PlatformConfig')
        results.append(r)

        # Option ROM
        r = self.extend_pcr(2, b'option-rom-nic-001', EventType.EFI_BOOT_SERVICES_DRIVER, 'OptionROM')
        results.append(r)

        # Boot loader
        r = self.extend_pcr(4, b'grub2-2.06', EventType.IPL, 'BootLoader')
        results.append(r)

        # Secure Boot policy
        r = self.extend_pcr(7, b'secure-boot-enabled-db-001', EventType.EFI_VARIABLE_DRIVER_CONFIG, 'SecureBootPolicy')
        results.append(r)

        # Boot application
        r = self.extend_pcr(8, b'vmlinuz-5.15.0', EventType.EFI_BOOT_SERVICES_APPLICATION, 'Kernel')
        results.append(r)

        self._boot_complete = True
        return results

    def get_event_log(self) -> MeasurementLog:
        return self.event_log

    def reset(self):
        """Reset the TPM state."""
        for bank in self.pcr_banks.values():
            bank.reset()
        self.event_log = MeasurementLog()
        self._boot_complete = False
