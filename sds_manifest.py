"""
Hand-rolled parser for Amazon's "SDS" game-manifest format (protobuf package
tv.twitch.fuel.sds), used by the real Amazon Games client and by Nile
(github.com/NearlyTRex/Nile) to describe a game's downloadable files.

No `protobuf` or crypto library dependency -- PlayDate has no per-plugin
dependency mechanism (see PyYAML note in requirements.txt) and Flatpak's
bundled Python doesn't ship google.protobuf, the same reason Battle.net's
product_db.py hand-parses its own protobuf file instead of importing the
package. The wire format here is tiny (8 flat messages, no oneofs/maps) so a
~40-line generic varint/length-delimited decoder covers all of it -- see
_decode_fields().

Signature verification (RSA-2048 PKCS#1 v1.5 / SHA-256) is done with pure
stdlib (hashlib + Python's builtin pow() for modular exponentiation) rather
than pulling in pycryptodome/cryptography for one call. AMZ_RSA_N/AMZ_RSA_E
are Amazon's real public key (github.com/NearlyTRex/Nile's AMZ_RSA_KEY
constant), extracted from the PEM once, offline, and hardcoded here --
avoids needing a DER/PEM parser at runtime for a key that never changes.
"""

import hashlib
import lzma
import struct

# Amazon's manifest-signing RSA public key (2048-bit, e=65537), extracted
# from Nile's AMZ_RSA_KEY PEM constant.
AMZ_RSA_N = 29534125617676521908024438092397415328287058517340002268756017952460736563362747519230981685421627430441555050811067994895848178887528561686711487955013620906421250756565605734719045888716283835622685687956458670807566733025349374163626902363198997644387405163464078943938306432979851404660013164611585681764146725593144580470945273180606115058833571539751349776456246378215815402061149914565594902964548495978874501507284818116040205064340610741450195522252210821033145023838228104284628283978506941119921000011206795482384812526722485838568197679895119763985829761132093841121586622900400012525704873431788568772971
AMZ_RSA_E = 65537

# DER prefix for a SHA-256 DigestInfo (fixed OID + params), per RFC 8017 PKCS#1 v1.5.
_SHA256_DIGESTINFO_PREFIX = bytes.fromhex('3031300d060960864801650304020105000420')

_COMPRESSION_ALGORITHMS = {0: 'none', 1: 'lzma'}
_HASH_ALGORITHMS        = {0: 'sha256', 1: 'shake128'}
_SIGNATURE_ALGORITHMS   = {0: 'sha256_with_rsa'}


class ManifestVerificationError(ValueError):
    pass


# ── Minimal protobuf wire-format decoder ────────────────────────────────────
#
# Decodes a message into {field_number: [(wire_type, raw_value), ...]} without
# a .proto schema -- callers know which field numbers/types to expect for
# each of the 8 fixed messages below (schema documented per-parser).

def _read_varint(buf, pos):
    result = 0
    shift = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7f) << shift
        if not (b & 0x80):
            return result, pos
        shift += 7


def _decode_fields(buf):
    fields = {}
    pos = 0
    length = len(buf)
    while pos < length:
        tag, pos = _read_varint(buf, pos)
        field_no  = tag >> 3
        wire_type = tag & 0x7
        if wire_type == 0:      # varint
            value, pos = _read_varint(buf, pos)
        elif wire_type == 1:    # 64-bit
            value = buf[pos:pos + 8]
            pos += 8
        elif wire_type == 2:    # length-delimited
            n, pos = _read_varint(buf, pos)
            value = buf[pos:pos + n]
            pos += n
        elif wire_type == 5:    # 32-bit
            value = buf[pos:pos + 4]
            pos += 4
        else:
            raise ValueError(f'Unsupported protobuf wire type {wire_type}')
        fields.setdefault(field_no, []).append(value)
    return fields


def _f_str(fields, n, default=''):
    v = fields.get(n)
    return v[0].decode('utf-8') if v else default

def _f_bytes(fields, n, default=b''):
    v = fields.get(n)
    return v[0] if v else default

def _f_int(fields, n, default=0):
    v = fields.get(n)
    return v[0] if v else default

def _f_bool(fields, n, default=False):
    v = fields.get(n)
    return bool(v[0]) if v else default

def _f_msg(fields, n):
    v = fields.get(n)
    return _decode_fields(v[0]) if v else {}

def _f_msgs(fields, n):
    return [_decode_fields(raw) for raw in fields.get(n, [])]


# ── Typed views over the decoded fields ─────────────────────────────────────

class Hash:
    # message Hash { 1: HashAlgorithm algorithm; 2: bytes value; }
    def __init__(self, fields):
        self.algorithm = _HASH_ALGORITHMS.get(_f_int(fields, 1), 'sha256')
        self.raw_value = _f_bytes(fields, 2)
        self.value     = self.raw_value.hex()


class Dir:
    # message Dir { 1: string path; 2: uint32 mode; }
    def __init__(self, fields):
        self.path = _f_str(fields, 1)
        self.mode = _f_int(fields, 2)


class File:
    # message File { 1: path; 2: mode; 3: size; 4: created; 5: Hash hash; 6: hidden; 7: system; }
    def __init__(self, fields):
        self.path    = _f_str(fields, 1)
        self.mode    = _f_int(fields, 2)
        self.size    = _f_int(fields, 3)
        self.created = _f_str(fields, 4)
        self.hash    = Hash(_f_msg(fields, 5))
        self.hidden  = _f_bool(fields, 6)
        self.system  = _f_bool(fields, 7)


class Package:
    # message Package { 1: string name; 2: repeated File files; 3: repeated Dir dirs; }
    def __init__(self, fields):
        self.name  = _f_str(fields, 1)
        self.files = [File(f) for f in _f_msgs(fields, 2)]
        self.dirs  = [Dir(d) for d in _f_msgs(fields, 3)]


class Manifest:
    # message Manifest { 1: repeated Package packages; }
    def __init__(self):
        self.packages = []


def _parse_manifest_body(raw):
    fields = _decode_fields(raw)
    m = Manifest()
    m.packages = [Package(p) for p in _f_msgs(fields, 1)]
    return m


# ── RSA-PKCS1v1.5/SHA-256 verification (pure stdlib) ────────────────────────

def _rsa_pkcs1v15_verify_sha256(message: bytes, signature: bytes) -> bool:
    n_bytes = (AMZ_RSA_N.bit_length() + 7) // 8
    if len(signature) != n_bytes:
        return False
    sig_int   = int.from_bytes(signature, 'big')
    recovered = pow(sig_int, AMZ_RSA_E, AMZ_RSA_N).to_bytes(n_bytes, 'big')

    if not recovered.startswith(b'\x00\x01'):
        return False
    sep = recovered.find(b'\x00', 2)
    if sep == -1:
        return False
    padding = recovered[2:sep]
    if len(padding) < 8 or any(b != 0xff for b in padding):
        return False

    digest = hashlib.sha256(message).digest()
    return recovered[sep + 1:] == _SHA256_DIGESTINFO_PREFIX + digest


# ── Top-level entry point ───────────────────────────────────────────────────

def parse_manifest(content: bytes, verify: bool = True) -> Manifest:
    """
    Parse a v3 SDS manifest.proto response (4-byte big-endian header length,
    then a ManifestHeader message, then the -- usually LZMA-compressed --
    signed Manifest body). Raises ManifestVerificationError if `verify` and
    the signature doesn't check out against Amazon's known public key.
    """
    header_size = struct.unpack('>I', content[:4])[0]
    header      = _decode_fields(content[4:4 + header_size])

    compression = _f_int(_f_msg(header, 1), 1)          # CompressionSettings.algorithm
    signature_fields = _f_msg(header, 3)                # Signature
    sig_algorithm = _SIGNATURE_ALGORITHMS.get(_f_int(signature_fields, 1))
    sig_value     = _f_bytes(signature_fields, 2)

    raw = content[4 + header_size:]
    if compression == 1:      # lzma
        raw = lzma.decompress(raw)
    elif compression != 0:    # not 'none'
        raise ManifestVerificationError(f'Unknown compression algorithm {compression!r}')

    if verify:
        if sig_algorithm != 'sha256_with_rsa':
            raise ManifestVerificationError(f'Unknown signature algorithm {sig_algorithm!r}')
        if not _rsa_pkcs1v15_verify_sha256(raw, sig_value):
            raise ManifestVerificationError('Manifest signature verification failed')

    return _parse_manifest_body(raw)
