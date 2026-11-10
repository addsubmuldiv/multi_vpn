"""Offline UniVPN V1 codecs derived from the inspected client. No networking."""
from dataclasses import dataclass
import ipaddress
import re
import struct

MAGIC = bytes.fromhex('c192a4d6')
HEADER = struct.Struct('!4sBBH')
DATA_HEADER = struct.Struct('!4sBBH8x')

@dataclass(frozen=True)
class Frame:
    command: int
    payload: bytes

def encode_frame(command, payload=b''):
    payload = bytes(payload)
    if not 0 <= command <= 255 or len(payload) > 65535:
        raise ValueError('command or payload out of range')
    return HEADER.pack(MAGIC, 1, command, len(payload)) + payload

def decode_frame(data):
    data = bytes(data)
    if len(data) < 8:
        raise ValueError('truncated header')
    magic, version, command, size = HEADER.unpack_from(data)
    if magic != MAGIC or version != 1:
        raise ValueError('invalid V1 header')
    if len(data) != size + 8:
        raise ValueError('frame length mismatch')
    return Frame(command, data[8:])

class FrameReader:
    """Incrementally split a TLS byte stream; never assume read boundaries."""
    def __init__(self, max_payload=65535):
        if not 0 <= max_payload <= 65535:
            raise ValueError('invalid payload limit')
        self.buffer = bytearray()
        self.max_payload = max_payload

    def feed(self, data):
        self.buffer.extend(data)
        frames = []
        while len(self.buffer) >= 8:
            magic, version, _, size = HEADER.unpack_from(self.buffer)
            if magic != MAGIC or version != 1 or size > self.max_payload:
                raise ValueError('invalid stream header or length')
            if len(self.buffer) < 8 + size:
                break
            frames.append(decode_frame(self.buffer[:8 + size]))
            del self.buffer[:8 + size]
        return frames

    def finish(self):
        if self.buffer:
            raise ValueError('stream ended within a frame')

def read_frame(recv, max_payload=65535):
    """Read exactly one frame using a recv(n) callable without over-reading."""
    def exact(n):
        result = bytearray()
        while len(result) < n:
            chunk = recv(n - len(result))
            if not chunk:
                raise EOFError('stream ended within a frame')
            if len(chunk) > n - len(result):
                raise ValueError('recv returned more than requested')
            result.extend(chunk)
        return bytes(result)
    head = exact(8)
    magic, version, _, size = HEADER.unpack(head)
    if magic != MAGIC or version != 1 or size > max_payload:
        raise ValueError('invalid stream header or length')
    return decode_frame(head + exact(size))

def encode_tlv(kind, value):
    value = bytes(value)
    if not 0 <= kind <= 65535 or len(value) > 65535:
        raise ValueError('TLV out of range')
    return struct.pack('!HH', kind, len(value)) + value

def parse_tlvs(data):
    items, pos = [], 0
    while pos < len(data):
        if len(data) - pos < 4:
            raise ValueError('truncated TLV header')
        kind, size = struct.unpack_from('!HH', data, pos)
        pos += 4
        if size > len(data) - pos:
            raise ValueError('truncated TLV value')
        items.append((kind, bytes(data[pos:pos + size])))
        pos += size
    return items

def _cstring(value, limit):
    raw = value.encode('utf-8') if isinstance(value, str) else bytes(value)
    if b'\0' in raw or len(raw) > limit:
        raise ValueError('invalid string length or embedded NUL')
    return raw + b'\0'

def auth_v1(domain, username, password, mac):
    """Auth mode 0 only; encoding beyond ASCII requires gateway validation."""
    domain = _cstring(domain, 255).ljust(256, b'\0')
    mac = mac.encode('ascii') if isinstance(mac, str) else bytes(mac)
    if not re.fullmatch(rb'[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}', mac):
        raise ValueError('MAC must have uppercase XXXX-XXXX-XXXX format')
    body = domain + bytes(4)
    body += encode_tlv(1, _cstring(username, 256))
    body += encode_tlv(2, _cstring(password, 128))
    body += encode_tlv(3, mac)
    return encode_frame(1, body)

def parse_vip(payload):
    """Decode cmd3 payload, preserving unknown fields and duplicate TLVs."""
    if len(payload) < 4:
        raise ValueError('truncated VIP response')
    if payload[0] != 0:
        return {'result': payload[0], 'raw': bytes(payload)}
    flags = payload[1]
    out = dict(result=0, allocation_type=flags & 7, route_type=(flags >> 3) & 7,
               flags_high=flags >> 6, tlvs=parse_tlvs(payload[4:]))
    for kind, value in out['tlvs']:
        expected = {1:5, 2:20, 3:8, 4:140, 7:1, 8:32, 9:2}.get(kind)
        if expected is not None and len(value) != expected:
            raise ValueError('invalid VIP field length')
        if kind in (5, 6) and (not value or len(value) % 5):
            raise ValueError('invalid route field length')
        if kind in (5, 6) and len(value) // 5 > 1024:
            raise ValueError('too many routes')
        if kind == 1:
            prefix = value[4]
            if prefix > 32:
                raise ValueError('invalid IPv4 prefix')
            out['vip'] = str(ipaddress.IPv4Address(value[:4]))
            out['prefix'] = prefix
        elif kind == 3:
            out['ipv4_pair'] = [str(ipaddress.IPv4Address(value[i:i+4])) for i in (0,4)]
        elif kind == 4:
            out['dns_domain_raw'] = value[:128]
            out['dns_servers'] = [str(ipaddress.IPv4Address(value[i:i+4])) for i in (128,132,136) if any(value[i:i+4])]
        elif kind in (5, 6):
            routes = []
            for i in range(0, len(value), 5):
                if value[i+4] > 32:
                    raise ValueError('invalid route prefix')
                routes.append(str(ipaddress.IPv4Network((str(ipaddress.IPv4Address(value[i:i+4])),value[i+4]), strict=False)))
            out['exclude_routes' if kind == 5 else 'expansion_routes'] = routes
        elif kind == 7:
            out['tunnel_mode'] = value[0]
        elif kind == 8:
            out['key_material'] = value
        elif kind == 9:
            out['udp_port'] = struct.unpack('!H', value)[0]
    return out

def validate_ipv4(packet):
    packet = bytes(packet)
    if len(packet) < 20 or packet[0] >> 4 != 4:
        raise ValueError('invalid IPv4 packet')
    ihl = (packet[0] & 15) * 4
    if ihl < 20 or len(packet) < ihl or struct.unpack_from('!H', packet, 2)[0] != len(packet):
        raise ValueError('IPv4 length mismatch')
    return packet

def data_frame(packet):
    packet = validate_ipv4(packet)
    if len(packet) > 65535 - 8:
        raise ValueError('V1 data payload out of range')
    return DATA_HEADER.pack(MAGIC, 1, 0x66, len(packet) + 8) + packet

def decode_data(frame):
    if frame.command != 0x66 or len(frame.payload) < 8:
        raise ValueError('invalid data frame')
    # Reserved eight bytes are retained on the wire; their receive semantics
    # are not yet independently established beyond the inspected send path.
    return validate_ipv4(frame.payload[8:])

def checksum(data):
    data = bytes(data)
    data += bytes(len(data) % 2)
    total = sum(struct.unpack('!' + 'H' * (len(data)//2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535

def icmp_echo(source, destination, identifier=1, sequence=1, payload=b'univpn-probe'):
    body = struct.pack('!BBHHH',8,0,0,identifier,sequence) + bytes(payload)
    body = body[:2] + struct.pack('!H', checksum(body)) + body[4:]
    head = struct.pack('!BBHHHBBH4s4s',0x45,0,20+len(body),0,0,64,1,0,
                       ipaddress.IPv4Address(source).packed,ipaddress.IPv4Address(destination).packed)
    return head[:10] + struct.pack('!H',checksum(head)) + head[12:] + body

def decode_icmp(packet):
    packet = validate_ipv4(packet)
    ihl = (packet[0] & 15) * 4
    if packet[9] != 1 or len(packet) < ihl + 8 or struct.unpack_from('!H',packet,6)[0] & 0x3fff:
        raise ValueError('not a complete ICMP packet')
    if checksum(packet[:ihl]) or checksum(packet[ihl:]):
        raise ValueError('checksum mismatch')
    kind, code, _, identifier, sequence = struct.unpack_from('!BBHHH',packet,ihl)
    return dict(type=kind, code=code, identifier=identifier, sequence=sequence,
                source=str(ipaddress.IPv4Address(packet[12:16])),
                destination=str(ipaddress.IPv4Address(packet[16:20])),payload=packet[ihl+8:])
