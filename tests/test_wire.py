import unittest
import multi_vpn.wire as w

class WireTests(unittest.TestCase):
    def test_fragmentation_and_coalescing(self):
        wire = w.encode_frame(6) + w.encode_frame(3,b'abc')
        reader = w.FrameReader()
        result = []
        for byte in wire:
            result += reader.feed(bytes([byte]))
        reader.finish()
        self.assertEqual(result,[w.Frame(6,b''),w.Frame(3,b'abc')])
        self.assertEqual(w.FrameReader().feed(wire),result)

    def test_truncated_and_hostile_lengths(self):
        for raw in (b'',w.encode_frame(1) + b'x', b'BAD!' + bytes(4)):
            with self.assertRaises(ValueError): w.decode_frame(raw)
        reader = w.FrameReader(2)
        with self.assertRaises(ValueError): reader.feed(w.encode_frame(1,b'123')[:8])
        with self.assertRaises(ValueError): w.parse_tlvs(b'\0\1\0\x03x')
        reader = w.FrameReader()
        reader.feed(b'x')
        with self.assertRaises(ValueError): reader.finish()

    def test_auth_layout(self):
        frame = w.decode_frame(w.auth_v1('example.invalid','alice','secret','0011-2233-4455'))
        self.assertEqual(frame.command,1)
        self.assertEqual(frame.payload[:260],b'example.invalid' + bytes(245))
        self.assertEqual(w.parse_tlvs(frame.payload[260:]),[(1,b'alice\0'),(2,b'secret\0'),(3,b'0011-2233-4455')])
        with self.assertRaises(ValueError): w.auth_v1('x','bad\0name','x','0011-2233-4455')

    def test_vip(self):
        body = bytes([0,9,0,0]) + w.encode_tlv(1,bytes([10,0,0,7,24]))
        body += w.encode_tlv(5,bytes([192,0,2,0,24])) + w.encode_tlv(9,b'\x01\xbb')
        body += w.encode_tlv(999,b'future')
        parsed = w.parse_vip(body)
        self.assertEqual((parsed['vip'],parsed['prefix'],parsed['udp_port']),('10.0.0.7',24,443))
        self.assertEqual(parsed['exclude_routes'],['192.0.2.0/24'])
        with self.assertRaises(ValueError): w.parse_vip(bytes(4)+w.encode_tlv(1,bytes(4)))
        with self.assertRaises(ValueError): w.parse_vip(bytes(4)+w.encode_tlv(6,bytes(6)))

    def test_icmp_data_roundtrip(self):
        packet = w.icmp_echo('192.0.2.1','198.51.100.2',123,7,b'odd')
        info = w.decode_icmp(packet)
        self.assertEqual((info['type'],info['identifier'],info['sequence'],info['payload']),(8,123,7,b'odd'))
        self.assertEqual(w.decode_data(w.decode_frame(w.data_frame(packet))),packet)
        with self.assertRaises(ValueError): w.decode_icmp(packet[:-1]+b'!')

    def test_read_exact(self):
        buf = bytearray(w.encode_frame(6,b'xyz'))
        def recv(n):
            chunk = bytes(buf[:min(1,n)])
            del buf[:len(chunk)]
            return chunk
        self.assertEqual(w.read_frame(recv),w.Frame(6,b'xyz'))
        with self.assertRaises(EOFError): w.read_frame(recv)

if __name__ == '__main__': unittest.main()
