from enum import Enum
import socket
import struct
import base64


class ControlType(Enum):
    SYN = 1
    ACK = 2
    NACK = 4
    FIN = 8
    DATA = 16
    SYN_ACK = 32


class Packet:

    def __init__(self, dst_port, src_port, dst_ip, src_ip, control_type, data, udp_seq=0, udp_ack_seq=0):
        byte_data = base64.b64encode(data.encode('utf-8'))

        ## IPv4 Pseudo Header (18 bytes)
        self.src_addr = src_ip  # 4 bytes
        self.dst_addr = dst_ip  # 4 bytes
        self.zeroes = 0  # 1 byte
        self.protocol = socket.IPPROTO_UDP  # 1 byte
        self.src_port = src_port  # 2 bytes
        self.dst_port = dst_port  # 2 bytes
        self.length = 18 + 18 + len(data)  # 2 bytes
        self.ip_checksum = 0  # 2 bytes (only checksum of IP fields)

        ## UDP Header (18 bytes + data)
        self.udp_src_port = src_port  # 2 bytes
        self.udp_dst_port = dst_port  # 2 bytes
        self.udp_length = len(data) + 18  # 2 bytes; size of UDP header + UDP data
        self.udp_checksum = 0  # 2 bytes (includes src/dst addr, reserved set to all 0s, protocol taken from IP header, length, data)
        self.udp_seq = udp_seq  # 4 bytes
        self.udp_ack_seq = udp_ack_seq  # 4 bytes
        self.control = control_type.value  # 1 byte
        self.data_len = len(byte_data)  # 1 byte
        self.data = byte_data  # max of 512 - 36 = 476 bytes

        # Packet packet
        self.raw = None
        self.calculate_ip_checksum()
        self.calculate_udp_checksum()
        return

    def calculate_ip_checksum(self):
        src_addr = socket.inet_aton(self.src_addr)
        dst_addr = socket.inet_aton(self.dst_addr)
        protocol = socket.IPPROTO_UDP
        ip_fragment = src_addr + dst_addr + struct.pack('!BBHHH',
                                                        self.zeroes,
                                                        protocol,
                                                        self.src_port,
                                                        self.dst_port,
                                                        self.length
                                                        )
        self.ip_checksum = self.chksum(ip_fragment)
        return

    def calculate_udp_checksum(self):
        src_addr = socket.inet_aton(self.src_addr)
        dst_addr = socket.inet_aton(self.dst_addr)
        protocol = socket.IPPROTO_UDP
        udp_fragment = src_addr + dst_addr + struct.pack('!HHHLLBH',
                                                         self.udp_src_port,
                                                         self.dst_port,
                                                         self.udp_length,
                                                         self.udp_seq,
                                                         self.udp_ack_seq,
                                                         self.control,
                                                         self.data_len)
        udp_fragment = udp_fragment + self.data
        # self.udp_checksum = self.chksum(udp_fragment)
        self.udp_checksum = 0
        return

    def chksum(self, msg):
        s = 0

        if (len(msg) % 2) == 1:
            msg += struct.pack('!B', 0)
        print(msg)
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + (msg[i + 1])
            s += w

        s = (s >> 16) + (s & 0xffff)
        s = ~s & 0xffff
        return s

    def assemble_packet(self):
        src_addr = socket.inet_aton(self.src_addr)
        dst_addr = socket.inet_aton(self.dst_addr)
        print(self.data_len)
        self.raw = src_addr + dst_addr + struct.pack('!BBHHHHHHHHLLBH',
                                                     self.zeroes,
                                                     self.protocol,
                                                     self.src_port,
                                                     self.dst_port,
                                                     self.length,
                                                     self.ip_checksum,
                                                     self.udp_src_port,
                                                     self.udp_dst_port,
                                                     self.udp_length,
                                                     self.udp_checksum,
                                                     self.udp_seq,
                                                     self.udp_ack_seq,
                                                     self.control,
                                                     self.data_len) + self.data
        return


def verify_checksum(msg):
    s = 0

    # if (len(msg) % 2) == 1:
    #     msg += struct.pack('!B', 0)
    #
    # for i in range(0, len(msg), 2):
    #     w = (msg[i] << 8) + (msg[i + 1])
    #     s += w
    #
    # s = (s >> 16) + (s & 0xffff)
    # s = ~s & 0xffff
    # return s == 0


def verify_ip_checksum(packet_ip):
    (src_addr, dst_addr, zeroes, protocol, src_port, dst_port, length, ip_checksum) = struct.unpack_from("!LLBBHHHH",
                                                                                                         packet_ip)
    ip_fragment = struct.pack('!LLBBHHHH',
                              src_addr,
                              dst_addr,
                              zeroes,
                              protocol,
                              src_port,
                              dst_port,
                              length,
                              ip_checksum)
    return verify_checksum(ip_fragment)


def verify_udp_checksum(packet_udp, data):
    (src_addr, dst_addr) = struct.unpack_from("!LL", packet_udp)
    (
        udp_src_port, udp_dst_port, udp_length, udp_checksum, udp_seq, udp_ack_seq, control,
        data_len) = struct.unpack_from(
        "!HHHHLLBB", packet_udp, offset=18)
    udp_fragment = struct.pack('!LLHHHLLHBH',
                               src_addr,
                               dst_addr,
                               udp_src_port,
                               udp_dst_port,
                               udp_length,
                               udp_seq,
                               udp_ack_seq,
                               udp_checksum,
                               control,
                               data_len)
    udp_fragment += data
    return verify_checksum(udp_fragment)


if __name__ == '__main__':
    original_data = None
    with open("README.MD", "r") as f:
        original_data = f.read()

    final_data = bytes()
    for i in range(0, len(original_data), 484):
        data = original_data[i:i + 484]
        encoded_data = base64.b64encode(data)
        final_data += encoded_data



    packet = Packet(8000, 1234, '127.0.0.1', '192.134.0.241', ControlType.DATA,
                    final_data, 134, 0);

    packet.assemble_packet()

    (src_addr, dst_addr, zeroes, protocol, src_port, dst_port, length, ip_checksum) = struct.unpack_from("!LLBBHHHH",
                                                                                                         packet.raw)
    src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
    dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
    print(verify_ip_checksum(packet.raw))

    (
    udp_src_port, udp_dst_port, udp_length, udp_checksum, udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from(
        "!HHHHLLBB", packet.raw, offset=19)
    byte_data = struct.unpack_from("!" + "s" * data_len, packet.raw, offset=-data_len)
    data = bytes()
    for d in byte_data:
        data += d
    print(data)
    print(verify_udp_checksum(packet.raw, data))
    print(base64.b64decode(data))
    with open("out_file1.md", "w") as f:
        f.write(base64.b64decode(data))
