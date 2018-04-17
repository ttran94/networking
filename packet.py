import socket
import struct
import base64
from checksum import verify_checksum, verify_ip_checksum, verify_udp_checksum
from enum import Enum

DATA_PER_PACKET = 475

class ControlType(Enum):
	SYN = 1
	ACK = 2
	NACK = 3
	FIN = 4
	DATA = 5
	SYN_ACK = 6
	INIT = 7  # use for all initialization communication # RTT, RTT Matrix, Peer Disovery etc.
	ACK_FIN = 8
	KEEP_ALIVE = 9
	KEEP_ALIVE_ACK = 10


class Packet:

	def __init__(self, dst_port, src_port, dst_ip, src_ip, control_type, data, udp_seq, udp_ack_seq):
		#byte_data = base64.b64encode(data.encode('utf-8'))
		
		byte_data = data

		## IPv4 Pseudo Header (18 bytes)
		self.src_addr = src_ip # 4 bytes
		self.dst_addr = dst_ip # 4 bytes
		self.zeroes = 0 # 1 byte
		self.protocol = socket.IPPROTO_UDP # 1 byte
		self.src_port = src_port # 2 bytes
		self.dst_port = dst_port # 2 bytes
		self.length = 18 + 19 + len(data) # 2 bytes
		self.ip_checksum = 0 # 2 bytes (only checksum of IP fields)

		## UDP Header (18 bytes + data)
		self.udp_src_port = src_port # 2 bytes
		self.udp_dst_port = dst_port # 2 bytes
		self.udp_length = len(data) + 19 # 2 bytes; size of UDP header + UDP data
		self.udp_checksum = 0 # 2 bytes (includes src/dst addr, reserved set to all 0s, protocol taken from IP header, length, data)
		self.udp_seq = udp_seq # 4 bytes
		self.udp_ack_seq = udp_ack_seq # 4 bytes
		self.control = control_type.value # 1 byte
		self.data_len = len(byte_data) # 2 bytes
		self.data = byte_data # max of 512 - 36 = 476 bytes

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
		self.udp_checksum = self.chksum(udp_fragment)
		return

	
	def chksum(self, msg):
		s = 0

		if (len(msg)%2) == 1:
			msg += struct.pack('!B', 0)

		for i in range(0, len(msg), 2):
			w = (msg[i] << 8) + (msg[i + 1])
			s += w

		s = (s >> 16) + (s & 0xffff)
		s = ~s & 0xffff
		return s


	# call this method to pack all fields of the packet into a byte-string
	def assemble_packet(self):
		src_addr = socket.inet_aton(self.src_addr)
		dst_addr = socket.inet_aton(self.dst_addr)
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


if __name__ == '__main__':
	with open("test_file1.pdf", "rb") as f:
	 	original_data = f.read()
	 	encoded_data = base64.b64encode(original_data)
	 	print(len(encoded_data))


	final_data = bytes()
	err_ip = 0
	err_udp = 0
	count = 0
	for i in range(0, len(encoded_data), DATA_PER_PACKET):
		if i + DATA_PER_PACKET > len(encoded_data):
			data_fragment = encoded_data[i:]
		else:
			data_fragment = encoded_data[i:i+DATA_PER_PACKET]
		packet = Packet(8000, 1234, '127.0.0.1', '192.134.0.241', ControlType.DATA, data_fragment, 134, 0)
		packet.assemble_packet()
		(src_addr, dst_addr, zeroes, protocol, src_port, dst_port, length, ip_checksum) = struct.unpack_from("!LLBBHHHH", packet.raw)
		src_addr = socket.inet_ntoa(struct.pack('!L', src_addr))
		dst_addr = socket.inet_ntoa(struct.pack('!L', dst_addr))
		(udp_src_port, udp_dst_port, udp_length, udp_checksum, udp_seq, udp_ack_seq, control, data_len) = struct.unpack_from("!HHHHLLBH", packet.raw, offset=18)
		byte_data = struct.unpack_from("!" + "s" * data_len, packet.raw, offset=-data_len)
		data = bytes()
		for d in byte_data:
			data += d

		print(data)

		final_data += data
		if not verify_ip_checksum(packet.raw):
			err_ip += 1
			print(data_fragment)
			print(data)
		if not verify_udp_checksum(packet.raw, data):
			err_udp += 1
			print(data_fragment)
			print(data)


	print(len(final_data))
	print(final_data == encoded_data)
	name = base64.b64encode("out_file.pdf".encode('utf-8'))
	name = base64.b64decode(name)
	print(name)
	with open(name, "wb") as f:
		f.write(base64.decodebytes(final_data))