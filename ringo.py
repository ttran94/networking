import socket
import struct
import time
import math
import time
import threading
import operator
import sys
import itertools

BUFFER_SIZE = 2048


class Ringo:
    def __init__(self, flag, local_port, poc_host, poc_port, n):
        self.flag = flag
        self.local_port = local_port
        self.poc_host = poc_host
        self.poc_port = poc_port
        self.n = n
        self.peers = set()  # {(ip, port), (ip, port)}
        self.rtt_vector = {}
        # self.rtt_matrix = [[math.inf for i in range(n)] for j in range(n)]
        self.rtt_matrix = {}

    def peer_discovery(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)  # 3 seconds
        addr = (self.poc_host, self.local_port)
        length = 0
        total = self.n - 1
        while len(self.peers) < total or length < total:
            try:
                # time.sleep(0.05)
                message = ""
                if not self.peers:
                    message = "peer_discovery, no info available"
                else:
                    for (peer_ip, peer_port) in self.peers:
                        message +=  peer_ip + ":" + str(peer_port) + ","
                    message = "peer_discovery," + message
                _ = s.sendto(message, addr)
                data_sent, recv_addr = s.recvfrom(BUFFER_SIZE)
                length = int(data_sent)
            except socket.timeout:
                print("Timed out in attempt to discover peers. Trying again")
        s.close()
        print("length ")
        print(len(self.peers))
        return self.peers

    def add_peers(self, data, address):
        recv_host = address[0]
        recv_port = int(address[1])
        self_host = socket.gethostbyname(socket.gethostname())
        if recv_host !=  self_host:
            self.peers.add((recv_host, recv_port))
        if data != "peer_discovery, no info available":
            host_port_pairs = data.split(",")
            host_port_pairs = host_port_pairs[1:len(host_port_pairs) - 1]
            for pair in host_port_pairs:
                host_port_pair = pair.split(":")
                (peer_host, peer_port) = (host_port_pair[0], int(host_port_pair[1]))
                if peer_host != self_host:
                    self.peers.add((peer_host, peer_port))

    def initialize_rtt_vector(self):
        for (peer_host, peer_port) in self.peers:
            self.rtt_vector[peer_host] = float("inf")

    # listens to and sends from SERVER_PORT
    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((socket.gethostname(), self.local_port))
        while (1):
            data, address = server.recvfrom(BUFFER_SIZE)
            length = len(self.peers)
            if "peer_discovery" in data:
                if length < self.n - 1:
                    self.add_peers(data, address)
                server.sendto(str(length), address)
            elif "calculating RTT" in data:
                server.sendto(data, address)
            else:
                server.sendto(data, address)
                time.sleep(0.5)
                if "rtt_vectors" in data:
                    print("From: ")
                    print(address)
                    from_host = data.split("/")[1]
                    rtt_vectors = data.split("/")[2]
                    rtt_vec = {}
                    for vector in rtt_vectors.split(","):
                        host_rtt_pair = vector.split(":")
                        host = host_rtt_pair[0]
                        rtt = host_rtt_pair[1]
                        rtt_vec[host] = float(rtt)
                    print("RTT Vec: ")
                    print(rtt_vec)
                    for host in rtt_vec:
                        # rtt_matrix[sorted_hosts.index(from_host)][sorted_hosts.index(host)] = sorted_hosts[host]
                        self.rtt_matrix[(from_host, host)] = rtt_vec[host]
                    print("RTT Matrix")
                    print(self.rtt_matrix)


    # def receive_rtt_vector(self):
    #     server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    #     server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    #     server.bind((socket.gethostname(), RTT_PORT))
    #     while (1):
    #         data, address = server.recvfrom(BUFFER_SIZE)
    #         server.sendto(data, address)
    #         if "rtt_vectors" in data:
    #             from_host = data.split("/")[1]
    #             rtt_vectors = data.split("/")[2]
    #             rtt_vec = {}
    #             for vector in rtt_vectors.split(","):
    #                 host_rtt_pair = vector.split(":")
    #                 host = ip_rtt_pair[0]
    #                 rtt = ip_rtt_pair[1]
    #                 rtt_vec[host] = int(rtt)
    #             for host in rtt_vec:
    #                 # rtt_matrix[sorted_hosts.index(from_host)][sorted_hosts.index(host)] = sorted_hosts[host]
    #                 self.rtt_matrix[(from_host, host)] = sorted_hosts[host]
    #
    #                 # sends from and gets responses to local_port

    def calculate_rtt_vector(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        self.initialize_rtt_vector()
        for (peer_ip, peer_port) in self.peers:
            peer_addr = (peer_ip, self.local_port)
            counter = 0
            time_diff = 0
            while counter < 3:
                try:
                    send_time = time.time() * 1000  # time in ms
                    msg = "calculating RTT"
                    _ = s.sendto(msg, peer_addr)
                    data_sent, _ = s.recvfrom(BUFFER_SIZE)
                    if data_sent == msg:
                        counter += 1
                        recv_time = time.time() * 1000
                        time_diff += recv_time - send_time
                        # self.rtt_vector[peer_ip] = recv_time - send_time
                except socket.timeout:
                    print("Timed out. Trying again")
            self.rtt_vector[peer_ip] = time_diff / 3
        print(self.rtt_vector)
        s.close()

    def get_rtt_vector_msg(self, self_host):
        rtt_vector = self.rtt_vector
        rtt_vector[socket.gethostbyname(socket.gethostname())] = 0
        msg = "rtt_vectors/" + self_host + "/"
        for host in rtt_vector.keys():
            msg += host + ":" + str(rtt_vector[host]) + ","
        if msg:
            msg = msg[:-1]  # remove last comma
        return msg

    def print_rtt_matrix(self):
        hosts = [socket.hostname()] + self.peers
        sorted_hosts = sorted(hosts)
        print(" ")
        for host in sorted_hosts:
            print(" " + host)  # print columns
        print("\n")
        for from_host in sorted_hosts:
            print(from_host)
            for to_host in sorted_hosts:
                print(" " + self.rtt_matrix[(from_host, to_host)])  # print rows
            print("\n")

    def make_rtt_matrix_symmetric(self):
        hosts = [(socket.gethostbyname(socket.gethostname()), self.local_port)] + list(self.peers)
        for host1 in hosts:
            for host2 in hosts:
                rtt1 = self.rtt_matrix[(host1[0], host2[0])]
                rtt2 = self.rtt_matrix[(host2[0], host1[0])]
                average = (rtt1 + rtt2) / 2
                self.rtt_matrix[(host1[0], host2[0])] = average
                self.rtt_matrix[(host2[0], host1[0])] = average

    # send to SERVER PORT or create a new port for that?
    def send_rtt_vectors(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        msg = self.get_rtt_vector_msg(socket.gethostbyname(socket.gethostname()))
        self.initialize_rtt_matrix()
        print("Self Vector")
        print(self.rtt_vector)
        print("Self RTT")
        print(self.rtt_matrix)
        for (peer_ip, peer_port) in self.peers:
            peer_addr = (peer_ip, self.local_port)
            try:
                time.sleep(0.5)
                _ = s.sendto(msg, peer_addr)
                data_sent, _ = s.recvfrom(BUFFER_SIZE)
            # handle: try again
            except socket.timeout:
                print("Timed out. Trying again")
        while len(self.rtt_matrix) != self.n * self.n:
            time.sleep(0.2)
        return

    def initialize_rtt_matrix(self):
        rtt_vector = self.rtt_vector
        rtt_vector[socket.gethostbyname(socket.gethostname())] = 0
        for host in rtt_vector:
            self.rtt_matrix[(socket.gethostbyname(socket.gethostname()), host)] = self.rtt_vector[host]


# RTT_MATRIX: {(A,A)->0, (A,B)-> 2, ..., (A->F)->10, (B,A)->2, (B,B)->0, ...}
# A: B, C, D: ABCDA, ACDBA, AABCD, ACDAB, ....
# A...A
    def optimal_path(self):
        hosts = []
        for peer in self.peers:
            hosts.append(peer[0])
        possible_orders = list(itertools.permutations([socket.gethostbyname(socket.gethostname())] + hosts +
                                                      [socket.gethostbyname(socket.gethostname())]))
        sequence_to_rtt = {}
        for order in possible_orders:
            # starting host must be current ringo
            total_rtt = 0
            if order[0] == socket.gethostbyname(socket.gethostname()) and order[-1] == socket.gethostbyname(socket.gethostname()):
                for i in range(len(order) - 1):
                    pair = order[i:i + 2]
                    from_ringo = pair[0]
                    to_ringo = pair[1]
                    total_rtt += self.rtt_matrix[(from_ringo, to_ringo)]
                sequence_to_rtt[order] = total_rtt
        print("Sequence RTT")
        print(sequence_to_rtt)
        sorted_paths = sorted(sequence_to_rtt.items(), key=operator.itemgetter(1))
        return sorted_paths[0]


# input format: ringo <flag> <local-port> <PoC-name> <PoC-port> <N>

def main():
    if (len(sys.argv) != 6):
        print("Please provide arguments in the form: ringo.py <flag> <local-port> <PoC-name>" +
              "<PoC-port>>")
        return


    print(socket.gethostbyname(socket.gethostname()))
    flag = sys.argv[1]
    if flag != 'S' or flag != 'R' or flag != 'F':
        print("Flag input must be either S (Sender), R (Receiver) or F (Forwarder)")
        return
    local_port = int(sys.argv[2])
    poc_host = sys.argv[3]
    poc_port = int(sys.argv[4])
    n = int(sys.argv[5])
    ringo = Ringo(flag, local_port, poc_host, poc_port, n)
    help_others = threading.Thread(target=ringo.listen, args=())
    help_others.start()
    ringo.peer_discovery()
    ringo.calculate_rtt_vector()
    ringo.send_rtt_vectors()
    optimal_paths = ringo.optimal_path()

    help_others.join()
    while (1):
        command_input = raw_input("Ringo command: ")
        if command_input == "show-matrix":
            print(ringo.print_rtt_matrix())
        elif command_input == "show-ring":
            print(optimal_paths)
        elif command_input == "disconnect":
            break
        else:
            print("Please input one of the follow commands: <show-matrix>, <show-ring>, <disconnect>")

main()
