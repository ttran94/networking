import socket
import struct
import time
import math
import time
import threading
import operator
import sys
import itertools
import errno

BUFFER_SIZE = 2048  # if you change this to 512, parts from first assignment fail as  more than 512 bytes is sent in some instances.
DATA_PER_PACKET = 484


class Ringo:
    def __init__(self, flag, local_port, poc_host, poc_port, n):
        self.role = flag
        self.local_host = socket.gethostname()
        self.local_port = local_port
        self.poc_host = poc_host
        self.poc_port = poc_port
        self.n = n
        self.peers = set()  # {(ip, port), (ip, port)}
        self.rtt_vector = {}
        self.roles = {}  # {{ip, port}: <role>}
        self.rtt_matrix = {}

    # Ping
    def peer_discovery(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3)  # 3 seconds
        # keep track of peers pinged so far
        peer_discovery_map = {}
        while len(peer_discovery_map) < self.n - 1 or min(peer_discovery_map.items()) < self.n - 1:
            msg = "Peer Discovery/" + self.local_host + ":" + str(self.local_port)
            # starting ringo doesn't have a PoC; wait until there is a peer
            if self.poc_host == "0" and len(self.peers) == 0:
                continue

            # base case: ringo only has a PoC and no peers
            elif self.poc_host != "0" and len(self.peers) == 0:
                addr = (self.poc_host, self.poc_port)
                msg += "," + self.poc_host + ":" + str(self.poc_port)
                try:
                    _ = s.sendto(msg, addr)
                    data_recvd, _ = s.recvfrom(BUFFER_SIZE)
                    peers_discovered_by_peer = int(data_recvd)
                    peer_discovery_map[addr] = peers_discovered_by_peer
                except socket.timeout:
                    print("Timed out in attempt to discover peers. Trying again")

            # ping both poc and peers
            else:
                for (peer_host, peer_port) in self.peers:
                    msg += "," + peer_host + ":" + str(peer_port)
                if self.poc_host != "0":
                    msg += "," + self.poc_host + ":" + str(self.poc_port)
                    peers_to_ping = [(self.poc_host, self.poc_port)] + list(self.peers)
                else:
                    # case in which host doesn't have a PoC
                    peers_to_ping = list(self.peers)
                for peer in peers_to_ping:
                    try:
                        _ = s.sendto(msg, peer)
                        data_recvd, _ = s.recvfrom(BUFFER_SIZE)
                        peers_discovered_by_peer = int(data_recvd)
                        peer_discovery_map[peer] = peers_discovered_by_peer
                    except socket.timeout:
                        print("Timed out in attempt to discover peers. Trying again")

            time.sleep(0.05)
        s.close()
        return

    # listens to and sends from SERVER_PORT
    def listen(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((socket.gethostname(), self.local_port))
        while (1):
            data, address = server.recvfrom(BUFFER_SIZE)
            addr = (socket.gethostbyaddr(address[0])[0].split(".")[0], address[1])
            length = len(self.peers)
            if "Peer Discovery" in data:
                for peer in data.split("/")[1].split(","):
                    host_of_peer = peer.split(":")[0]
                    port_of_peer = int(peer.split(":")[1])
                    addr_of_peer = (host_of_peer, port_of_peer)
                    if addr_of_peer != (self.local_host, self.local_port) and addr_of_peer not in self.peers:
                        self.peers.add(addr_of_peer)
                server.sendto(str(len(self.peers)), addr)  # send back the number of peers it has
            elif "RTT" in data:
                server.sendto(data, addr)
                host_of_peer = data.split("/")[1].split(":")[0]
                port_of_peer = int(data.split("/")[1].split(":")[1])
                self.roles[(host_of_peer, port_of_peer)] = data.split("/")[2]
            elif "rtt_vectors" in data:
                server.sendto(data, addr)
                time.sleep(0.5)
                if "rtt_vectors" in data:
                    from_host = data.split("/")[1].split(":")[0]
                    from_port = int(data.split("/")[1].split(":")[1])
                    rtt_vectors = data.split("/")[2]
                    rtt_vec = {}
                    for vector in rtt_vectors.split(","):
                        host_port_pair = vector.split("=")
                        to_host = host_port_pair[0].split(":")[0]
                        to_port = int(host_port_pair[0].split(":")[1])
                        rtt = host_port_pair[1]
                        rtt_vec[(to_host, to_port)] = float(rtt)
                    for (to_host, to_port) in rtt_vec:
                        # rtt_matrix[sorted_hosts.index(from_host)][sorted_hosts.index(host)] = sorted_hosts[host]
                        self.rtt_matrix[(from_host, from_port, to_host, to_port)] = rtt_vec[(to_host, to_port)]

    def initialize_rtt_vector(self):
        for peer in self.peers:
            self.rtt_vector[peer] = float("inf")

    def calculate_rtt_vector(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        self.initialize_rtt_vector()
        self.roles[(self.local_host, int(self.local_port))] = self.role
        for peer in self.peers:
            counter = 0
            time_diff = 0
            while counter < 3:
                try:
                    send_time = time.time() * 1000  # time in ms
                    msg = "RTT/" + self.local_host + ":" + str(self.local_port) + "/" + self.role
                    _ = s.sendto(msg, peer)
                    data_sent, _ = s.recvfrom(BUFFER_SIZE)
                    if data_sent == msg:
                        counter += 1
                        recv_time = time.time() * 1000
                        time_diff += recv_time - send_time
                        # self.rtt_vector[peer_ip] = recv_time - send_time
                except socket.timeout:
                    print("Timed out in calculating RTT Vector. Trying again")
            self.rtt_vector[peer] = time_diff / 3
        s.close()

    # send to SERVER PORT or create a new port for that?
    def send_rtt_vectors(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(2)
        msg = self.get_rtt_vector_msg()
        self.initialize_rtt_matrix()
        for peer in self.peers:
            try:
                time.sleep(0.5)
                _ = s.sendto(msg, peer)
                data_sent, _ = s.recvfrom(BUFFER_SIZE)
            # handle: try again
            except socket.timeout:
                print("Timed out in sending RTT Vectors for RTT mattrix. Trying again")
        while len(self.rtt_matrix) != self.n * self.n:
            time.sleep(0.2)
        return

    def get_rtt_vector_msg(self):
        rtt_vector = self.rtt_vector
        curr_ringo_addr = (socket.gethostname(), self.local_port)
        rtt_vector[curr_ringo_addr] = 0
        msg = "rtt_vectors/" + socket.gethostname() + ":" + str(self.local_port) + "/"
        for peer in rtt_vector.keys():
            msg += peer[0] + ":" + str(peer[1]) + "=" + str(rtt_vector[peer]) + ","
        if msg:
            msg = msg[:-1]  # remove last comma
        return msg

    def initialize_rtt_matrix(self):
        rtt_vector = self.rtt_vector
        rtt_vector[socket.gethostname(), self.local_port] = 0
        for (host, port) in rtt_vector:
            self.rtt_matrix[(socket.gethostname(), self.local_port, host, port)] = self.rtt_vector[(host, port)]

    def print_rtt_matrix(self):
        all_ringos = [(socket.gethostname(), self.local_port)] + list(self.peers)
        sorted_ringos = sorted(all_ringos)
        print("\nRTT Matrix (in ms)")
        sys.stdout.write("                ")
        for host1, port1 in sorted_ringos:
            sys.stdout.write(" " + host1 + ":" + str(port1))
        sys.stdout.write("\n")
        for from_host, from_port in sorted_ringos:
            sys.stdout.write(from_host + ":" + str(from_port))
            i = 0
            for to_host, to_port in sorted_ringos:
                if i == 0:
                    sys.stdout.write(
                        "      " + str(round(self.rtt_matrix[(from_host, from_port, to_host, to_port)], 2)) + "      ")
                else:
                    sys.stdout.write(
                        str(round(self.rtt_matrix[(from_host, from_port, to_host, to_port)], 2)) + "      ")
            sys.stdout.write("\n")

    def make_rtt_matrix_symmetric(self):
        hosts = [(socket.gethostbyname(socket.gethostname()), self.local_port)] + list(self.peers)
        for host1 in hosts:
            for host2 in hosts:
                rtt1 = self.rtt_matrix[(host1[0], host2[0])]
                rtt2 = self.rtt_matrix[(host2[0], host1[0])]
                average = (rtt1 + rtt2) / 2
                self.rtt_matrix[(host1[0], host2[0])] = average
                self.rtt_matrix[(host2[0], host1[0])] = average

    def optimal_path(self):
        hosts = []
        for peer in self.peers:
            hosts.append(peer[0] + ":" + str(peer[1]))

        possible_orders = list(itertools.permutations([socket.gethostname() + ":" + str(self.local_port)] + hosts +
                                                      [socket.gethostname() + ":" + str(self.local_port)]))
        sequence_to_rtt = {}
        for order in possible_orders:
            # starting host must be current ringo
            total_rtt = 0
            # rather than having the current ringo as starting point of the optimal path, use sender as starting point
            if order[0] == socket.gethostname() + ":" + str(self.local_port) and order[
                -1] == socket.gethostname() + ":" + str(self.local_port):
                for i in range(len(order) - 1):
                    pair = order[i:i + 2]
                    from_ringo = pair[0].split(":")
                    to_ringo = pair[1].split(":")
                    total_rtt += self.rtt_matrix[(from_ringo[0], int(from_ringo[1]), to_ringo[0], int(to_ringo[1]))]
                sequence_to_rtt[order] = total_rtt
        sorted_paths = sorted(sequence_to_rtt.items(), key=operator.itemgetter(1))
        return sorted_paths[0][1], sorted_paths[0][0][:-1]

        # This method gives the best path and worst path (to be used when one of the ringos go offline in the best path)

    def establish_path(self):
        _, ring = self.optimal_path()
        path = [(ringo.split(":")[0], int(ringo.split(":")[1])) for ringo in ring]

        for peer in ring:
            addr = peer.split(":")[0]
            port = int(peer.split(":")[1])

        print('roles ', self.roles)
        for peer in self.roles:
            # Sender
            if self.roles[peer] == "S":
                sender = peer
            elif self.roles[peer] == "R":
                receiver = peer

        print('path ', path)
        print('sender ', sender)
        start_pos = path.index(sender)  # should be 0
        print('receiver', receiver)
        end_pos = path.index(receiver)  # anywhere from 1 to N - 1
        clockwise_path = [path[start_pos]]
        # Path 1 (clockwise)
        clockwise_rtt = 0
        if end_pos > start_pos:
            # [F F F S F F F F R]
            for i in range(start_pos, end_pos):
                from_ringo_addr = path[i][0]
                from_ringo_port = path[i][1]
                to_ringo_addr = path[i + 1][0]
                to_ringo_port = path[i + 1][1]
                clockwise_path.append(path[i + 1])
                clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]
        else:
            # [ F R F F S F F F F F]
            for i in range(start_pos, len(path) - 1):
                # covers from S until last position in path
                from_ringo_addr = path[i][0]
                from_ringo_port = path[i][1]
                to_ringo_addr = path[i + 1][0]
                to_ringo_port = path[i + 1][1]
                clockwise_path.append(path[i + 1])
                clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

            # from last position in path to front of path
            clockwise_path.append(path[0])
            clockwise_rtt += self.rtt_matrix[(path[len(path) - 1][0], path[len(path) - 1][1], path[0][0], path[0][1])]
            for i in range(0, end_pos):
                # covers from front to R
                from_ringo_addr = path[i][0]
                from_ringo_port = path[i][1]
                to_ringo_addr = path[i + 1][0]
                to_ringo_port = path[i + 1][1]
                clockwise_path.append(path[i + 1])
                clockwise_rtt += self.rtt_matrix[(from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

        print(clockwise_rtt)
        print(clockwise_path)

        # Path 2 (counter-clockwise)
        counter_clockwise_path = [path[start_pos]]
        counter_clockwise_rtt = 0
        if end_pos < start_pos:
            # [R F F S F F F F F]
            for i in range(start_pos, end_pos, -1):
                from_ringo_addr = path[i][0]
                from_ringo_port = path[i][1]
                to_ringo_addr = path[i - 1][0]
                to_ringo_port = path[i - 1][1]
                counter_clockwise_path.append(path[i - 1])
                counter_clockwise_rtt += self.rtt_matrix[
                    (from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]
        else:
            # [F F F R F F S F F]
            for i in range(start_pos, 0, -1):
                from_ringo_addr = path[i][0]
                from_ringo_port = path[i][1]
                to_ringo_addr = path[i - 1][0]
                to_ringo_port = path[i - 1][1]
                counter_clockwise_path.append(path[i - 1])
                counter_clockwise_rtt += self.rtt_matrix[
                    (from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

            # from front to last position in path
            counter_clockwise_path.append(path[len(path) - 1])
            counter_clockwise_rtt += self.rtt_matrix[
                (path[0][0], path[0][1], path[len(path) - 1][0], path[len(path) - 1][1])]

            for i in range(len(path) - 1, end_pos, -1):
                from_ringo_addr = path[i][0]
                from_ringo_port = path[i][1]
                to_ringo_addr = path[i - 1][0]
                to_ringo_port = path[i - 1][1]
                counter_clockwise_path.append(path[i - 1])
                counter_clockwise_rtt += self.rtt_matrix[
                    (from_ringo_addr, from_ringo_port, to_ringo_addr, to_ringo_port)]

        print(counter_clockwise_rtt)
        print(counter_clockwise_path)
        if (clockwise_rtt <= counter_clockwise_path):
            fast_path = clockwise_path
            slow_path = counter_clockwise_path
        else:
            fast_path = counter_clockwise_path
            slow_path = clockwise_path

        return fast_path, slow_path


# input format: ringo <flag> <local-port> <PoC-name> <PoC-port> <N>

def main():
    if (len(sys.argv) != 6):
        print("Please provide arguments in the form: ringo.py <flag> <local-port> <PoC-name>" +
              " <PoC-port> <N>")
        return
    print("IP Address: " + socket.gethostbyname(socket.gethostname()))
    print("Host name: " + socket.gethostname())
    flag = sys.argv[1]
    if flag != "S" and flag != "R" and flag != "F":
        print("Flag input must be either S (Sender), R (Receiver) or F (Forwarder)")
        return
    local_port = int(sys.argv[2])
    input_poc_host = sys.argv[3]
    poc_host = ""
    if len(input_poc_host.split(".")) == 4:
        poc_host = socket.gethostbyaddr(input_poc_host)[0].split(".")[0]
    else:
        poc_host = input_poc_host
    poc_port = int(sys.argv[4])
    n = int(sys.argv[5])
    ringo = Ringo(flag, local_port, poc_host, poc_port, n)
    help_others = threading.Thread(target=ringo.listen, args=())
    help_others.start()
    ringo.peer_discovery()
    ringo.calculate_rtt_vector()
    ringo.send_rtt_vectors()
    total_rtt, optimal_path = ringo.optimal_path()
    ringo.establish_path()

    while (1):
        command_input = raw_input("Ringo command: ")
        if command_input == "show-matrix":
            ringo.print_rtt_matrix()
        elif command_input == "show-ring":
            print("\nOptimal Path:")
            print(optimal_path)
            print("\nTotal RTT:")
            print(total_rtt)
        elif command_input == "disconnect":
            break
        elif "send" in command_input:
            filename = command_input.split(" ")[1]
            send_file(filename)
        else:
            print("Please input one of the follow commands: <show-matrix>, <show-ring>, <disconnect>")

    # help_others.join()


main()