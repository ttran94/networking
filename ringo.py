import socket
import struct
import time
import math
import time
import threading
import itertools

BUFFER_SIZE = 2048
SERVER_PORT = 5000
RTT_PORT = 5050

class Ringo:
  def __init__(self, flag, local_port, poc_host, poc_port, n):
    self.flag = flag
    self.local_port = local_port
    self.poc_host = poc_host
    self.poc_port = poc_port
    self.n = n
    self.peers = set()  # {(ip, port), (ip, port)}
    self.rtt_vector = {}
    #self.rtt_matrix = [[math.inf for i in range(n)] for j in range(n)]
    self.rtt_matrix = {}

    
    def peer_discovery(flag, local_port, poc_host, poc_port, n, peers):
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.settimeout(3) # 3 seconds
      addr = (poc_host, poc_port)
      while len(peers) < n - 1:
        trial = 0
        try:
          while (trial < 3):
            try:
              # time.sleep(0.05)
              message = ""
              if not peers:
                message = "no info available"
              else:
                for (peer_ip, peer_port) in peers:
                  message += peer_ip + ":" + peer_port + "," 
              _ = s.sendto(message, addr)
              data_sent, recv_addr = s.recvfrom(BUFFER_SIZE)
              recv_host = recv_addr[0]
              recv_port = recv_addr[1]
              peers.add((recv_host, recv_port))
              response, _ = s.recvfrom(BUFFER_SIZE)
              flag = False
            except socket.timeout:
                print("Timed out in attempt to discover peers. Trying again")
                trial += 1
        finally:
          if trial == 3:
            print("Timed out 3 times, there's something wrong with the peer discovery method")
            s.close()
            return
        host_port_pairs = response.split(",")
        for pair in host_port_pairs:
          host_port_pair = pair.split(":")
          (peer_host, peer_port) = (host_port_pair[0], host_port_pair[1])
          peers.add((peer_host, peer_port))
      
      round_trip_time_matrix()
    
    
    def initialize_rtt_vector():
      for (peer_host, peer_port) in self.peers:
        self.rtt_vector[peer_host] = math.inf
        
     
    # listens to and sends from SERVER_PORT
    def listen():
      server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      s.bind(socket.gethostname(), SERVER_PORT)
      while(True):
          data, address = server.recvfrom(BUFFER_SIZE)
          server.sendto(data, address)
              
 
     def receive_rtt_vector():
      server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
      s.bind(socket.gethostname(), RTT_PORT)
      while(True):
          data, address = server.recvfrom(BUFFER_SIZE)
          server.sendto(data, address)
          if "rtt_vectors" in data:
            from_host = data.split("/")[1]
            rtt_vectors = data.split("/")[2]
            rtt_vec = {}
            for vector in rtt_vectors.split(","):
              host_rtt_pair = vector.split(":")
              host = ip_rtt_pair[0]
              rtt = ip_rtt_pair[1]
              rtt_vec[host] = int(rtt)
            
            #sorted_hosts = sorted(rtt_vec.keys(), key=lambda x:x.lower())
            for host in sorted_hosts:
              #rtt_matrix[sorted_hosts.index(from_host)][sorted_hosts.index(host)] = sorted_hosts[host]
              self.rtt_matrix[(from_host, host)] = sorted_hosts[host]                      
          
    
    # sends from and gets responses to local_port
    def calculate_rtt_vector():
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect((socket.gethostname(), self.local_port))
      s.settimeout(2) 
      initialize_rtt_vector()
      for (peer_ip, peer_port) in self.peers:
        peer_addr = (peer_ip, SERVER_PORT)
        trial = 0
        try:
          flag = True
          while (trial < 3 and flag):
            try:
              send_time = int(time.time()) * 1000000 # time in ms
              msg = "calculating RTT"
              _ = s.sendto(msg, peer_addr)
              data_sent, _ = s.recvfrom(BUFFER_SIZE)
              if data_sent != msg:
                # handle: try again
              recv_time = int(time.time()) * 1000000 
              self.rtt_vector[peer_ip] = recv_time - send_time
              flag = False
            except socket.timeout:
              print("Timed out. Trying again")
              trial += 1
        finally:
          if trial == 3:
            print(socket.gethostname() + " doesn't have direct path to " + peer_ip)
     
      s.close()
    
      
    def get_rtt_vector_msg(self_host):
      rtt_vector = self.rtt_vector
      rtt_vector[socket.gethostname()] = 0
      msg = "rtt_vectors/" + self_host + "/"
      for host in rtt_vector.keys():
        msg += host + ":" + rtt_vector[host] + ","
      if msg:
        msg = msg[:-1] # remove last comma
       return msg
    
    
    def print_rtt_matrix():
      hosts = [socket.hostname()] + self.peers
      sorted_hosts = sorted(hosts)
      print(" ")
      for host in sorted_hosts:
        print(" " + host)  # print columns
      print("\n")
      for from_host in sorted_hosts:
        print(from_host)
        for to_host in sorted_hosts:
          print(" " + self.rtt_matrix[(from_host, to_host)]) # print rows
        print("\n")
      
            
    def make_rtt_matrix_symmetric():
      hosts = [socket.gethostname()] + self.peers
      for host1 in hosts:
        for host2 in hosts:
          rtt1 = self.rtt_matrix[(host1, host2)]
          rtt2 = self.rtt_matrix[(host2, host1)]
          average = (rtt1 + rtt2)/2
          self.rtt_matrix[(host1, host2)] = average
          self.rtt_matrix[(host2, host1)] = average
    
    
    # send to SERVER PORT or create a new port for that?
    def send_rtt_vectors():
      s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
      s.connect((socket.gethostname(), self.local_port))
      s.setimeout(2)
      msg = get_rtt_vector_msg(socket.gethostname())
      for (peer_ip, peer_port) in self.peers:
        peer_addr = (peer_ip, RTT_PORT)
        trial = 0
        try:
          flag = True
          while (trial < 3 and flag):
            try:
              _ = s.sendto(msg, peer_addr)
              data_sent, _ = s.recvfrom(BUFFER_SIZE)
              if data_sent != msg:
                # handle: try again
              flag = False
            except socket.timeout:
              print("Timed out. Trying again")
               trial += 1
        finally:
          if trial == 3:
            print(socket.gethostname() + " doesn't have direct path to " + peer_ip)
       
       
# RTT_MATRIX: {(A,A)->0, (A,B)-> 2, ..., (A->F)->10, (B,A)->2, (B,B)->0, ...} 
# A: B, C, D: ABCDA, ACDBA, AABCD, ACDAB, ....
# A...A
    def optimal_path():
      possible_orders = list(itertools.permutations([socket.gethostname()] + self.peers + [socket.gethostname()]))
      sequence_to_rtt = {}
      for order in possible_orders:
        # starting host must be current ringo
        total_rtt = 0
        if order[0] != socket.gethostname() and order[-1] != socket.gethostname():
          continue
        for i in range(len(order) - 1):
          pair = order[i:i+2]
          from_ringo = pair[0]    
          to_ringo = pair[1]
          total_rtt += self.rtt_matrix[(from_ringo, to_ringo)]
          
        sequence_to_rtt[order] = total_rtt
      sorted_paths = sorted(sequence_to_rtt.items(), key=operator.itemgetter(1))
      return sorted_paths[0]


# input format: ringo <flag> <local-port> <PoC-name> <PoC-port> <N> 

def main():
  args = sys.argv
  if (len(sys.argv) != 5):
    gd
    
  flag = sys.argv[1]
  local_port = sys.argv[2]
  poc_host = sys.argv[3]
  poc_port = sys.argv[4]
  n = sys.argv[5]
  ringo = Ringo(flag, local_port, poc_host, poc_port, n)
  peers = ringo.peer_discovery()
  for item in peers:
    print(peers)
  help_others = threading.Thread(target=ringo.listen, args=())
  help_others.start()
  ringo.calculate_mine()
  