import socket
import struct
import time
import math
import time

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
    
    #self.rtt_matrix = [[0 for x in range(n)] for y in range(n)]
    
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
                  nbbjb
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
        self.rtt_vector[(peer_host, peer_port)] = math.inf
    
    def round_trip_time_matrix():
      initialize_rtt_vector()
      for (peer_ip, peer_port) in self.peers:
        peer_addr = (peer_ip, peer_port)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(3) # 3 seconds
        trial = 0
        try:
          while (trial < 3):
            send_time = int(time.time()) # time in ns
            _ = s.sendto("calculating rtt", peer_addr)
            data_sent
            
   


# input format: ringo <flag> <local-port> <PoC-name> <PoC-port> <N> 

def main():
  args = sys.argv
  if (len(sys.argv) != 5):
    print("Please provide arguments in the form: ringo <flag> <local-port> <PoC-name> <PoC-port> <N> ")
    return
  flag = sys.argv[1]
  local_port = sys.argv[2]
  poc_host = sys.argv[3]
  poc_port = sys.argv[4]
  n = sys.argv[5]
  ringo = Ringo(flag, local_port, poc_host, poc_port, n)
  peers = ringo.peer_discovery()
  for item in peers:
    print(peers)
  
  