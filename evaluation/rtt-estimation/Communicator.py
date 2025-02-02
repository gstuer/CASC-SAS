import socket

class Communicator():
    def __init__(self, port):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.ip = "0.0.0.0"
        self.port = port
        self.socket.bind((self.ip, self.port))

    def send(self, message, ip, port = None):
        if port is None:
            port = self.port
        self.socket.sendto(message.encode(), (ip, port))

    def receive(self, timeout, bufferSize = 1024):
        self.socket.settimeout(timeout)
        try:
            (data, address) = self.socket.recvfrom(bufferSize)
            # print(f"{data} from {address}")
        except TimeoutError:
            return None
        return (data.decode(), address)
