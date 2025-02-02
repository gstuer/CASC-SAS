from Communicator import Communicator
from Entity import Entity, printTimed
import sys

class PassiveEntity(Entity, Communicator):
    def __init__(self, port):
        Entity.__init__(self)
        Communicator.__init__(self, port)

    def listen(self):
        while True:
            (data, sender) = self.receive(timeout = None)
            (ip, port) = sender
            self.send(data, ip, port)

if __name__ == "__main__":
    port = int(sys.argv[1])
    entity = PassiveEntity(port)

    printTimed(f"Starting to listen to port {port:d}")
    entity.listen()
