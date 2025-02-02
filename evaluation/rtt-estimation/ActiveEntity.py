from Communicator import Communicator
from Entity import Entity, printTimed
from statistics import fmean
import json
import sys
import time

class ActiveEntity(Entity, Communicator):
    def __init__(self, destination, port):
        Entity.__init__(self)
        Communicator.__init__(self, port)
        self.destination = destination

    def estimateRoundTripTime(self, readings, initializationPackets = 5, initializationThreshold = 0.8, intermessageTimeout = 0, receiveTimeout = 1.5, preInitializationTimeout = 0, postInitializationTimeout = 0):
        # Wait until passive entity is ready
        time.sleep(preInitializationTimeout)

        # Test and initialize "connection"
        # -> Due to unknown reasons the first packet(s) has a significantly different RTT than other packets
        packetsLost = 0
        for i in range(0, initializationPackets):
            self.send("init", self.destination)
            packet = self.receive(timeout = receiveTimeout)
            if packet is None:
                packetsLost += 1
        if (1 - packetsLost / initializationPackets) < initializationThreshold:
            return None

        # Wait until system has processed initialization packets
        time.sleep(postInitializationTimeout)

        # Send readings many messages and estimate roundtriptime
        roundTripTimes = []
        for i in range(0, readings):
            # Send packet containing current time in nanoseconds
            if i != 0:
                # Wait before sending the next message
                time.sleep(intermessageTimeout)
            self.send(str(time.time_ns()), self.destination)

            # Block and wait for response packet
            packet = self.receive(timeout = receiveTimeout)

            # Calculate RTT, or set RTT to None in case of timeout
            receiveTime = time.time_ns()
            if packet is None:
                roundTripTimes.append(None)
            else:
                (sendTime, address) = packet
                roundTripTimes.append(receiveTime - int(sendTime))
        return roundTripTimes

if __name__ == "__main__":
    destination = str(sys.argv[1])
    port = int(sys.argv[2])
    readings = int(sys.argv[3])
    label = str(sys.argv[4])
    entity = ActiveEntity(destination, port)

    printTimed(f"Starting to estimate RTT.")
    startTime = time.time_ns()
    roundTripTimes = entity.estimateRoundTripTime(readings)
    endTime = time.time_ns()

    if roundTripTimes is None:
        printTimed("Estimation failed: Connection initilization not successful.")
    else:
        roundTripTimes = [x for x in roundTripTimes if x is not None]
        printTimed(f"Estimation successful.\nMin:{min(roundTripTimes)} Max:{max(roundTripTimes)} Avg:{fmean(roundTripTimes)} Lost:{readings - len(roundTripTimes)} PPS:{readings / (endTime - startTime) * pow(10, 9)}")
        estimation = {"label": label, "roundTripTimes": roundTripTimes}
        with open("./" + label + ".json", "w") as file:
            json.dump(estimation, file)