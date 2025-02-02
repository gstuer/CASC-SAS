import signal
import sys
import time

class Entity():
    def __init__(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)

    def shutdown(self, signum, frame):
        printTimed(f"Stopping (Sig {signum}: {signal.strsignal(signum)})")
        sys.exit(0)

def getTimeRepresentation(timestamp = None):
    localDateTime = time.localtime(timestamp)
    formattedDate = time.strftime("%d %b %Y", localDateTime)
    formattedTime = time.strftime("%H:%M:%S", localDateTime)
    return f"{formattedDate} {formattedTime} {localDateTime.tm_zone}"

def printTimed(output):
    print(f"[{getTimeRepresentation()}] {output}")
