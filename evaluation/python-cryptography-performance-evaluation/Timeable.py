import time
import timeit

class Timeable:
    def executeTimed(self, function):
        timer = timeit.Timer(function, timer=time.perf_counter_ns)
        # TODO Implement free method to reset child class (free memory etc.) and then average multiple runs
        nanoseconds = timer.timeit(number=1)
        return nanoseconds
