# Real-Time Server-Aided Attribute-Based Authorization & Access Control for Substation Automation Systems

## Performance Analysis
### Perform Analysis Run
TODO ...
### Results
You can find the latest results of the RTS-ABAC performance analysis [here](https://github.com/gstuer/CASC-SAS/tree/real-time-abac/evaluation/rtt-estimation/results/rts-abac).
Each run of the performance analysis is represented by a result file in the JSON format.
#### Result File Layout
```json
{
  "label": "Label used to identify analysis run (typically authentication algorithm)",
  "lost": "Number of lost packets",
  "pps": "Number of sequential packets per second",
  "mean": "Mean RTT in ms",
  "median": "Median RTT in ms",
  "standardDeviation": "Standard deviation of the RTT in ms",
  "max": "Max RTT in ms",
  "min": "Min RTT in ms",
  "minMaxMidrange": "Non-trimmed central value between max and min RTT",
  "minMaxRange": "Difference of max and min RTT",
  "lowLatencyReadings": "Number of readings with RTT ≤ 6 ms",
  "mediumLatencyReadings": "Number of readings with RTT ≤ 40 ms",
  "highLatencyReadings": "Number of readings with RTT ≤ 200 ms",
  "veryHighLatencyReadings": "Number of readings with RTT ≤ 1000 ms",
  "roundTripTimes": "Ordered array of raw RTT readings"
}
```
