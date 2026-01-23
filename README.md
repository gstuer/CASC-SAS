# Real-Time Server-Aided Attribute-Based Authorization & Access Control for Substation Automation Systems
RTS-ABAC is a novel real-time server-aided attribute-based authorization and access control approach for time-critical applications. In particular, we tailored
RTS-ABAC to the strict timing constraints inherent to the protocols employed in substation automation systems (SAS), especially the protocols GOOSE and SV. By conducting a laboratory-based performance and applicability analysis, we were able to demonstrate that our approach is a feasible solution for SAS environments, not only security-wise and performance-wise, but also cost-wise and due to its highly-compatible BITW concept. The BITW concept enables our approach to enhance the communication security in newly constructed and retrofitted digital substations.

If you have any further questions, please feel free to reach out to us!

## Performance Analysis
### Run Analysis
To reconduct the performance analysis you require five independent computers, we used five [Raspberry Pi 5 8GB](https://www.raspberrypi.com/products/raspberry-pi-5), interconnected via Ethernet.
Regarding the commands to be executed to run the analysis, please refer to the performance analysis targets "performance_analysis_*" within the [Makefile](https://github.com/gstuer/RTS-ABAC/tree/main/Makefile) for further information.

Note: You find the templates for the (compile-time) ABAC policies of the performance analysis in the [Authorization Controller](https://github.com/gstuer/RTS-ABAC/blob/main/pdp/src/main/java/com/gstuer/casc/pdp/AuthorizationController.java).
Please note that, if you do not use the same MAC and IP addresses as we did, you have to replace the addresses accordingly. The same applies for the commands within the [Makefile](https://github.com/gstuer/RTS-ABAC/tree/main/Makefile).
The pre-configured data plane of the performance analysis uses the following configuration (Hostname<IP, MAC, RTS-ABAC Role>):

**Lingonberry**<None, 2c:cf:67:a8:51:24, Active Entity> UDP--> **Strawberry**<192.168.0.60, Not relevant, Policy Enforcement Point (PEP)> RTS-ABAC--> **Cranberry**<192.168.0.61, Not relevant, Policy Enforcement Point (PEP)> UDP--> **Gooseberry**<None, 2c:cf:67:a8:51:7e, Passive Entity> (and vice-versa!)

Additionally, a policy decision point (PDP) needs to be deployed (**Huckleberry**<192.168.0.64, Not relevant, PDP>) and connected via Ethernet to **Strawberry** and **Cranberry**.

### Results
You can find the latest results of the RTS-ABAC performance analysis [here](https://github.com/gstuer/RTS-ABAC/tree/main/evaluation/rtt-estimation/results/rts-abac).
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
  "roundTripTimes": "Time-ordered array of raw RTT readings"
}
```

## Publications
- Moritz Gstür. 2025. Certificateless Attribute-Based Server-Aided Cryptosystem for Substation Automation Systems
(CASC-SAS). Master’s thesis. Karlsruher Institut für Technologie (KIT). doi:10.5445/IR/1000182038

- More are already in progress...
