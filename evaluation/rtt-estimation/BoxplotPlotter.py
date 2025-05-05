import json
import sys
import matplotlib.pyplot as plt
import numpy as np
import os

if __name__ == "__main__":
    files = sys.argv[1].split(",")
    measurements = []
    labels = []
    for filename in files:
        with open(os.path.expanduser(filename), "r") as file:
            data = json.load(file)
            labels.append(data["label"])
            measurements.append([y for y in data["roundTripTimes"]])

    # Create the boxplot
    plt.figure(figsize=(14, 7))
    bp = plt.boxplot(measurements, labels=labels, patch_artist=True, boxprops=dict(edgecolor='#34495e', facecolor='lightblue', linewidth=1.5), showfliers=False)

    # Customize whiskers & median
    for whisker, cap in zip(bp['whiskers'], bp['caps']):
        whisker.set(color='#34495e', linewidth=1.5)
        cap.set(color='#34495e', linewidth=1.5)

    for median in bp['medians']:
        median.set(color='#2c3e50', linewidth=1.5)

    # Add a baseline with a fixed value
    fontsize = 14
    #plt.axhline(y=20, color='#2c3e50', linestyle='--', label=f'Medium Latency < 20 ms')
    plt.axhline(y=6, color='gray', linestyle='--', label=f'Low Latency < 6 ms')
    plt.legend(fontsize=fontsize)

    # Add labels
    plt.ylabel("Round-Trip Time (ms)", fontsize=fontsize)
    plt.xticks(fontsize=fontsize)

    plt.savefig('output.pdf', bbox_inches='tight')
    plt.show()
