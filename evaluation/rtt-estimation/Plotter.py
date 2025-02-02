import json
import sys
import matplotlib.pyplot as plt
import numpy as np
import os

if __name__ == "__main__":
    files = sys.argv[1].split(",")
    estimations = []
    maxValues = 0
    for filename in files:
        with open(os.path.expanduser(filename), "r") as file:
            data = json.load(file)
            estimation = {}
            estimation["label"] = data["label"]
            estimation["x"] = [x for x in range(len(data["roundTripTimes"]))]
            estimation["y"] = [y / pow(10, 6) for y in data["roundTripTimes"]]
            estimations.append(estimation)
            maxValues = max(maxValues, len(estimation["x"]))

    # Set figure size in inches
    fig, ax = plt.subplots(figsize=(10, 7))

    # Add baseline to plot
    baseline = 6
    x = [x for x in range(maxValues)]
    ax.plot([x[0], x[-1]], [baseline, baseline], label="Baseline", color="gray", linestyle="--", linewidth=1)
    ax.text(x[-1] * 1.01, baseline, "Baseline", color="gray", fontweight="bold", horizontalalignment="left", verticalalignment="center")

    # Plot data
    colors = ["tab:green", "tab:blue", "tab:brown", "tab:purple", "tab:orange"]
    minY = 100
    maxY = 0
    for i in range(len(estimations)):
        ax.plot(estimations[i]["x"], estimations[i]["y"], label=estimations[i]["label"], color = colors[i])
        ax.text(estimations[i]["x"][-1] * 1.01, estimations[i]["y"][-1], estimations[i]["label"], fontweight="normal", horizontalalignment="left", verticalalignment="center", color = colors[i])
        minY = min(minY, min(estimations[i]["y"]))
        maxY = max(maxY, max(estimations[i]["y"]))
    minY = round(minY)
    maxY = round(maxY)

    # Set axis labels
    ax.set_xlabel("Packet (#)")
    ax.set_ylabel("Latency (ms)")

    # Hide the axis lines & ticks
    ax.spines["right"].set_visible(False)
    ax.spines["top"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.yaxis.set_ticks_position("left")
    ax.xaxis.set_ticks_position("bottom")
    ax.spines["bottom"].set_bounds(min(x), 100.1)
    ax.spines["left"].set_bounds(minY, maxY)
    ax.set_xticks(np.arange(min(x), 100.1, 20))
    ax.set_yticks(np.arange(minY, maxY + 0.1, 1))

    # ax.legend()
    plt.savefig('output.pdf', bbox_inches='tight')
    plt.show()
