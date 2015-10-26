import numpy as np
import random
import math
import matplotlib.pyplot as plt
import pprint as pprint

websites = 6071
sigma = 240
epochs = 135 
random_samples = []
privex_data = []

if __name__ == '__main__':
    sd = (sigma/math.sqrt(epochs))
    for i in range(0, websites):
        random_samples.append(random.gauss(0, sd))
    random_samples.sort()
    X = np.array(random_samples)
    pprint.pprint(X)
    Y_range = np.linspace(0, len(random_samples), len(random_samples), endpoint=True)/len(random_samples)
    plt.plot(X, Y_range, label='N(0,%f)' % sd)
    with open('results_stats.txt', 'r') as f:
        for line in f:
            if "Other" not in line and 'Epochs' not in line and "Censored" not in line:
                _, count = line.strip().split()
                privex_data.append(float(count))

    privex_X = np.array(privex_data)
    privex_Y_range = np.linspace(0, len(privex_data), websites, endpoint=True)/len(privex_data)
    print len(privex_X), len(privex_Y_range)
    plt.plot(privex_X, privex_Y_range, label='Privex: %d Epoch(s)' % epochs)

    plt.legend(loc='lower right')
    plt.xlabel('Visits')
    plt.ylabel('CDF')
    plt.show()
