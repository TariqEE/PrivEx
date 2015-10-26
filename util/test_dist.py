import numpy as np
import random
import math
import matplotlib.pyplot as plt
import pprint as pprint

sigma = 240
epochs = 135 
random_samples = []
privex_data = []

if __name__ == '__main__':
    sd = sigma/math.sqrt(epochs)
    for i in range(0, 6071):
        random_samples.append(random.gauss(0, sd))
    random_samples.sort()
    X = np.array(random_samples)
    pprint.pprint(X)
    Y_range = np.linspace(0, len(random_samples), len(random_samples), endpoint=True)/len(random_samples)
    plt.plot(X, Y_range, label='N(0,%f)' % sd)
    print len(random_samples)
    with open('results_stats.txt', 'r') as f:
        for line in f:
            if "Other" not in line and 'Epoch' not in line and 'Censored' not in line:
                _, count = line.strip().split()
                privex_data.append(float(count))

    privex_X = np.array(privex_data)
    privex_Y_range = np.linspace(0, len(privex_data), 6071, endpoint=True)/len(privex_data)
    print len(privex_data)
    plt.plot(privex_X, privex_Y_range, label='Privex: %d Epoch(s)' % epochs)
    plt.legend(loc='bottom right')
    plt.xlabel('Visits')
    plt.ylabel('CDF')
    plt.show()
