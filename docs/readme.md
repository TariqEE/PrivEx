# PrivEx: a Privacy-Preserving Statistics collection system for Anonymous Networks

## Instructions
(If you are looking to set up and run Privex, then please read S2/S2-netified/README.)

There are two PrivEx schemes. One uses secret sharing (found in the S2 directory) and the other uses distributed decryption (found in the D2 directory).

Required libraries:
libssl-dev, libssl, and cffi are needed.

Setup:
Noise generation requires that we know the amount of traffic that will be seen by the DC. In the Tor example from the paper we can use the Tor consensus to figure this out. We will thus need two files: consensus and fingerprint. Example files have been included but you can download fresher consensuses from the metrics.torproject.org. 

consensus: This Tor consensus file is used to find the probability traffic will flow through a DC. 

fingerprint: This is contains the DC's Tor relay fingerprint. We provide a utility that extracts fingerprints from a consensus file. It is in the util directory and is called fingerprint_extract. Just pick a fingerprint from the output of this tool and store it in this file.

Parameters:
PrivEx depends on certain parameters that set the operational performance and security envelope. These can be found at the top of S2-core.py and D2-core.py. 

num_DC: the number of data collectors. 
num_TKS: the number of tally key servers.
num_websites: the number of websites to collect stats for.
sigma: the standard deviation of the Gaussian probability distribution for use in generating the noise.

N.B. resolution should not need changing, but if it is increased, then in the D2 variant the size of the lookup table needs to be increased to accommodate the potentially larger message size.

Execution:
Simply run ./S2-core or ./D2-core.py to see the implementation be run through the code base. The output of each is a table listing of visitor counts per website. 
