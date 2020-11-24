# Computation over encrypted data
FHE example code repo
part of the code fork from https://github.com/ancarey/OpenSourceFHE

To test the example code, we will first need to build and install the respective libraries. My project was tested in the following environment:
1. Host machine: MacBook Pro (13-inch, 2017) 2.3 GHz Dual-Core Intel Core i5 8 GB 2133 MHz LPDDR3
2. Host operating system: macOS Catalina version 10.15.6
3. Virtualization tool: VMware Fusion 11.5.1
4. Virtual Machine operating system: Intel® Core™ i5-7360U CPU @ 2.30GHz × 2 2.9 GB Ubuntu 20.04.1 LTS 64 bit
5. HElib version: 1.1.0
6. SEAL version: 3.5.9
7. Palisade version: 1.10.5


### HElib
1. HElib build & install prerequisites and instructions please refer to: https://github.com/homenc/HElib/blob/master/INSTALL.md
2. Once installed, We can test fully working examples provided by HElib under ```helib/examples``` to check if we build and install successfully.
2. Make HElibBGV.cpp and we can run the executable for the HElib BGV test

### SEAL
1. SEAL build & install prerequisites and instructions please refer to: https://github.com/microsoft/SEAL#building-microsoft-seal-manually
2. Once installed, we can test the working examples at ```/SEAL/bin/sealexamples``` and check if we build and install successfully.
3. Subsitute the eample code 1_bfv_basics.cpp to SEALBFV.cpp code and 4_ckks_basics.ccp code to SEALCKKS.cpp code in the ```SEAL/native/sealexamples``` and make the sealexample exectuable. Once we can make the sealexamples executable, we can then test SEAL bfv and ckks test in example 1 & 4.

### Palisade
1. Palisade build & install prerequisites and instructions please refer to: https://gitlab.com/palisade/palisade-release/-/tree/master
2. We can test the working examples at ```/palisade-release/bin/examples/pke``` and check if we build and install successfully.
3. Clone the Palisade code from this repo to ```/palisade-release/src/pke/examples``` and make from ```/palidade-release``` directory
4. We then can find the executable in ```/palisade-release/bin/examples/pke``` and run the respective palisade test 
