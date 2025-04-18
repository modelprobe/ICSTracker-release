# ICSTracker-Release

**ICSTracker** is a system for identifying the model of ICS (Industrial Control System) devices over the Internet based on active network scanning traffic.

This repository provides core code and sample data to support the reproduction of key components described in our paper.

## Repository Structure
The directory structure of this repository is as follows:
```bash
ICSTracker-Release/ 
├── code/ # Core code for signature generation and device identification 
│ ├── device_identification/ # Core code
│ └── environment.yml # Conda environment file 
├── datasets/ # Sample scanning traffic and corresponding label files for demonstration purposes
│ ├── DS1
│ │ └──{protocol}_{region}_{source}_round{i}.pcap # Sample PCAP file
│ ├── DS2
│ ├── DS3
│ ├── DS4
│ ├── DS5
│ └── {protocol}_{source}_valid.csv # Sample label file
├── LICENSE
└── README.md # This file
```

## Data and Code Access

This repository includes:
- **Core Code** for device fingerprinting and matching.
- **Sample Datasets** for illustrative purposes.

**Note:**  
The full datasets and complete implementation are available **upon request during the peer-review process**.

**Important:**  
All code and data will be **fully released after the paper is officially accepted**.
