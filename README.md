# ICSTracker-Release

**ICSTracker** aims to investigate the potential risks of model leakage in Industrial Control System (ICS) devices that are exposed on the Internet. By combining active Internet scanning with network traffic fingerprinting, this project remotely identifies ICS device models to support defenders in assessing their network assets.

This repository includes the core implementation and sample data to support reproduction of key components described in our paper. Access to the full dataset is available upon request and requires submitting relevant information to verify a legitimate research purpose, in order to prevent misuse.

## Ethics Statement

This project conducts remote identification of ICS device models via active Internet scanning and network traffic fingerprinting. Recognizing the ethical implications of active probing, we adhere to the Menlo Report principles and RFC 9511 best practices. We carefully designed secure scanning procedures by analyzing real-world probe traffic collected from honeypots and validating request security through extensive local testbed trials. To minimize risks during global scanning, we limit probing frequency and volume, randomize target order, and provide clear opt-out mechanisms via our website and DNS records. While we openly share our identification method to support ICS defenders, we do not release scanning code to prevent potential misuse. All shared datasets are anonymized using a prefix-preserving algorithm and are available upon request for legitimate research purposes only.


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

### Important Notice
The full datasets and complete implementation are available **upon request during the peer-review process**.
The complete implementation of the identification method will be **publicly released after the paper is officially accepted**.
Please note that the source code for the ICS scanners used in this study is **not included due to potential security concerns**.

