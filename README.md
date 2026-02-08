# ICSTracker-Release

**ICSTracker** is a network-traffic-based framework for Internet-scale ICS device model attribution under incomplete observability. It combines protocol-compliant Internet probing with cross-round evidence aggregation to extract stable model-level interaction evidence, and performs robust single-round attribution under missing and extra packets. The system supports defense-oriented tasks such as asset inventory validation, exposure measurement, and responsible notification.

## Ethics Statement

This project conducts remote identification of ICS device models via active Internet scanning and network traffic fingerprinting. Recognizing the ethical implications of active probing, we adhere to the Menlo Report principles and RFC 9511 best practices. We carefully designed secure scanning procedures by analyzing real-world probe traffic collected from honeypots and validating request security through extensive local testbed trials. To minimize risks during global scanning, we limit probing frequency and volume, randomize the target order, and support opt-out through a public explanation website, whose address is embedded in outbound HTTP and UDP packets. While we openly share our identification method to support ICS defenders, we do not release scanning code to prevent potential misuse. All shared datasets are anonymized using a prefix-preserving algorithm and are available upon request for legitimate research purposes only.

 
## Repository Structure
The directory structure of this repository is as follows:
```bash
ICSTracker-Release/ 
├── code/ # Core code for signature generation and device identification 
│ ├── device_identification/ # Core code
│ └── environment.yml # Conda environment file 
├── datasets/ # Sample scanning traffic
│ ├── DS1/
│ │ └──{protocol}_{region}_{source}_round{i}.pcap # Sample PCAP file
│ ├── DS2/
│ ├── DS3/
│ ├── DS4/
│ └── DS5/
├── LICENSE
└── README.md # This file
```

## Data and Code Access

This repository provides the core attribution pipeline (feature extraction, signature construction, and inference) and evaluation scripts to reproduce key results reported in the paper.
For misuse-risk mitigation, we do not publicly release Internet-facing scanner code; instead we document the probing procedure (operation set, schedule, rate limits, and safeguards) to enable scientific assessment.

### Important Notice

Access to the full datasets remains available upon request, while the complete implementation of the identification method will be **publicly released following the official acceptance of the paper**.

Please note that the source code for the ICS scanners used in this study is **not included due to potential security concerns**.

## Dataset Request

Currently, we only provide sample data for illustrative purposes. Due to the requirements of anonymous peer review, we cannot share our contact information or detailed data request procedures at this stage.

Once the paper is officially accepted, we will update this repository with clear instructions on how to request access to the full datasets. We appreciate your understanding and patience.
