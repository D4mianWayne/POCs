# PoC Repository for CVEs and Vulnerabilities

Welcome to the PoC (Proof of Concept) repository for demonstrating CVEs (Common Vulnerabilities and Exposures) and other security vulnerabilities. This repository contains code snippets, scripts, and PoCs related to security vulnerabilities discovered in various software, libraries, and frameworks.

## About

This repository serves as a collection of PoCs developed by D4mianWayne (Robin) to showcase security vulnerabilities and their exploitation techniques. Each PoC is categorized based on the CVE identifier or the type of vulnerability it demonstrates.

## Contents

- **CVE PoCs**: Demonstrations for CVEs with detailed explanations and exploitation techniques.
- **Exploit Scripts**: Python scripts, shell scripts, and other tools developed to exploit specific vulnerabilities.

## POCs

- CrushFTP SSTI Vulnerability - [CVE 2024-4040](./CVE%202024-4040/)
- Ivanti Avalanche XXE Vulnerability - [CVE 2024-38653](./CVE%202024-38653/)
- Ivanti Endpoint Manager XXE Vulnerability - [CVE 2024-37397](./CVE%202024-37397/)
    * This exploit has hardcoded `historyEntryID`: [CVE-2024-37397-Hardcoded-ID-Showcase](./CVE%202024-37397/CVE-2024-37397-Hardcoded-ID-Showcase.py)
    * Final exploit leveraging `GetTasksXml` for `historyEntryID` Retrieval: [CVE-2024-37397-Final-Full-Chain](./CVE%202024-37397/CVE-2024-37397-Final-Full-Chain.py)
- HPE Insights Remote Support XXE via `validateAgainstXSD` Vulnerability - [CVE 2024-53675](./CVE%202024-53675/CVE-2024-53675.py)

## Disclaimer

This repository is intended for educational and research purposes only. The PoCs provided here should not be used for any illegal activities or malicious purposes. The maintainers of this repository are not responsible for any misuse of the information and code provided here.

## License

The code in this repository is licensed under the [Apache License](LICENSE).
