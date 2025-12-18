Threat Intelligence Feed Aggregator (Mock Mode)
Overview

This project is a small Python-based Threat Intelligence Feed Aggregator created for the CYB 333 – Security Automation course. The goal of the project is to demonstrate how threat intelligence data can be automatically collected, cleaned up, and exported into a format that can be easily reviewed or used by other security tools.

Instead of manually copying indicators from a threat intel source, this script automates the process of ingesting indicator data, normalizing it into a consistent format, removing duplicates, and exporting the results as JSON or CSV.

For the purposes of this project, mock threat intelligence data is used instead of a live API. This keeps the tool predictable, repeatable, and easy to run without relying on external services or API keys.

What the Tool Does

Reads threat intelligence pulse data from a mock JSON file

Extracts Indicators of Compromise (IOCs), including:

IPv4 addresses

Domains and hostnames

URLs

File hashes

Normalizes indicator values (trimming whitespace, lowercasing domains, validating IPs)

Deduplicates indicators across multiple pulses

Exports the final results to JSON or CSV

Project Structure
aggregator/
├── Aggregator.py        # Main Python script
├── mock_pulses.json     # Mock threat intelligence data
├── screenshots/         # Screenshots showing the tool running
├── output/              # Generated output files (created at runtime)
└── README.md

Requirements

Python 3.10 or newer

No external libraries required 

How to Run

From the project directory, run:

python .\Aggregator.py --input .\mock_pulses.json --format json --out .\output\iocs.json


To export CSV instead:

python .\Aggregator.py --input .\mock_pulses.json --format csv --out .\output\iocs.csv


When successful, the script will display a message confirming the output file and the number of IOCs processed.

Screenshots 

The screenshots folder includes:

The Python code

A successful execution of the script

The generated output file

These screenshots are included to demonstrate that the tool runs correctly and produces structured output as required.

Security Notes

No API keys or credentials are used

No secrets are stored in the repository

Mock data is used to avoid external dependencies and ensure consistent results

Purpose and Learning Outcome

This project focuses on security automation concept and not a real-time threat intelligence analyzer. It demonstrates how repetitive security tasks such as indicator collection, normalization, and formatting can be automated reliably. The same approach could be extended to live feeds or additional data sources in a real-world environment.