# mail_header_probe

A small Python CLI tool to parse mail headers and extract useful review points.

This tool is designed for lightweight mail header review. It helps you inspect common fields such as `From`, `Return-Path`, `Reply-To`, `Message-ID`, `Authentication-Results`, `Received-SPF`, and `Received`, then summarizes possible clues for manual analysis.

It is intended as a review helper, not as a spam detection engine or a full forensic tool.

## Features

- Parses raw mail header text files
- Extracts basic header fields
- Summarizes SPF / DKIM / DMARC results
- Extracts sender IP candidates from `Received` headers
- Extracts domain candidates from multiple header fields
- Highlights review points as `WARN` / `INFO`
- Detects simple inconsistencies such as:
  - `From` vs `Return-Path`
  - `From` vs `Reply-To`
  - private IPs in the `Received` chain

## Use cases

- Quick review of suspicious mail headers
- Organizing manual mail investigation work
- Checking authentication-related header results
- Extracting likely sender IPs and domain candidates

## Project structure

```text
mail_header_probe/
├── main.py
├── parser.py
├── checks.py
├── formatter.py
├── sample/
│   ├── header.txt
│   └── spam_header.txt
├── README.md
└── .gitignore
````

## Requirements

* Python 3.9 or later

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
```

No external packages are required.

## Usage

### Parse a normal sample header

```bash
python main.py sample/header.txt
```

### Parse a suspicious sample header

```bash
python main.py sample/spam_header.txt
```

## Example output

```text
[Summary]
From: "Amazon Support" <support@amazon.co.jp>
Return-Path: <bounce@random-mail.xyz>
Reply-To: payment-confirm@cheap-alert.ru
Message-ID: <9988776655@random-mail.xyz>
Subject: Urgent: Confirm your account now
Date: Tue, 07 Apr 2026 03:12:10 +0000

[Authentication]
SPF: fail
DKIM: none
DMARC: fail

[Findings]
WARN: SPF result is fail.
WARN: DKIM result is none.
WARN: DMARC result is fail.
INFO: From domain and Return-Path domain differ: amazon.co.jp vs random-mail.xyz
INFO: From domain and Reply-To domain differ: amazon.co.jp vs cheap-alert.ru
INFO: Received header count: 2
INFO: Sender IP candidates found: 2
INFO: Private IP addresses found in Received chain: 10.0.0.5

[Sender IP Candidates]
- 10.0.0.5
- 203.0.113.55

[Domain Candidates]
- amazon.co.jp
- random-mail.xyz
- cheap-alert.ru
- unknown-node.random-mail.xyz
- mx.example.jp
- example.jp
```

## Notes

* This tool does not determine whether a message is definitively spam.
* It provides clues for human review.
* Mail headers vary a lot between systems, so extracted results should be reviewed carefully.
* Domain candidates are heuristic and may include noise depending on the header format.
* Private IPs in `Received` headers are not automatically malicious, but may be useful review points.

## Current checks

### Authentication-related

* SPF result
* DKIM result
* DMARC result

### Consistency-related

* `From` domain vs `Return-Path` domain
* `From` domain vs `Reply-To` domain
* missing `Return-Path`
* missing `Message-ID`
* missing `Received` headers

### Received chain-related

* number of `Received` headers
* sender IP candidate count
* private IPs found in the `Received` chain

## Future improvements

* Colorized output for findings
* Better filtering of noisy domain candidates
* Optional JSON output
* More precise extraction of originating sender
* Optional DNS lookups for domain investigation
* Better support for unusual header formats

## License

MIT


