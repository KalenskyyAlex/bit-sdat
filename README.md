# Static Document Analysis Tool (SDAT)

A Python CLI tool for **static analysis of potentially malicious documents**. Supports legacy Office CFBF (`.doc`, `.xls`), modern OOXML (`.docx`, `.xlsx`), and PDF formats.

The tool identifies common Indicators of Compromise (IOC), scores them, and generates JSON or PDF reports.

## Features

- Detects auto-run macros, embedded binaries, obfuscated content, and more.
- Generates structured reports in JSON or PDF.
- Modular pipeline architecture for easy extension.
- Static analysis only (no code execution).

## Installation

Clone the repository and install dependencies via `pip`:

```bash
git clone https://github.com/KalenskyyAlex/bit-sdat.git
cd bit-sdat
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

The CLI exposes two main commands: `analyze` and `pdf`.

**Analyze the document**
```
# Analyze a document and output JSON report
sdat analyze sample.docx

# Analyze and generate PDF report
sdat analyze sample.docx --pdf

# Specify custom output path
sdat analyze sample.docx --out reports/custom_report.pdf --pdf
```

**Convert an existing JSON report to PDF**
```
sdat pdf reports/sample_report.json

# Specify custom output path
sdat pdf reports/sample_report.json --out reports/sample_report.pd
```