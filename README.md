# analyze_export

Created by using ChatGPT+ mid 2023.

Features:
- analyzes various types of text-containing files with regex patterns, output the entities as CSV Spreadsheet for further analysis
- import of multiple files of different types in one step is possible
- simplistic UI using pyQt5
- pre-defined patterns include ipv4, ipv6, email, btc addresses (all common formats), btc txid and custom (currently untested)
- option to only output crossmatches, when multiple files are imported
- natively supported file input formats: xlsx, pdf,  docx, csv and txt
- script checks if requirements are met when run

 Requirements: 
 - Python3 (created with 3.11)
 - python libraries: openpyxl, docx2txt, PyQt5, PyPDF2, pandas, os

Known Issues:
  - CSV files are not processed correctly. Solution in progress.
