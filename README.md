# Data Analyzer Application

This application is a PyQt5-based tool for analyzing text data from various file formats using regular expressions.

## Features

- Support for multiple file formats (PDF, TXT, XLSX, CSV).
- Regular expression-based analysis for different data patterns.
- GUI for easy interaction and usage.

## Installation

1. Clone the Repository:
   git clone https://github.com/your-username/data-analyzer.git
   cd data-analyzer

2. Set up a Virtual Environment (Optional but Recommended):
   - For Windows:
     python -m venv venv
     .\venv\Scripts\activate
   - For Linux/Mac:
     python3 -m venv venv
     source venv/bin/activate

3. Install Required Packages:
   pip install -r requirements.txt

4. Run the Application:
   - For Windows:
     python analyze_export_4.py
   - For Linux/Mac:
     python3 analyze_export_4.py

## Usage

After starting the application, follow these steps:

- Use the 'Select File for Analysis' button to choose files for analysis.
- Select the types of data patterns you want to analyze (IPv4, IPv6, Email Address, etc.).
- Optionally, enter a custom regex pattern.
- Click on 'Start Analysis' to begin the analysis.
- After the analysis, results will be displayed, and you can choose to save them as a CSV file.

## Contributing

Contributions to this project are welcome. Please feel free to fork the repository, make changes, and submit pull requests.

## License

This project is licensed under the Unlicense.
