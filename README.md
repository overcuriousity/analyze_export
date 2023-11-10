 
# Data Analyzer Application

This application is a PyQt5-based tool for analyzing text data from various file formats using regular expressions.

## Features

- Support for multiple file formats (PDF, TXT, XLSX, CSV).
- Regular expression-based analysis for different data patterns.
- GUI for easy interaction and usage.

## Installation

1. **Clone the Repository**

   ```bash
   git clone https://github.com/your-username/data-analyzer.git
   cd data-analyzer


2. Set up a Virtual Environment (Optional but Recommended)

For Windows:

bash
Copy code
python -m venv venv
.\venv\Scripts\activate
For Linux/Mac:

bash
Copy code
python3 -m venv venv
source venv/bin/activate
Install Required Packages

Install all required packages using the requirements.txt file:

bash
Copy code
pip install -r requirements.txt
Run the Application

3. After installing all the dependencies, you can run the application:

For Windows:

bash
Copy code
python analyze_export_4.py
For Linux/Mac:

bash
Copy code
python3 analyze_export_4.py


4. Usage

After starting the application, follow these steps:

Use the 'Select File for Analysis' button to choose files for analysis.
Select the types of data patterns you want to analyze (IPv4, IPv6, Email Address, etc.).
Optionally, enter a custom regex pattern.
Click on 'Start Analysis' to begin the analysis.
After the analysis, results will be displayed, and you can choose to save them as a CSV file.


5. Contributing
Contributions to this project are welcome. Please feel free to fork the repository, make changes, and submit pull requests.

6. License
This project is licensed under the Unlicense.
