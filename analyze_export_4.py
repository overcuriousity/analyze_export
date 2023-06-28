import importlib
import sys

# Define the required packages
required_packages = [
    'openpyxl', 'docx2txt', 'PyQt5', 'PyPDF2', 'pandas', 'os'
]

# Check if the required packages are installed
missing_packages = []
for package in required_packages:
    try:
        importlib.import_module(package)
    except ImportError:
        missing_packages.append(package)

# Prompt the user to install missing packages if any
if missing_packages:
    print("The following packages are missing:")
    for package in missing_packages:
        print(package)

    print("\nTo install the missing packages, use the following command:")
    print("pip install <package_name>")
    print("If you are using a Unix or Mac system, you may need to use pip3 instead of pip.\n")

    print("Please install the missing packages and run the script again.")
    sys.exit()  # Exit the script if there are missing packages
else:
    # All required packages are installed, proceed with the script
    import re
    import csv
    import os
    from openpyxl import load_workbook
    from docx2txt import process as docx2txt_process
    from PyPDF2 import PdfFileReader
    from PyQt5.QtWidgets import (
        QApplication,
        QMainWindow,
        QWidget,
        QVBoxLayout,
        QLabel,
        QPushButton,
        QFileDialog,
        QMessageBox,
        QCheckBox,
        QLineEdit,
    )
    from PyQt5.QtCore import Qt, QThread, pyqtSignal
    from concurrent.futures import ThreadPoolExecutor
    from collections import (
        Counter,
        defaultdict
    ) 
    import pandas as pd
    from pandas import read_excel


class AnalysisThread(QThread):
    analysis_complete = pyqtSignal(dict)
    patterns = {
        'IPv4 Address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        'IPv6 Address': re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'),
        'Email Address': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
        'BTC Address': re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-z0-9]{11,71})\b', re.IGNORECASE),
        'BTC txid': re.compile(r'\b[a-fA-F0-9]{64}\b')
    }

    def __init__(self, file_path, selected_entities, regex_pattern):
        super().__init__()
        self.file_path = file_path
        self.selected_entities = selected_entities
        if regex_pattern:  # Add custom pattern during initialization
            self.patterns['Custom'] = re.compile(regex_pattern)
        self.data = {entity: defaultdict(lambda: {'filenames': set(), 'count': 0}) for entity in selected_entities}  # Initialize data here
    
    def run(self):
        for file_path in self.file_path:
            text = self.extract_text_from_file(file_path)
            filename = os.path.basename(file_path)  # Extract only the filename from the file_path
            self.analyze_data(text, self.data, filename)  # Pass the filename parameter
        self.analysis_complete.emit(self.data)  # Emit the signal after analysis

    def extract_text_from_file(self, file):
        text = ''
        try:
            if file.endswith('.pdf'):
                with open(file, "rb") as file:
                    reader = PdfFileReader(file)
                    text = ' '.join([reader.getPage(i).extractText() for i in range(reader.getNumPages())])
            elif file.endswith('.txt'):
                with open(file, 'r') as file:
                    text = file.read()
            elif file.endswith('.xlsx'):
                df = pd.read_excel(file)
                text = ' '.join(df.astype(str).values.flatten())
            elif file.endswith('.docx'):
                text = docx2txt_process(file)
            elif file.endswith('.csv'):
                df = pd.read_csv(file)
                text = ' '.join(df.astype(str).values.flatten())
        except FileNotFoundError:
            print(f"The file {file} was not found.")
        except IOError:
            print(f"There was an error opening the file {file}.")
        except Exception as e:
            print(f"An unexpected error occurred while reading the file: {str(e)}")
        return text

    def analyze_data(self, text, data, filename):
        print(f"Analyzing data with the following patterns: {self.patterns}")  # Debugging print

        num_entities = len(self.selected_entities)
        for i, entity in enumerate(self.selected_entities, 1):
            matches = self.patterns[entity].findall(text)
            for match in matches:
                data[entity][match]['filenames'].add(filename)
                data[entity][match]['count'] += 1


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Data Analyzer')
        self.setFixedSize(500, 400)

        self.file_paths = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        layout = QVBoxLayout(central_widget)

        # File selection for analysis
        self.file_path_label = QLabel('No file selected for analysis')
        self.file_path_button = QPushButton('Select File for Analysis')
        self.file_path_button.clicked.connect(self.select_analysis_file)

        # File selection for output
        self.output_file_label = QLabel('No file selected for output')
        self.output_file_button = QPushButton('Select File for Output')
        self.output_file_button.clicked.connect(self.select_output_file)

        self.analysis_button = QPushButton('Start Analysis')
        self.analysis_button.clicked.connect(self.start_analysis)
        self.analysis_button.setEnabled(False)


        self.checkboxes = {
            'IPv4 Address': QCheckBox('IPv4 Address'),
            'IPv6 Address': QCheckBox('IPv6 Address'),
            'Email Address': QCheckBox('Email Address'),
            'BTC Address': QCheckBox('BTC Address'),
            'BTC txid': QCheckBox('BTC txid'),
            'Custom': QCheckBox('Custom'),
        }

        self.checkboxes['Custom'].stateChanged.connect(self.on_custom_checkbox_state_changed)
        self.custom_regex_field = QLineEdit()
        self.custom_regex_field.setPlaceholderText('Custom Regex (Optional)')

        self.crossmatch_checkbox = QCheckBox('Output only crossmatches')
        self.crossmatch_checkbox.setEnabled(False)

        layout.addWidget(self.file_path_label)
        layout.addWidget(self.file_path_button)
        layout.addWidget(self.output_file_label)
        layout.addWidget(self.output_file_button)
        layout.addWidget(self.analysis_button)
        for checkbox in self.checkboxes.values():
            layout.addWidget(checkbox)
        layout.addWidget(self.custom_regex_field)
        layout.addWidget(self.crossmatch_checkbox)

    def on_custom_checkbox_state_changed(self, state):
        self.custom_regex_field.setEnabled(state == Qt.Checked)

    def select_analysis_file(self):
        file_paths, _ = QFileDialog.getOpenFileNames(self, 'Open Files')

        if file_paths:
            self.file_paths = file_paths  # Save selected file paths
            self.file_path_label.setText(', '.join(file_paths))  # Show selected file paths
            self.analysis_button.setEnabled(True)

            # Enable or disable the crossmatch checkbox depending on the number of files selected
            self.crossmatch_checkbox.setEnabled(len(file_paths) > 1)

    def select_output_file(self):
        file_path, _ = QFileDialog.getSaveFileName(self, 'Save File', '', 'CSV Files (*.csv)')

        if file_path:
            self.output_file_label.setText(file_path)

    def is_valid_regex(self, pattern):
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

    def start_analysis(self):
        selected_entities = [entity for entity, checkbox in self.checkboxes.items() if checkbox.isChecked()]
        regex_pattern = self.custom_regex_field.text()

        # Validate the regex pattern
        if regex_pattern and not self.is_valid_regex(regex_pattern):
            QMessageBox.critical(self, 'Invalid Regex', 'The provided regular expression is not valid.')
            return

        # Change this to pass list of file paths instead of single file path
        self.analysis_thread = AnalysisThread(self.file_paths, selected_entities, regex_pattern)
        self.analysis_thread.analysis_complete.connect(self.analysis_complete)
        self.analysis_thread.start()

    def generate_summary(self, data):
        summary = ''
        for entity, matches in data.items():
            total_count = sum(info['count'] for info in matches.values())  # Total count of the entity across all files
            unique_entities_count = len(matches)  # Number of unique entities without duplicates
            crossmatch_count = len([match for match, info in matches.items() if len(info['filenames']) > 1])  # Number of entities that appear in more than one file
            
            summary += f"For entity type {entity}:\n"
            summary += f"\t- number of occurrences across all files: {total_count}\n"
            summary += f"\t- unique entities found (without duplicates): {unique_entities_count}\n"
            if len(self.file_paths) > 1:
                summary += f"\t- number of crossmatches: {crossmatch_count}\n"
        return summary

    def analysis_complete(self, data):
        summary = self.generate_summary(data)
        QMessageBox.information(self, 'Analysis Complete', 'The data analysis is complete.\n\n' + summary)

        output_only_crossmatches = self.crossmatch_checkbox.isChecked()

        try:
            # Output the data to a CSV file
            with open(self.output_file_label.text(), 'w', newline='') as csvfile:
                print("Writing to output.csv")  # Debugging print
                fieldnames = ['Type', 'Entity', 'Occurrences', 'Filenames']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for entity, matches in data.items():
                    for match, info in matches.items():
                        # Skip if it's not a crossmatch and only crossmatches are to be outputted
                        if output_only_crossmatches and len(info['filenames']) <= 1:
                            continue
                        filenames_str = ", ".join(info['filenames'])
                        writer.writerow({'Type': entity, 'Entity': match, 'Occurrences': info['count'], 'Filenames': filenames_str})
        except Exception as e:
            print("Error while writing to CSV file: ", e)

            print("Finished writing to output.csv")  # Debugging print
        except FileNotFoundError:
            QMessageBox.critical(self, 'File Not Found', f"The output file {self.output_file_label.text()} was not found.")
        except IOError:
            QMessageBox.critical(self, 'File Error', f"There was an error writing to the file {self.output_file_label.text()}.")
        except Exception as e:
            QMessageBox.critical(self, 'Unexpected Error', f"An unexpected error occurred while writing to the file: {str(e)}")


app = QApplication([])
window = MainWindow()
window.show()
app.exec_()
