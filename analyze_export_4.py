from collections import defaultdict
import sys
import os
import re
import csv
import importlib
import logging
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QLabel, QPushButton,
    QFileDialog, QMessageBox, QCheckBox, QLineEdit
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
import pandas as pd
from PyPDF2 import PdfFileReader
from openpyxl import load_workbook

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

# Function to check and import required packages
def import_required_packages():
    required_packages = [
        'openpyxl', 'PyQt5', 'PyPDF2', 'pandas'
    ]

    missing_packages = []
    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)

    if missing_packages:
        missing = ", ".join(missing_packages)
        print(f"Missing packages: {missing}")
        print("\nTo install missing packages, use: pip install " + ' '.join(missing_packages))
        print("Note: On some Linux distributions, use 'pip3' instead of 'pip'.")
        print("On Archlinux, consider using 'pipx', installable via 'pacman' or 'pamac'.")
        sys.exit()

import_required_packages()

class AnalysisThread(QThread):
    analysis_complete = pyqtSignal(dict)
    patterns = {
        'IPv4 Address': re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'),
        'IPv6 Address': re.compile(r'\b(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}\b'),
        'Email Address': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', re.IGNORECASE),
        'BTC Address': re.compile(r'\b(1[a-km-zA-HJ-NP-Z1-9]{25,34}|3[a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-zA-HJ-NP-Z0-9]{11,71})\b', re.IGNORECASE),        
        'BTC txid': re.compile(r'\b[a-fA-F0-9]{64}\b')
    }

    def __init__(self, file_paths, selected_entities, regex_pattern):
        super().__init__()
        self.file_paths = file_paths
        self.selected_entities = selected_entities
        if regex_pattern:
            self.patterns['Custom'] = re.compile(regex_pattern)
        self.data = {entity: defaultdict(lambda: {'filenames': set(), 'count': 0}) for entity in selected_entities}
    
    def run(self):
        for file_path in self.file_paths:
            text = self.extract_text_from_file(file_path)
            if text is None:
                continue
            filename = os.path.basename(file_path)
            self.analyze_data(text, filename)
        self.analysis_complete.emit(self.data)

    def extract_text_from_file(self, file_path):
        logging.debug(f'Reading input file: {file_path}')
        try:
            if file_path.endswith('.pdf'):
                return self.extract_text_from_pdf(file_path)
                logging.debug('Finished reading PDF input file.')
            elif file_path.endswith('.txt'):
                return self.extract_text_from_txt(file_path)
                logging.debug('Finished reading TXT input file.')
            elif file_path.endswith('.xlsx'):
                return self.extract_text_from_excel(file_path)
                text_from_excel = self.extract_text_from_excel(file_path)
                logging.debug(f'Text extracted from XLSX file: {text_from_excel[:100]}...')  # Logs the first 100 characters of the extracted text
                logging.debug('Finished reading XLSX input file.')
            elif file_path.endswith('.csv'):
                return self.extract_text_from_csv(file_path)
                logging.debug('Finished reading CSV input file.')
            else:
                print(f"Unsupported file type: {file_path}")
                return None
                logging.debug('Finished reading input file - unsupported')
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            return None
            logging.debug('Finished reading input file with error.')

    # Methods to handle different file types
    def extract_text_from_pdf(self, file_path):
        logging.debug('Starting analysis of PDF')
        with open(file_path, "rb") as pdf_file:
            reader = PdfFileReader(pdf_file)
            return ' '.join([reader.getPage(i).extractText() for i in range(reader.getNumPages())])

    def extract_text_from_txt(self, file_path):
        logging.debug('Starting analysis of TXT')
        with open(file_path, 'r') as txt_file:
            return txt_file.read()

    def extract_text_from_excel(self, file_path):
        logging.debug('Starting analysis of XLSX file: ' + file_path)
        try:
            logging.debug('Attempting to read Excel file using pandas...')
            df = pd.read_excel(file_path)
            text = ' '.join(df.astype(str).values.flatten())
            logging.debug('Successfully extracted text from XLSX file.')
            return text
        except Exception as e:
            logging.error(f'Error occurred while processing XLSX file {file_path}: {e}')
            return ''

    def extract_text_from_csv(self, file_path):
        logging.debug('Starting analysis CSV, flattening data...')
        with open(file_path, 'r') as csv_file:
            try:
                sample_data = csv_file.read(1024)
                dialect = csv.Sniffer().sniff(sample_data)
                csv_file.seek(0)
                csv_reader = csv.reader(csv_file, dialect)
            except csv.Error:
                csv_file.seek(0)
                csv_reader = csv.reader(csv_file, delimiter=',')
            return ' '.join([' '.join(row) for row in csv_reader])

    def analyze_data(self, text, filename):
        lines = text.split('\n')  # Split the text into lines
        for line_number, line in enumerate(lines, start=1):
            for entity in self.selected_entities:
                matches = self.patterns[entity].findall(line)
                for match in matches:
                    if (filename, line_number) not in self.data[entity][match]['filenames']:
                        self.data[entity][match]['filenames'].add((filename, line_number))
                    self.data[entity][match]['count'] += 1



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
        self.output_file_label = QLabel('No file selected for output!')

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
        logging.debug('select_output_file function called. Opening file dialog for output file selection.')
        
        file_path, _ = QFileDialog.getSaveFileName(self, 'Save File', '', 'CSV Files (*.csv)')
        
        if file_path:
            logging.debug(f'Output file selected: {file_path}')
            self.output_file_label.setText(file_path)
            self.selected_output_file = file_path
        else:
            logging.debug('Output file selection was canceled by the user.')
            self.output_file_label.setText('No file selected for output!')


    def start_analysis(self):
        selected_entities = [entity for entity, checkbox in self.checkboxes.items() if checkbox.isChecked()]
        regex_pattern = self.custom_regex_field.text()

        # Validate the regex pattern
        if regex_pattern and not self.is_valid_regex(regex_pattern):
            QMessageBox.critical(self, 'Invalid Regex', 'The provided regular expression is not valid.')
            return

        # Get the output file path
        if not self.output_file_label.text() or self.output_file_label.text() == 'No file selected for output!':
            self.output_file_label.setText('output.csv')
        output_file_path = self.output_file_label.text()
        if not output_file_path:
            # Use a default file name and save it in the script directory
            output_file_path = os.path.join(os.path.dirname(__file__), 'output.csv')

        # Change this to pass list of file paths instead of a single file path
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
        output_file_path = self.output_file_label.text()
        if not output_file_path:
            output_file_path = os.path.join(os.path.dirname(__file__), 'output.csv')
        output_message = 'The data analysis is complete.\n\n' + summary
        output_message += f"\n\nOutput file saved at: {os.path.join(os.path.dirname(__file__), output_file_path)}"
        QMessageBox.information(self, 'Analysis Complete', output_message)

        output_only_crossmatches = self.crossmatch_checkbox.isChecked()

        try:
            # Output the data to a CSV file
            with open(self.output_file_label.text(), 'w', newline='') as csvfile:
                print("Writing to output.csv")  # Debugging print
                fieldnames = ['Type', 'Entity', 'Occurrences', 'Source']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

                writer.writeheader()
                for entity, matches in data.items():
                    for match, info in matches.items():
                        # Prepare filenames and line numbers string
                        filenames_lines = ", ".join([f"Line {line} in {fname}" for fname, line in info['filenames']])
                        writer.writerow({'Type': entity, 'Entity': match, 'Occurrences': info['count'], 'Source': filenames_lines})
                        logging.debug('writing unique value to output file')
                    logging.debug('writing value to output file')
                logging.debug('Analysis complete. Writing results to output file.')
            logging.debug('Output file generation complete.')

        except Exception as e:
            print("Error while writing to CSV file: ", e)

            print("Finished writing to output.csv")  # Debugging print
        except FileNotFoundError:
            QMessageBox.critical(self, 'File Not Found', f"The output file {self.output_file_label.text()} was not found.")
        except IOError:
            QMessageBox.critical(self, 'File Error', f"There was an error writing to the file {self.output_file_label.text()}.")
        except Exception as e:
            QMessageBox.critical(self, 'Unexpected Error', f"An unexpected error occurred while writing to the file: {str(e)}")

def main():
    app = QApplication([])
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()