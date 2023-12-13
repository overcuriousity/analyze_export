from collections import defaultdict
import sys
import os
import re
import csv
import importlib
import logging
import yaml
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QMessageBox, QCheckBox, QLineEdit, QComboBox
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
    def __init__(self, file_paths, selected_entities, regex_pattern, entities, include_context, context_type, context_size):
        super().__init__()
        self.file_paths = file_paths
        self.selected_entities = selected_entities
        self.entities = entities
        self.include_context = include_context
        self.context_type = context_type
        self.context_size = int(context_size) if context_size.isdigit() else 0

        self.patterns = {}
        for entity in selected_entities:
            if entity == 'Custom':
                self.patterns['Custom'] = re.compile(regex_pattern)
            elif entity in self.entities:
                self.patterns[entity] = re.compile(self.entities[entity]['regex'])
        
        self.data = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'filenames': set()}))

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
                logging.debug('Finished reading PDF input file.')
                return self.extract_text_from_pdf(file_path)
                
            elif file_path.endswith('.txt'):
                logging.debug('Finished reading TXT input file.')
                return self.extract_text_from_txt(file_path)                
            elif file_path.endswith('.csv'):
                logging.debug('Finished reading CSV input file.')
                return self.extract_text_from_csv(file_path)                
            else:
                print(f"Unsupported file type: {file_path}")
                logging.debug('Finished reading input file - unsupported')
                return None                
        except Exception as e:
            print(f"Error processing {file_path}: {e}")
            logging.debug('Finished reading input file with error.')
            return None
            

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
        lines = text.split('\n')
        for line_number, line in enumerate(lines, start=1):
            for entity in self.selected_entities:
                matches = self.patterns[entity].findall(line)
                for match in matches:
                    data_entry = self.data[entity][match]
                    data_entry['filenames'].add(filename)
                    data_entry['count'] += 1
                    if self.include_context:
                        context = self.get_context(lines, line_number, match)
                        data_entry.setdefault('context', []).append(context)


    def get_context(self, lines, line_number, match):
        if self.context_type == 'sentences':
            return self.get_context_sentences(lines, line_number, match)
        elif self.context_type == 'lines':
            return self.get_context_lines(lines, line_number)
        elif self.context_type == 'words':
            return self.get_context_words(lines, line_number, match)
        elif self.context_type == 'characters':
            return self.get_context_characters(lines, line_number, match)
        
        
    def get_context_words(self, lines, line_number, match):
        # Concatenate a buffer of lines around the entity
        buffer = ' '.join(lines[max(0, line_number - 3):min(len(lines), line_number + 2)])

        # Find the entity in the buffer and split into words
        words = buffer.split()
        try:
            entity_index = words.index(match)
        except ValueError:
            return "Context not found"

        # Calculate context range
        start_index = max(0, entity_index - self.context_size)
        end_index = min(len(words), entity_index + self.context_size + 1)

        return ' '.join(words[start_index:end_index])

    def get_context_lines(self, lines, line_number):
        start_line = max(0, line_number - self.context_size - 1)
        end_line = min(len(lines), line_number + self.context_size)
        return '\n'.join(lines[start_line:end_line])

    def get_context_characters(self, lines, line_number, match):
        buffer = ' '.join(lines[max(0, line_number - 3):min(len(lines), line_number + 2)])
        try:
            match_start = buffer.index(match)
            match_end = match_start + len(match)
        except ValueError:
            return "Context not found"

        start_index = max(0, match_start - self.context_size)
        end_index = min(len(buffer), match_end + self.context_size)
        return buffer[start_index:end_index]

    def get_context_sentences(self, lines, line_number, match):
        buffer = ' '.join(lines[max(0, line_number - 3):min(len(lines), line_number + 2)])
        sentences = re.split(r'(?<=[.!?]) +', buffer)

        # Find the sentence containing the entity
        match_sentence_index = -1
        for i, sentence in enumerate(sentences):
            if match in sentence:
                match_sentence_index = i
                break

        if match_sentence_index == -1:
            return "Context not found"

        start_index = max(0, match_sentence_index - self.context_size)
        end_index = min(len(sentences), match_sentence_index + self.context_size + 1)
        return ' '.join(sentences[start_index:end_index])


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Data Analyzer')
        self.setFixedSize(500, 400)
        self.file_paths = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QVBoxLayout(central_widget)
        context_layout = QHBoxLayout()


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

        self.entities = self.read_yaml('entities.yaml')

        self.checkboxes = {}
        for entity in self.entities:
            self.checkboxes[entity] = QCheckBox(entity)
            main_layout.addWidget(self.checkboxes[entity])

        if 'Custom' not in self.checkboxes:
            self.checkboxes['Custom'] = QCheckBox('Custom')
            main_layout.addWidget(self.checkboxes['Custom'])
            self.checkboxes['Custom'].stateChanged.connect(self.on_custom_checkbox_state_changed)

        self.checkboxes['Custom'].stateChanged.connect(self.on_custom_checkbox_state_changed)
        self.custom_regex_field = QLineEdit()
        self.custom_regex_field.setPlaceholderText('Custom Regex (Optional)')

        self.crossmatch_checkbox = QCheckBox('Output only crossmatches')
        self.crossmatch_checkbox.setEnabled(False)

        self.include_context_checkbox = QCheckBox('Include context in output')
        context_layout.addWidget(self.include_context_checkbox)

        self.context_size_combobox = QComboBox()
        self.context_size_combobox.addItems(["sentences", "lines", "words", "characters"])
        context_layout.addWidget(self.context_size_combobox)

        self.context_size_input = QLineEdit()
        self.context_size_input.setPlaceholderText('Context size (Enter a number)')
        context_layout.addWidget(self.context_size_input)

        main_layout.addLayout(context_layout)
        main_layout.addWidget(self.file_path_label)
        main_layout.addWidget(self.file_path_button)
        main_layout.addWidget(self.output_file_label)
        main_layout.addWidget(self.output_file_button)
        main_layout.addWidget(self.analysis_button)
        for checkbox in self.checkboxes.values():
            main_layout.addWidget(checkbox)
        main_layout.addWidget(self.custom_regex_field)
        main_layout.addWidget(self.crossmatch_checkbox)

    def read_yaml(self, file_path):
        with open(file_path, 'r') as yaml_file:
            return yaml.safe_load(yaml_file)

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

        context_type = self.context_size_combobox.currentText()
        context_size = self.context_size_input.text()

        self.analysis_thread = AnalysisThread(self.file_paths, selected_entities, regex_pattern, self.entities, self.include_context_checkbox.isChecked(), context_type, context_size)        
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
        output_message += f"\n\nOutput file saved at: {output_file_path}"
        QMessageBox.information(self, 'Analysis Complete', output_message)

        try:
            with open(output_file_path, 'w', newline='') as csvfile:
                fieldnames = ['Type', 'Entity', 'Occurrences', 'Source', 'Context_Snippet']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entity, matches in data.items():
                    for match, info in matches.items():
                        row = {
                            'Type': entity,
                            'Entity': match,
                            'Occurrences': info['count'],
                            'Source': ', '.join(info['filenames'])
                        }
                        if self.include_context_checkbox.isChecked():
                            if len(info['filenames']) > 1:
                                row['Context_Snippet'] = 'Found in multiple input files, manual analysis required.'
                            else:
                                row['Context_Snippet'] = '\n\n'.join(info.get('context', []))
                        writer.writerow(row)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while writing to the file: {str(e)}")

def main():
    app = QApplication([])
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
