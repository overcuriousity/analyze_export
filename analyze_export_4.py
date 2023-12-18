from collections import defaultdict
import sys
import os
import re
import csv
import logging
import yaml
from PyPDF2 import PdfFileReader  
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QFileDialog, QMessageBox, QCheckBox, QLineEdit, QComboBox,
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QEvent, QUrl
from openpyxl import load_workbook
from PyQt5.QtGui import QDesktopServices


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

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
            logging.error(f"Error processing {file_path}: {e}")
            return None
            
    def extract_text_from_pdf(self, file_path):
        try:
            with open(file_path, 'rb') as pdf_file:
                pdf_reader = PdfFileReader.PdfFileReader(pdf_file)
                return ' '.join([pdf_reader.getPage(i).extractText() for i in range(pdf_reader.getNumPages())])
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            return None
        
    def extract_text_from_txt(self, file_path):
        try:
            with open(file_path, 'r') as txt_file:
                return txt_file.read()
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            return None

    def extract_text_from_csv(self, file_path):
        try:
            with open(file_path, 'r') as csv_file:
                sample_data = csv_file.read(1024)
                csv_file.seek(0)
                dialect = csv.Sniffer().sniff(sample_data)
                reader = csv.reader(csv_file, dialect)          
                return ' '.join([' '.join(row) for row in reader])
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            return None

    def analyze_data(self, text, filename):
        lines = text.split('\n')
        for line_number, line in enumerate(lines, start=1):
            for entity in self.selected_entities:
                matches = self.patterns[entity].findall(line)
                for match in matches:
                    # Handle tuple matches
                    if isinstance(match, tuple):
                        match_str = ' '.join(match)
                    else:
                        match_str = match

                    data_entry = self.data[entity][match_str]
                    data_entry['filenames'].add((filename, line_number))  # Store filename and line number
                    data_entry['count'] += 1
                    if self.include_context:
                        context = self.get_context(lines, line_number, match_str)
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
        else:
            return "Context not found"  
        
    def get_context_words(self, lines, line_number, match):
        buffer = ' '.join(lines[max(0, line_number - self.context_size - 1):min(len(lines), line_number + self.context_size)])
        match_start_index, match_end_index = self.find_match_in_buffer(buffer, match)
        if match_start_index is None:
            return "Context not found"

        words = buffer.split()
        start_word_index = len(buffer[:match_start_index].split())
        end_word_index = len(buffer[:match_end_index].split())

        start_index = max(0, start_word_index - self.context_size)
        end_index = min(len(words), end_word_index + self.context_size)

        return ' '.join(words[start_index:end_index])

    def get_context_lines(self, lines, line_number):
        start_line = max(0, line_number - self.context_size - 1)
        end_line = min(len(lines), line_number + self.context_size)
        return '\n'.join(lines[start_line:end_line])

    def get_context_characters(self, lines, line_number, match):
        buffer = ' '.join(lines[max(0, line_number - self.context_size - 1):min(len(lines), line_number + self.context_size)])
        
        match_start = buffer.find(match)
        if match_start == -1:
            return "Context not found"

        start_index = max(0, match_start - self.context_size)
        end_index = min(len(buffer), match_start + len(match) + self.context_size)

        return buffer[start_index:end_index]

    def get_context_sentences(self, lines, line_number, match):
        buffer = ' '.join(lines[max(0, line_number - self.context_size - 1):min(len(lines), line_number + self.context_size)])
        sentences = re.split(r'(?<=[.!?]) +', buffer)

        match_sentence_index = None
        for i, sentence in enumerate(sentences):
            if match in sentence:
                match_sentence_index = i
                break

        if match_sentence_index is None:
            return "Context not found"

        start_index = max(0, match_sentence_index - self.context_size)
        end_index = min(len(sentences), match_sentence_index + self.context_size + 1)
        return ' '.join(sentences[start_index:end_index])

    def find_match_in_buffer(self, buffer, match):
        match_start = buffer.find(match)
        if match_start == -1:
            return None, None

        match_end = match_start + len(match)
        return match_start, match_end


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Data Analyzer')
        self.setFixedSize(800, 600)
        self.file_paths = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.main_layout = QVBoxLayout(central_widget)
        context_layout = QHBoxLayout()


        # File selection for analysis
        self.file_path_label = QLabel('No file selected for analysis')
        self.file_path_button = QPushButton('Select File for Analysis')
        self.file_path_button.clicked.connect(self.select_analysis_file)

        # File selection for output
        self.output_file_label = QLabel('No file selected for output, saving at default location.')

        self.output_file_button = QPushButton('Select File for Output')
        self.output_file_button.clicked.connect(self.select_output_file)

        self.analysis_button = QPushButton('Start Analysis')
        self.analysis_button.clicked.connect(self.start_analysis)
        self.analysis_button.setEnabled(False)

        self.entities = self.read_yaml('entities.yaml')

        self.checkboxes = {}
        self.setup_checkboxes_with_tooltips()

        if 'Custom' not in self.checkboxes:
            self.checkboxes['Custom'] = QCheckBox('Custom')
            self.main_layout.addWidget(self.checkboxes['Custom'])
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

        self.link_label = QLabel()
        self.link_label.setText('<a href="https://github.com/overcuriousity/analyze_export/">github</a>')
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_browser)

        self.main_layout.addLayout(context_layout)
        self.main_layout.addWidget(self.file_path_label)
        self.main_layout.addWidget(self.file_path_button)
        self.main_layout.addWidget(self.output_file_label)
        self.main_layout.addWidget(self.output_file_button)
        self.main_layout.addWidget(self.analysis_button)
        for checkbox in self.checkboxes.values():
            self.main_layout.addWidget(checkbox)
        self.main_layout.addWidget(self.custom_regex_field)
        self.main_layout.addWidget(self.crossmatch_checkbox)
        self.info_label = QLabel("Hover over an entity for more information")
        self.main_layout.addWidget(self.info_label)   
        self.main_layout.addWidget(self.link_label)

    def open_browser(self, url):
        QDesktopServices.openUrl(QUrl(url))

    def read_yaml(self, file_path):
        try:
            with open(file_path, 'r') as yaml_file:
                return yaml.safe_load(yaml_file)
        except FileNotFoundError:
            logging.error(f"YAML file not found: {file_path}")
            return {}
        except yaml.YAMLError as exc:
            logging.error(f"Error parsing YAML file: {file_path}, {exc}")
            return {}

    def setup_checkboxes_with_tooltips(self):
        for entity, properties in self.entities.items():
            checkbox = QCheckBox(entity)
            self.checkboxes[entity] = checkbox
            tooltip = properties.get('tooltip', 'No tooltip provided.')
            checkbox.setProperty("tooltipText", tooltip)
            checkbox.installEventFilter(self)
            
            self.main_layout.addWidget(checkbox)

    def eventFilter(self, source, event):
        if event.type() == QEvent.Enter and isinstance(source, QCheckBox):
            tooltip = source.property("tooltipText")
            self.info_label.setText(tooltip)
        return super(MainWindow, self).eventFilter(source, event)
    
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
            self.output_file_label.setText('No file selected for output, saving at default location.')


    def start_analysis(self):
        try:
            selected_entities = [entity for entity, checkbox in self.checkboxes.items() if checkbox.isChecked()]
            regex_pattern = self.custom_regex_field.text()
            if regex_pattern and not self.is_valid_regex(regex_pattern):
                QMessageBox.critical(self, 'Error', 'Invalid custom regex pattern.')
                return
            
            output_file_path = self.output_file_label.text() or 'output.csv'
            context_type = self.context_size_combobox.currentText()
            context_size = self.context_size_input.text()

            self.analysis_thread = AnalysisThread(self.file_paths, selected_entities, regex_pattern, self.entities, self.include_context_checkbox.isChecked(), context_type, context_size)
            self.analysis_thread.analysis_complete.connect(self.analysis_complete)
            self.analysis_thread.start()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while starting the analysis: {str(e)}")
            logging.error(f"An error occurred while starting the analysis: {str(e)}")


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

        # Check if an output file path is set, if not, use a default path
        output_file_path = self.output_file_label.text()
        if not output_file_path or output_file_path == 'No file selected for output, saving at default location.':
            output_file_path = os.path.join(os.path.dirname(__file__), 'output.csv')
            self.output_file_label.setText(output_file_path)

        output_message = 'The data analysis is complete.\n\n' + summary
        output_message += f"\n\nOutput file saved at: {output_file_path}"
        QMessageBox.information(self, 'Analysis Complete', output_message)

        try:
            with open(output_file_path, 'w', newline='') as csvfile:
                fieldnames = ['Type', 'Entity', 'Occurrences', 'Source', 'Context_Snippet', 'Location']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entity, matches in data.items():
                    for match, info in matches.items():
                        locations = ', '.join([f"{filename}:Line {line}" for filename, line in info['filenames']])
                        row = {
                            'Type': entity,
                            'Entity': match,
                            'Occurrences': info['count'],
                            'Source': locations,
                        }
                        if self.include_context_checkbox.isChecked():
                            if len(info['filenames']) > 1:
                                row['Context_Snippet'] = "Identical entity found in multiple input files, manual analysis required"
                            else:
                                row['Context_Snippet'] = '\n\n'.join(info.get('context', []))
                        else:
                            row['Context_Snippet'] = ''
                        row['Location'] = locations
                        writer.writerow(row)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while writing to the file: {str(e)}")

    @staticmethod
    def is_valid_regex(pattern):
        try:
            re.compile(pattern)
            return True
        except re.error:
            return False

class ClickableLabel(QLabel):
    clicked = pyqtSignal()  # Signal to handle the click event

    def __init__(self, text, parent=None):
        super().__init__(text, parent)
        self.setStyleSheet("text-decoration: underline; color: blue;")
        self.setCursor(Qt.PointingHandCursor)

    def mousePressEvent(self, event):
        self.clicked.emit()  # Emit the clicked signal

def main():
    app = QApplication([])
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
