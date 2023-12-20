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
    QFileDialog, QMessageBox, QCheckBox, QLineEdit, QComboBox, QDialog, QDialogButtonBox
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QEvent, QUrl
from PyQt5.QtGui import QDesktopServices
from odf.opendocument import OpenDocumentSpreadsheet
from odf.table import Table, TableRow, TableCell
from odf.text import P, Span
from odf.style import Style, TextProperties
import codecs


logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

class AnalysisThread(QThread):
    analysis_complete = pyqtSignal(dict)
    def __init__(self, file_paths, selected_entities, regex_pattern, entities, include_context, context_type, context_size, get_csv_delimiter):
        super().__init__()
        self.file_paths = file_paths
        self.selected_entities = selected_entities
        self.entities = entities
        self.include_context = include_context
        self.context_type = context_type
        self.context_size = int(context_size) if context_size.isdigit() else 0
        self.get_csv_delimiter = get_csv_delimiter
        self.patterns = {}
        for entity in selected_entities:
            if entity == 'Custom':
                self.patterns['Custom'] = re.compile(regex_pattern)
            elif entity in self.entities:
                self.patterns[entity] = re.compile(self.entities[entity]['regex'])
        
        self.data = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'filenames': set()}))

    def run(self):
        for file_path in self.file_paths:
            text, success = self.extract_text_from_file(file_path)  # This now consistently receives a tuple
            if not success:
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
                pdf_reader = PdfFileReader(pdf_file)
                return ' '.join([pdf_reader.getPage(i).extractText() for i in range(pdf_reader.getNumPages())])
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            return None
        
    def extract_text_from_txt(self, file_path):
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as txt_file:
                text_content = txt_file.read()
                return text_content, True
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            return None, False
            
    def extract_text_from_csv(self, file_path, delimiter=None):
        try:
            with codecs.open(file_path, 'r', encoding='utf-8', errors='replace') as csv_file:
                if delimiter is None:
                    sample_data = csv_file.read(1024)
                    csv_file.seek(0)
                    try:
                        dialect = csv.Sniffer().sniff(sample_data)
                        reader = csv.reader(csv_file, dialect)
                    except csv.Error:
                        return None, False  # Return None and a flag indicating failure
                else:
                    reader = csv.reader(csv_file, delimiter=delimiter)

                return ' '.join([' '.join(row) for row in reader]), True
        except Exception as e:
            logging.error(f"Error processing {file_path}: {e}")
            return None, True

    def analyze_data(self, text, filename):
        for entity in self.selected_entities:
            for match in self.patterns[entity].finditer(text):
                match_text = match.group()
                logging.debug(f"Match found: {match_text} in file {filename}")

                start_pos, end_pos = match.start(), match.end()
                data_entry = self.data[entity][match_text]
                data_entry['filenames'].add((filename, start_pos))  # Store filename and start position
                data_entry['count'] += 1

                if self.include_context:
                    # Context extraction based on type
                    context = self.get_context(text, start_pos, end_pos, self.context_type, self.context_size)
                    data_entry.setdefault('context', []).append(context)
                logging.debug(f"Data entry updated: {data_entry}")

    def get_context(self, text, start_pos, end_pos, context_type, context_size):
        if context_type == 'lines':
            return self.get_context_lines(text, start_pos, end_pos, context_size)
        elif context_type == 'words':
            return self.get_context_words(text, start_pos, end_pos, context_size)
        elif context_type == 'characters':
            return self.get_context_characters(text, start_pos, end_pos, context_size)
        elif context_type == 'sentences':
            return self.get_context_sentences(text, start_pos, end_pos, context_size)
        else:
            return "Context type not recognized"


    def find_match_positions(self, text, pattern):
        matches = list(re.finditer(pattern, text))
        if not matches:
            return -1, -1
        start = matches[0].start()
        end = matches[-1].end()
        return start, end
    
    def get_context_lines(self, text, start_pos, end_pos, context_size):
        lines = text.split('\n')
        start_line = end_line = 0

        # Find the line numbers for start_pos and end_pos
        current_pos = 0
        for i, line in enumerate(lines):
            if current_pos <= start_pos < current_pos + len(line):
                start_line = i
            if current_pos <= end_pos <= current_pos + len(line):
                end_line = i
            current_pos += len(line) + 1  # +1 for the newline character

        # Extract context
        start_context = max(0, start_line - context_size)
        end_context = min(len(lines), end_line + context_size + 1)
        return '\n'.join(lines[start_context:end_context])

    def get_context_words(self, text, start_pos, end_pos, context_size):
        words = text.split()
        start_word = end_word = 0

        current_pos = 0
        for i, word in enumerate(words):
            end_current_pos = current_pos + len(word)
            if current_pos <= start_pos < end_current_pos:
                start_word = i
            if current_pos <= end_pos <= end_current_pos:
                end_word = i
            current_pos = end_current_pos + 1  # +1 for space

        start_context = max(0, start_word - context_size)
        end_context = min(len(words), end_word + context_size + 1)

        return ' '.join(words[start_context:end_context])
    
    def get_context_characters(self, text, start_pos, end_pos, context_size):
        start_context = max(0, start_pos - context_size)
        end_context = min(len(text), end_pos + context_size)

        return text[start_context:end_context]

    def get_context_sentences(self, text, start_pos, end_pos, context_size):
        sentences = re.split(r'(?<=[.!?]) +', text)
        start_sentence = end_sentence = 0

        current_pos = 0
        for i, sentence in enumerate(sentences):
            end_current_pos = current_pos + len(sentence)
            if current_pos <= start_pos < end_current_pos:
                start_sentence = i
            if current_pos <= end_pos <= end_current_pos:
                end_sentence = i
            current_pos = end_current_pos + 1  # +1 for space after sentence

        start_context = max(0, start_sentence - context_size)
        end_context = min(len(sentences), end_sentence + context_size + 1)

        return ' '.join(sentences[start_context:end_context])


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle('Data Analyzer')
        self.setFixedSize(800, 600)
        self.file_paths = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.main_layout = QVBoxLayout(central_widget)
        output_format_layout = QHBoxLayout()
        context_layout = QHBoxLayout()


        # File selection for analysis
        self.file_path_label = QLabel('No file selected for analysis')
        self.file_path_button = QPushButton('Select File for Analysis')
        self.file_path_button.clicked.connect(self.select_analysis_file)

        # File selection for output
        self.output_file_label = QLabel('No file selected for output, saving at default location.')

        self.output_format_combobox = QComboBox()
        self.output_format_combobox.addItems(["ODS + CSV", "CSV"])
        output_format_layout.addWidget(QLabel("Choose output file format. ODS has highliting for context."))
        output_format_layout.addWidget(self.output_format_combobox)

        # Button for selecting the output file
        self.output_file_button = QPushButton('Select output file location')
        self.output_file_button.clicked.connect(self.select_output_file)

        # Add the button to the horizontal layout
        output_format_layout.addWidget(self.output_file_button)

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
        self.link_label.setText('<a href="https://debin.org">Feedback-Link</a>')
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_browser)

        self.main_layout.addLayout(context_layout)
        self.main_layout.addWidget(self.file_path_label)
        self.main_layout.addWidget(self.file_path_button)
        self.main_layout.addWidget(self.output_file_label)
        self.main_layout.addLayout(output_format_layout)
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
            self.selected_entity = selected_entities[0] if selected_entities else None

            regex_pattern = self.custom_regex_field.text()
            if regex_pattern and not self.is_valid_regex(regex_pattern):
                QMessageBox.critical(self, 'Error', 'Invalid custom regex pattern.')
                return

            output_file_path = self.output_file_label.text() or 'output.csv'
            context_type = self.context_size_combobox.currentText()
            context_size = self.context_size_input.text()

            self.global_csv_delimiter = None
            self.analysis_thread = AnalysisThread(self.file_paths, selected_entities, regex_pattern, self.entities, self.include_context_checkbox.isChecked(), context_type, context_size, self.get_csv_delimiter)
            self.analysis_thread.analysis_complete.connect(self.analysis_complete)
            self.analysis_thread.start()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while starting the analysis: {str(e)}")
            logging.error(f"An error occurred while starting the analysis: {str(e)}")

    def get_csv_delimiter(self, file_path):
        if self.global_csv_delimiter is not None:
            return self.global_csv_delimiter

        text, success = self.extract_text_from_csv(file_path)
        if text is None and not success:
            delimiter, apply_to_all = self.prompt_for_delimiter()
            if delimiter is not None:
                if apply_to_all:
                    self.global_csv_delimiter = delimiter
                return delimiter
        return None

    def prompt_for_delimiter(self):
        dialog = DelimiterDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            return dialog.getInputs()
        return None, False

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
        selected_format = self.output_format_combobox.currentText()

        default_filename = 'output.csv'
        output_file_path = self.output_file_label.text() or default_filename

        if not output_file_path or output_file_path == 'No file selected for output, saving at default location.':
            output_file_path = os.path.join(os.path.dirname(__file__), default_filename)
            self.output_file_label.setText(output_file_path)

        # Always write CSV
        self.write_csv(data, output_file_path)

        # If ODS is selected, convert the CSV to ODS
        if selected_format == 'ODS + CSV':
            ods_file_path = output_file_path.replace('.csv', '.ods')
            self.convert_csv_to_ods(output_file_path, ods_file_path)

        output_message = 'The data analysis is complete.\n\n' + summary
        output_message += f"\n\nOutput file saved at: {output_file_path if selected_format == 'CSV' else ods_file_path if selected_format == 'ODS + CSV' else xlsx_file_path}"
        QMessageBox.information(self, 'Analysis Complete', output_message)

    def write_csv(self, data, output_file_path): #data expects structure: {entity: {match_text: {'count': int, 'filenames': set, 'context': list}}}
        try:
            with open(output_file_path, 'w', newline='', encoding='utf-8') as csvfile:  # Specify UTF-8 encoding here
                fieldnames = ['Type', 'Entity', 'Occurrences', 'Source', 'Context_Snippet']
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
                        writer.writerow(row)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while writing to the file: {str(e)}")

    def convert_csv_to_ods(self, csv_file_path, ods_file_path):
        try:
            spreadsheet = OpenDocumentSpreadsheet()
            # Create a custom style for the red font
            red_style = Style(name="RedFont", family="text")
            red_style.addElement(TextProperties(color="#ff0000"))
            spreadsheet.automaticstyles.addElement(red_style)

            table = Table(name="Analysis")
            spreadsheet.spreadsheet.addElement(table)

            with open(csv_file_path, 'r', encoding='utf-8') as csv_file:
                reader = csv.DictReader(csv_file)
                for row in reader:
                    tr = TableRow()
                    table.addElement(tr)
                    for header, cell_text in row.items():
                        tc = TableCell()
                        tr.addElement(tc)
                        p = P()

                        if header == 'Context_Snippet':
                            print("Context Snippet:", cell_text)
                            entities_to_highlight = [e.strip() for e in row['Entity'].split(' ')]
                            print("Entities to Highlight:", entities_to_highlight)
                            pattern = '|'.join(map(re.escape, entities_to_highlight))
                            print("Pattern:", pattern)
                            start = 0
                            for match in re.finditer(pattern, cell_text, flags=re.IGNORECASE):
                                before_match = cell_text[start:match.start()]
                                match_text = cell_text[match.start():match.end()]

                                p.addElement(Span(text=before_match))
                                red_span = Span(stylename=red_style)
                                red_span.addText(match_text)
                                p.addElement(red_span)

                                start = match.end()

                            remaining_text = cell_text[start:]
                            p.addElement(Span(text=remaining_text))
                        else:
                            p.addText(cell_text)
                        tc.addElement(p)


            spreadsheet.save(ods_file_path)
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while converting to ODS file: {str(e)}")

    
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

class DelimiterDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enter CSV Delimiter")
        self.layout = QVBoxLayout()
        self.setLayout(self.layout)

        self.label = QLabel("Enter the delimiter used in the CSV file:")
        self.layout.addWidget(self.label)

        self.delimiter_input = QLineEdit(";")
        self.layout.addWidget(self.delimiter_input)

        self.apply_to_all_checkbox = QCheckBox("Set for all CSV Input Files")
        self.layout.addWidget(self.apply_to_all_checkbox)

        self.buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        self.buttons.accepted.connect(self.accept)
        self.buttons.rejected.connect(self.reject)
        self.layout.addWidget(self.buttons)

    def getInputs(self):
        return self.delimiter_input.text(), self.apply_to_all_checkbox.isChecked()


def main():
    app = QApplication([])
    window = MainWindow()
    window.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
