from collections import defaultdict
import bisect
import sys
import os
import re
import csv
import logging
import yaml 
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

    def __init__(self, file_paths, selected_entities, regex_pattern, entities, include_context, mainWindow):
        super().__init__()
        self.file_paths = file_paths
        self.selected_entities = selected_entities
        self.regex_pattern = regex_pattern
        self.entities = entities
        self.include_context = include_context
        self.mainWindow = mainWindow
        self.context_size = 2  # Hardcoded context size

    def run(self):
        result = defaultdict(lambda: defaultdict(lambda: {'count': 0, 'filenames': [], 'context': []}))
        for file_path in self.file_paths:
            with open(file_path, 'r', encoding='utf-8') as file:
                content = file.readlines()

            for entity, properties in self.entities.items():
                if entity in self.selected_entities:
                    regex = properties['regex']
                    for match in re.finditer(regex, ''.join(content), re.MULTILINE):
                        match_text = match.group()
                        line_number = self.get_line_number(match, content)
                        context_snippet = self.extract_context(content, line_number)
                        result[entity][match_text]['count'] += 1
                        result[entity][match_text]['filenames'].append((os.path.basename(file_path), line_number))
                        result[entity][match_text]['context'].append(context_snippet)

        self.analysis_complete.emit(result)

    def get_line_number(self, match, content):
        start_pos = match.start()
        current_pos = 0
        for i, line in enumerate(content):
            current_pos += len(line)
            if current_pos >= start_pos:
                return i + 1  # Line numbers start at 1
        return -1  # In case line number is not found

    def extract_context(self, content, line_number):
        start_line = max(0, line_number - 1 - self.context_size)
        end_line = min(line_number + self.context_size, len(content))
        return ''.join(content[start_line:end_line])

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.global_csv_delimiter = None  # Initialize the global delimiter
        self.setWindowTitle('Data Analyzer')
        self.setFixedSize(800, 600)
        self.file_paths = []

        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        self.main_layout = QVBoxLayout(central_widget)
        output_format_layout = QHBoxLayout()
        context_layout = QHBoxLayout()

        self.file_path_label = QLabel('No file selected for analysis')
        self.file_path_button = QPushButton('Select File for Analysis')
        self.file_path_button.clicked.connect(self.select_analysis_file)

        self.output_file_label = QLabel('No file selected for output, saving at default location.')

        self.output_format_combobox = QComboBox()
        self.output_format_combobox.addItems(["ODS + CSV", "CSV"])
        output_format_layout.addWidget(QLabel("Choose output file format. ODS has highliting for context."))
        output_format_layout.addWidget(self.output_format_combobox)

        # Button for selecting the output file
        self.output_file_button = QPushButton('Select output file location')
        self.output_file_button.clicked.connect(self.select_output_file)

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
        self.include_context_checkbox.setChecked(True)
        context_layout.addWidget(self.include_context_checkbox)


        self.bottomline_layout = QHBoxLayout()

        self.link_label = QLabel()
        self.link_label.setText('<a href="https://github.com/overcuriousity/analyze_export">github-repo</a>')
        self.link_label.setOpenExternalLinks(True)
        self.link_label.linkActivated.connect(self.open_browser)
        self.bottomline_layout.addWidget(self.link_label)
        
        self.display_regex_button = QPushButton('Display Regex Library...')
        self.display_regex_button.clicked.connect(self.display_regex_library)
        self.bottomline_layout.addWidget(self.display_regex_button)

        self.exit_button = QPushButton('Exit')
        self.exit_button.clicked.connect(self.close)
        self.bottomline_layout.addWidget(self.exit_button)

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
        self.main_layout.addLayout(self.bottomline_layout)

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

            self.global_csv_delimiter = None
            self.analysis_thread = AnalysisThread(self.file_paths, selected_entities, regex_pattern, self.entities, self.include_context_checkbox.isChecked(), self)
            self.analysis_thread.analysis_complete.connect(self.analysis_complete)
            self.analysis_thread.start()
        except Exception as e:
            QMessageBox.critical(self, 'Error', f"An error occurred while starting the analysis: {str(e)}")
            logging.error(f"An error occurred while starting the analysis: {str(e)}")


    def get_csv_delimiter(self, file_path):
        if self.global_csv_delimiter is not None:
            return self.global_csv_delimiter

        delimiter = self.analysis_thread.autodetect_csv_delimiter(file_path)
        if delimiter:
            return delimiter

        delimiter, apply_to_all = self.prompt_for_delimiter()
        if delimiter is not None:
            if apply_to_all:
                self.global_csv_delimiter = delimiter  # Set the global delimiter
            return delimiter
        return None


    def prompt_for_delimiter(self):
        dialog = DelimiterDialog(self)
        if dialog.exec_() == QDialog.Accepted:
            delimiter, apply_to_all = dialog.getInputs()
            return delimiter, apply_to_all
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
        output_message += f"\n\nOutput file saved at: {output_file_path if selected_format == 'CSV' else ods_file_path if selected_format == 'ODS + CSV' else 'Unknown'}"
        QMessageBox.information(self, 'Analysis Complete', output_message)

    def write_csv(self, data, output_file_path):
        try:
            with open(output_file_path, 'w', newline='', encoding='utf-8') as csvfile:
                fieldnames = ['Type', 'Entity', 'Occurrences', 'Source', 'Context_Snippet']
                writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
                writer.writeheader()
                for entity, matches in data.items():
                    for match, info in matches.items():
                        locations = ', '.join(f'{filename}, line {line}' for filename, line in info['filenames'])
                        row = {
                            'Type': entity,
                            'Entity': match,
                            'Occurrences': info['count'],
                            'Source': locations,
                            'Context_Snippet': '\n\n'.join(info['context'])
                        }
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

            # Add header row
            header_row = TableRow()
            table.addElement(header_row)
            for header in ['Type', 'Entity', 'Occurrences', 'Source', 'Context_Snippet']:
                header_cell = TableCell()
                header_row.addElement(header_cell)
                header_cell.addElement(P(text=header))

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
                            logging.debug(f"Processing Context_Snippet: {cell_text}")
                            highlighted_elements = self.highlight_text(cell_text, row['Entity'], red_style)
                            for element in highlighted_elements:
                                p.addElement(element)
                            logging.debug(f"Highlighted elements added for entity {row['Entity']}")
                        else:
                            p.addText(cell_text)
                        tc.addElement(p)

            spreadsheet.save(ods_file_path)
            logging.debug("ODS file saved successfully.")
        except Exception as e:
            logging.error(f"An error occurred while converting to ODS file: {str(e)}")
            QMessageBox.critical(self, 'Error', f"An error occurred while converting to ODS file: {str(e)}")


    def highlight_text(self, text, entity, red_style):
        # Split the entity into words
        entity_words = entity.split()
        # Create a regex pattern to match any of the words in the entity
        pattern = '|'.join(map(re.escape, entity_words))
        start = 0
        elements = []
        for match in re.finditer(pattern, text, flags=re.IGNORECASE):
            before_match = text[start:match.start()]
            match_text = text[match.start():match.end()]

            # Log the highlighting process
            logging.debug(f"Highlighting '{match_text}' in context: '{before_match}[{match_text}]'")

            elements.append(Span(text=before_match))
            red_span = Span(stylename=red_style)
            red_span.addText(match_text)
            elements.append(red_span)

            start = match.end()

        remaining_text = text[start:]
        elements.append(Span(text=remaining_text))
        return elements
    
    def display_regex_library(self):
        script_directory = os.path.dirname(os.path.abspath(__file__))
        regex_file_path = os.path.join(script_directory, "entities.yaml")
        QDesktopServices.openUrl(QUrl.fromLocalFile(regex_file_path))
    
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
