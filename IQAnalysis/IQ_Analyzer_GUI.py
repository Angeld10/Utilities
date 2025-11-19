import sys
import os
import subprocess
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                            QHBoxLayout, QLabel, QComboBox, QSpinBox, 
                            QCheckBox, QPushButton, QTextEdit, QTabWidget, 
                            QFormLayout, QFrame, QMessageBox)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont

class Worker(QThread):
    output_received = pyqtSignal(str)
    finished = pyqtSignal()
    
    def __init__(self, command):
        super().__init__()
        self.command = command
        self.process = None
        self.is_running = True

    def run(self):
        # Merge stdout and stderr
        self.process = subprocess.Popen(
            self.command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            creationflags=subprocess.CREATE_NO_WINDOW if sys.platform == 'win32' else 0
        )

        while self.is_running:
            line = self.process.stdout.readline()
            if not line and self.process.poll() is not None:
                break
            if line:
                self.output_received.emit(line)

        if self.process.poll() is None:
            self.process.terminate()
        
        self.finished.emit()

    def stop(self):
        self.is_running = False
        if self.process:
            self.process.terminate()

class DropArea(QLabel):
    file_dropped = pyqtSignal(str)

    def __init__(self):
        super().__init__()
        self.setText("Drag & Drop PCAP File Here")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setStyleSheet("""
            QLabel {
                border: 2px dashed #aaa;
                border-radius: 10px;
                background-color: #f0f0f0;
                color: #555;
                font-size: 16px;
                font-weight: bold;
            }
            QLabel:hover {
                background-color: #e0e0e0;
                border-color: #888;
            }
        """)
        self.setAcceptDrops(True)
        self.setMinimumHeight(100)

    def dragEnterEvent(self, event):
        if event.mimeData().hasUrls():
            event.accept()
        else:
            event.ignore()

    def dropEvent(self, event):
        files = [u.toLocalFile() for u in event.mimeData().urls()]
        if files:
            # Take the first file
            self.file_dropped.emit(files[0])

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("5G NR IQ Analyzer")
        self.resize(700, 600)
        
        self.selected_file = None
        self.worker = None
        self.current_output_section = "Console" # Console, Stats, Metadata

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # 1. Drop Zone
        self.drop_area = DropArea()
        self.drop_area.file_dropped.connect(self.on_file_dropped)
        main_layout.addWidget(self.drop_area)

        # 2. Configuration Controls
        config_group = QFrame()
        config_group.setFrameShape(QFrame.Shape.StyledPanel)
        config_layout = QFormLayout(config_group)

        # Compression Type
        self.combo_compression = QComboBox()
        self.combo_compression.addItems(["BFP", "Uncompressed"])
        self.combo_compression.setCurrentText("BFP") # Default
        config_layout.addRow("Compression Type:", self.combo_compression)

        # Bitwidth
        self.spin_bitwidth = QSpinBox()
        self.spin_bitwidth.setRange(8, 16)
        self.spin_bitwidth.setValue(9)
        config_layout.addRow("Bitwidth:", self.spin_bitwidth)

        # Interactive Plots
        self.check_interactive = QCheckBox("Show Interactive Plots")
        self.check_interactive.setChecked(True)
        config_layout.addRow("", self.check_interactive)
        
        # Max Samples
        self.spin_max_samples = QSpinBox()
        self.spin_max_samples.setRange(0, 100000000)
        self.spin_max_samples.setValue(0)
        self.spin_max_samples.setSpecialValueText("All")
        config_layout.addRow("Max Samples:", self.spin_max_samples)

        # Symbol Range Group (Optional)
        self.spin_start_symbol = QSpinBox()
        self.spin_start_symbol.setRange(-1, 100000)
        self.spin_start_symbol.setValue(-1)
        self.spin_start_symbol.setSpecialValueText("None")
        
        self.spin_end_symbol = QSpinBox()
        self.spin_end_symbol.setRange(-1, 100000)
        self.spin_end_symbol.setValue(-1)
        self.spin_end_symbol.setSpecialValueText("None")

        self.spin_num_symbols = QSpinBox()
        self.spin_num_symbols.setRange(0, 100000)
        self.spin_num_symbols.setValue(0)
        self.spin_num_symbols.setSpecialValueText("None")

        config_layout.addRow("Start Symbol:", self.spin_start_symbol)
        config_layout.addRow("End Symbol:", self.spin_end_symbol)
        config_layout.addRow("Number of Symbols:", self.spin_num_symbols)

        main_layout.addWidget(config_group)

        # 3. Run Button
        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.setHeight = 40
        self.btn_run.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;")
        self.btn_run.clicked.connect(self.run_analysis)
        self.btn_run.setEnabled(False) # Disabled until file selected
        main_layout.addWidget(self.btn_run)

        # 4. Output Console (Tabs)
        self.tabs = QTabWidget()
        
        self.txt_console = QTextEdit()
        self.txt_console.setReadOnly(True)
        self.tabs.addTab(self.txt_console, "Console")
        
        self.txt_report = QTextEdit()
        self.txt_report.setReadOnly(True)
        self.txt_report.setFont(QFont("Courier New", 9))
        self.tabs.addTab(self.txt_report, "Report")
        
        main_layout.addWidget(self.tabs)

    def on_file_dropped(self, file_path):
        self.selected_file = file_path
        self.drop_area.setText(f"Selected File:\n{os.path.basename(file_path)}")
        self.drop_area.setStyleSheet("""
            QLabel {
                border: 2px solid #4CAF50;
                border-radius: 10px;
                background-color: #e8f5e9;
                color: #2e7d32;
                font-size: 16px;
                font-weight: bold;
            }
        """)
        self.btn_run.setEnabled(True)

    def run_analysis(self):
        if not self.selected_file:
            return

        # Clear previous output
        self.txt_console.clear()
        self.txt_report.clear()
        self.current_output_section = "Console"
        self.tabs.setCurrentIndex(0)

        # Construct command
        cmd = [sys.executable, 'PCAP_Analyzer_WS.py', self.selected_file]
        
        # Compression settings
        if self.combo_compression.currentText() == "BFP":
            cmd.append('--force-bfp')
            cmd.extend(['--bfp-bitwidth', str(self.spin_bitwidth.value())])

        
        if self.check_interactive.isChecked():
            cmd.append('--show-plots')
            
        if self.spin_max_samples.value() > 0:
            cmd.extend(['--samples', str(self.spin_max_samples.value())])
            
        if self.spin_start_symbol.value() >= 0:
             cmd.extend(['--start-symbol', str(self.spin_start_symbol.value())])
             
        if self.spin_end_symbol.value() >= 0:
             cmd.extend(['--end-symbol', str(self.spin_end_symbol.value())])
             
        if self.spin_num_symbols.value() > 0:
             cmd.extend(['--symbols', str(self.spin_num_symbols.value())])

        # Disable run button
        self.btn_run.setEnabled(False)
        self.btn_run.setText("Running...")
        
        # Start worker
        self.worker = Worker(cmd)
        self.worker.output_received.connect(self.handle_output)
        self.worker.finished.connect(self.analysis_finished)
        self.worker.start()

    def handle_output(self, line):
        self.txt_console.insertPlainText(line)
        self.txt_console.moveCursor(self.txt_console.textCursor().MoveOperation.End)
        
        # Parse for Stats and Metadata tabs
        # Logic:
        # 1. "PCAP FILE ANALYSIS REPORT" -> Start of Stats
        # 2. "FRAME INFORMATION:" -> Start of Metadata (End of Stats)
        
        clean_line = line.strip()
        
        if "PCAP FILE ANALYSIS REPORT" in clean_line:
            self.current_output_section = "Stats"
        elif "FRAME INFORMATION:" in clean_line:
            self.current_output_section = "Metadata"
        elif "Detected maximum" in clean_line:
            # This is the last line of the report, capture it then stop
            if self.current_output_section in ["Stats", "Metadata"]:
                self.txt_report.insertPlainText(line)
                self.txt_report.moveCursor(self.txt_report.textCursor().MoveOperation.End)
            self.current_output_section = "Console"  # Switch back to console only
            return  # Don't process further
            
        if self.current_output_section in ["Stats", "Metadata"]:
            self.txt_report.insertPlainText(line)
            self.txt_report.moveCursor(self.txt_report.textCursor().MoveOperation.End)

    def analysis_finished(self):
        self.btn_run.setEnabled(True)
        self.btn_run.setText("Run Analysis")
        QMessageBox.information(self, "Analysis Complete", "The analysis has finished.")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

