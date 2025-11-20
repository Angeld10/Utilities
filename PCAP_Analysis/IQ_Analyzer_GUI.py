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

        # 1. Drop Zone with Browse Button
        drop_browse_layout = QHBoxLayout()
        
        self.drop_area = DropArea()
        self.drop_area.file_dropped.connect(self.on_file_dropped)
        drop_browse_layout.addWidget(self.drop_area, stretch=3)
        
        self.btn_browse = QPushButton("Browse...")
        self.btn_browse.setStyleSheet("background-color: #2196F3; color: white; font-weight: bold; padding: 10px;")
        self.btn_browse.clicked.connect(self.browse_file)
        drop_browse_layout.addWidget(self.btn_browse, stretch=1)
        
        main_layout.addLayout(drop_browse_layout)

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
        
        start_symbol_layout = QHBoxLayout()
        start_symbol_layout.addWidget(self.spin_start_symbol)
        btn_reset_start = QPushButton("Reset")
        btn_reset_start.setMaximumWidth(60)
        btn_reset_start.clicked.connect(lambda: self.spin_start_symbol.setValue(-1))
        start_symbol_layout.addWidget(btn_reset_start)
        
        self.spin_end_symbol = QSpinBox()
        self.spin_end_symbol.setRange(-1, 100000)
        self.spin_end_symbol.setValue(-1)
        self.spin_end_symbol.setSpecialValueText("None")
        
        end_symbol_layout = QHBoxLayout()
        end_symbol_layout.addWidget(self.spin_end_symbol)
        btn_reset_end = QPushButton("Reset")
        btn_reset_end.setMaximumWidth(60)
        btn_reset_end.clicked.connect(lambda: self.spin_end_symbol.setValue(-1))
        end_symbol_layout.addWidget(btn_reset_end)

        self.spin_num_symbols = QSpinBox()
        self.spin_num_symbols.setRange(0, 100000)
        self.spin_num_symbols.setValue(0)
        self.spin_num_symbols.setSpecialValueText("None")
        
        num_symbols_layout = QHBoxLayout()
        num_symbols_layout.addWidget(self.spin_num_symbols)
        btn_reset_num = QPushButton("Reset")
        btn_reset_num.setMaximumWidth(60)
        btn_reset_num.clicked.connect(lambda: self.spin_num_symbols.setValue(0))
        num_symbols_layout.addWidget(btn_reset_num)

        config_layout.addRow("Start Symbol:", start_symbol_layout)
        config_layout.addRow("End Symbol:", end_symbol_layout)
        config_layout.addRow("Number of Symbols:", num_symbols_layout)

        main_layout.addWidget(config_group)

        # 3. Buttons
        button_layout = QHBoxLayout()
        
        self.btn_run = QPushButton("Run Analysis")
        self.btn_run.setHeight = 40
        self.btn_run.setStyleSheet("background-color: #4CAF50; color: white; font-weight: bold; padding: 10px;")
        self.btn_run.clicked.connect(self.run_analysis)
        self.btn_run.setEnabled(False)
        button_layout.addWidget(self.btn_run)
        
        self.btn_close_plots = QPushButton("Close All Plots")
        self.btn_close_plots.setHeight = 40
        self.btn_close_plots.setStyleSheet("background-color: #f44336; color: white; font-weight: bold; padding: 10px;")
        self.btn_close_plots.clicked.connect(self.close_all_plots)
        button_layout.addWidget(self.btn_close_plots)
        
        main_layout.addLayout(button_layout)

        # 4. Output Console (Tabs)
        self.tabs = QTabWidget()
        
        self.txt_console = QTextEdit()
        self.txt_console.setReadOnly(True)
        self.tabs.addTab(self.txt_console, "Console")
        
        self.txt_report = QTextEdit()
        self.txt_report.setReadOnly(True)
        self.txt_report.setFont(QFont("Courier New", 9))
        self.tabs.addTab(self.txt_report, "Report")
        
        self.txt_metadata = QTextEdit()
        self.txt_metadata.setReadOnly(True)
        self.txt_metadata.setFont(QFont("Courier New", 9))
        self.tabs.addTab(self.txt_metadata, "Metadata")
        
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
    
    def browse_file(self):
        from PyQt6.QtWidgets import QFileDialog
        file_path, _ = QFileDialog.getOpenFileName(
            self,
            "Select PCAP File",
            "",
            "PCAP Files (*.pcap *.pcapng);;All Files (*.*)"
        )
        if file_path:
            self.on_file_dropped(file_path)


    def run_analysis(self):
        if not self.selected_file:
            return

        # Clear previous output
        self.txt_console.clear()
        self.txt_report.clear()
        self.txt_metadata.clear()
        self.current_output_section = "Console"
        self.tabs.setCurrentIndex(0)

        # Construct command
        cmd = [sys.executable, 'PCAP_Analyzer_WS.py', self.selected_file]
        
        # Compression settings - always pass explicitly so globals aren't used
        if self.combo_compression.currentText() == "BFP":
            cmd.append('--bfp')
            cmd.extend(['--bitwidth', str(self.spin_bitwidth.value())])
        else:
            # Explicitly pass uncompressed settings
            cmd.extend(['--bitwidth', '16'])  # 16-bit uncompressed
        
        
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
        elif "iq_separated_eAxC" in clean_line and "_metadata.json" in clean_line:
            # Metadata file has been saved, load it and stats files now
            self.load_metadata_and_stats()
            
        if self.current_output_section in ["Stats", "Metadata"]:
            self.txt_report.insertPlainText(line)
            self.txt_report.moveCursor(self.txt_report.textCursor().MoveOperation.End)

    def load_metadata_and_stats(self):
        """Load metadata.json and stats.txt files and populate tabs"""
        import json
        import glob
        
        # Find metadata.json file (iq_separated_eAxC*_metadata.json)
        metadata_files = glob.glob("iq_separated_eAxC*_metadata.json")
        if metadata_files:
            try:
                with open(metadata_files[0], 'r') as f:
                    metadata = json.load(f)
                    # Pretty print JSON with indentation
                    formatted_json = json.dumps(metadata, indent=2)
                    self.txt_metadata.setPlainText(formatted_json)
            except Exception as e:
                self.txt_metadata.setPlainText(f"Error loading metadata: {e}")
        
        # Find stats.txt file (iq_separated_eAxC*_DL_stats.txt or *_UL_stats.txt)
        stats_files = glob.glob("iq_separated_eAxC*_stats.txt")
        if stats_files:
            try:
                stats_content = ""
                for stats_file in stats_files:
                    with open(stats_file, 'r') as f:
                        stats_content += f"\n{'='*80}\n"
                        stats_content += f"FILE: {os.path.basename(stats_file)}\n"
                        stats_content += f"{'='*80}\n"
                        stats_content += f.read()
                        stats_content += "\n"
                # Append to report tab
                self.txt_report.append(stats_content)
            except Exception as e:
                self.txt_report.append(f"\nError loading stats: {e}")

    def analysis_finished(self):
        self.btn_run.setEnabled(True)
        self.btn_run.setText("Run Analysis")
        QMessageBox.information(self, "Analysis Complete", "The analysis has finished.")
    
    def close_all_plots(self):
        """Close all open matplotlib plot windows"""
        try:
            import subprocess
            import platform
            
            if platform.system() == 'Windows':
                # Use a Python script to enumerate and close matplotlib windows
                # This is safer as it only closes windows created by matplotlib
                close_script = '''
import sys
try:
    import matplotlib.pyplot as plt
    import matplotlib
    # Close all figures in the current matplotlib instance
    plt.close("all")
    # Force matplotlib to quit
    if hasattr(matplotlib, "interactive") and matplotlib.interactive():
        matplotlib.pyplot.ioff()
except:
    pass
'''
                # Run in a separate Python process to access matplotlib's state
                subprocess.run([sys.executable, '-c', close_script], timeout=2)
                
                # Alternative: Use pywinauto or win32gui to close windows by class name
                # But this requires additional dependencies, so we'll use a simpler approach
                try:
                    # Try to import win32gui if available (optional)
                    import win32gui
                    import win32con
                    
                    def close_matplotlib_windows(hwnd, _):
                        # Get window class name
                        class_name = win32gui.GetClassName(hwnd)
                        # Matplotlib windows typically have class name starting with 'Qt' or 'Tk'
                        # and title containing 'Figure'
                        title = win32gui.GetWindowText(hwnd)
                        if 'Figure' in title and ('Qt' in class_name or 'Tk' in class_name):
                            win32gui.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
                        return True
                    
                    win32gui.EnumWindows(close_matplotlib_windows, None)
                except ImportError:
                    # win32gui not available, that's okay
                    pass
            else:
                # On Linux/Mac, close matplotlib figures
                subprocess.run([sys.executable, '-c', 
                               'import matplotlib.pyplot as plt; plt.close("all")'], timeout=2)
            
            QMessageBox.information(self, "Plots Closed", "Attempted to close all matplotlib plot windows.")
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Error closing plots: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())

