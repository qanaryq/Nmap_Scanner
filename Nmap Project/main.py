import sys
import subprocess
import re
import requests
import socket
import os
import json
from datetime import datetime
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QMessageBox, QHBoxLayout, QComboBox, QSizePolicy, QStyle)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QIcon
from reportlab.pdfgen import canvas
from openai import OpenAI
from dotenv import load_dotenv

class NmapWorker(QThread):
    finished = pyqtSignal(str, str)  # target, results
    error = pyqtSignal(str)  # error message

    def __init__(self, target):
        super().__init__()
        self.target = target

    def run(self):
        try:
            command = ["nmap", "-sV", "-T4", "-O", self.target]
            result = subprocess.run(command, capture_output=True, text=True)
            if result.returncode == 0:
                self.finished.emit(self.target, result.stdout)
            else:
                self.error.emit(f"Nmap failed: {result.stderr}")
        except Exception as e:
            self.error.emit(f"Nmap error: {str(e)}")

class AIWorker(QThread):
    finished = pyqtSignal(str)  # Changed to expect only the analysis
    error = pyqtSignal(str)

    def __init__(self, api_key, nmap_results):
        super().__init__()
        self.api_key = api_key
        self.nmap_results = nmap_results

    def run(self):
        try:
            client = OpenAI(api_key=self.api_key)
            prompt = (f"Nmap scan results:\n{self.nmap_results}\n"
                     "List possible vulnerabilities with CVEs if known. "
                     "Provide concise technical analysis.")
            
            response = client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": prompt}]
            )
            self.finished.emit(response.choices[0].message.content)  # Single argument
        except Exception as e:
            self.error.emit(f"AI analysis error: {str(e)}")

class SecurityScanner(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowIcon(QIcon("logo.png"))
        # File paths for storage
        self.history_file = "scan_history.json"
        self.results_dir = "scan_results"
        self.cache_dir = "scan_cache"
        self.current_target = None  # Will store the resolved IP
        self.original_target = None  # Will store the original input
        
        # Create directories if they don't exist
        os.makedirs(self.results_dir, exist_ok=True)
        os.makedirs(self.cache_dir, exist_ok=True)
        
        self.init_ui()
        self.load_environment()
        self.load_history()
        self.update_history_combo()  # Initialize the dropdown
        
        self.nmap_worker = None
        self.ai_worker = None
        self.nmap_results = ""
        
    def init_ui(self):
        self.setStyleSheet("""
            QWidget {
                background-color: #2b2b2b;
                color: #e0e0e0;
            }
            QPushButton {
                background-color: #3c3f41;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 5px;
                min-width: 80px;
            }
            QPushButton:hover {
                background-color: #4e5254;
            }
            QPushButton:pressed {
                background-color: #2d2f30;
            }
            QLineEdit, QComboBox, QTextEdit {
                background-color: #3c3f41;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 5px;
            }
            QTextEdit {
                font-family: Consolas, Courier New, monospace;
            }
            QLabel {
                font-weight: bold;
            }
            QComboBox QAbstractItemView {
                background-color: #3c3f41;
                selection-background-color: #4e5254;
            }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(10)

        # Header
        header = QLabel("Security Scanner with AI Analysis")
        header_font = QFont()
        header_font.setPointSize(14)
        header_font.setBold(True)
        header.setFont(header_font)
        header.setAlignment(Qt.AlignCenter)
        header.setStyleSheet("color: #569cd6; margin-bottom: 15px;")
        layout.addWidget(header)

        # Target input section
        input_group = QWidget()
        input_layout = QVBoxLayout(input_group)
        input_layout.setContentsMargins(0, 0, 0, 0)
        
        self.label = QLabel("Target IP Address or Domain:")
        input_layout.addWidget(self.label)

        # Combo box with refresh button
        combo_layout = QHBoxLayout()
        self.history_combo = QComboBox(self)
        self.history_combo.setEditable(True)
        self.history_combo.setInsertPolicy(QComboBox.InsertAtTop)
        self.history_combo.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        combo_layout.addWidget(self.history_combo)

        self.refresh_history_btn = QPushButton("↻", self)
        self.refresh_history_btn.setToolTip("Refresh history")
        self.refresh_history_btn.setFixedSize(30, 30)
        self.refresh_history_btn.setStyleSheet("font-size: 16px;")
        combo_layout.addWidget(self.refresh_history_btn)
        input_layout.addLayout(combo_layout)

        layout.addWidget(input_group)

        # Set the combo box as the main input
        self.target_input = self.history_combo.lineEdit()
        
        # Scan buttons
        btn_group = QWidget()
        btn_layout = QHBoxLayout(btn_group)
        btn_layout.setContentsMargins(0, 0, 0, 0)
        btn_layout.setSpacing(10)

        self.scan_button = QPushButton("Run Nmap Scan", self)
        self.scan_button.setStyleSheet("background-color: #4169e1;")
        btn_layout.addWidget(self.scan_button)

        self.analyze_button = QPushButton("Analyze with AI and Get CVE Details", self)
        self.analyze_button.setStyleSheet("background-color: #008000;")
        self.analyze_button.setEnabled(False)
        btn_layout.addWidget(self.analyze_button)

        layout.addWidget(btn_group)

        # Report buttons
        report_group = QWidget()
        report_layout = QHBoxLayout(report_group)
        report_layout.setContentsMargins(0, 0, 0, 0)
        report_layout.setSpacing(10)
        
        self.txt_report_button = QPushButton("Export Text", self)
        self.txt_report_button.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_DialogSaveButton')))
        report_layout.addWidget(self.txt_report_button)

        self.pdf_report_button = QPushButton("Export PDF", self)
        self.pdf_report_button.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_FileIcon')))
        report_layout.addWidget(self.pdf_report_button)
        
        self.history_button = QPushButton("History", self)
        self.history_button.setIcon(self.style().standardIcon(getattr(QStyle, 'SP_FileDialogDetailedView')))
        report_layout.addWidget(self.history_button)

        layout.addWidget(report_group)

        # Results display
        results_group = QWidget()
        results_layout = QVBoxLayout(results_group)
        results_layout.setContentsMargins(0, 0, 0, 0)

        results_header = QLabel("Scan Results:")
        results_header.setStyleSheet("font-weight: bold; margin-bottom: 5px;")
        results_layout.addWidget(results_header)

        self.result_area = QTextEdit(self)
        self.result_area.setReadOnly(True)
        self.result_area.setStyleSheet("""
            QTextEdit {
                background-color: #1e1e1e;
                border: 1px solid #555;
                border-radius: 4px;
                padding: 8px;
                font-family: Consolas, Courier New, monospace;
                font-size: 11px;
            }
        """)
        
        # Set monospace font for better output alignment
        font = QFont("Consolas")
        font.setPointSize(10)
        self.result_area.setFont(font)
        
        # Add line numbers
        self.result_area.setLineWrapMode(QTextEdit.NoWrap)
        
        results_layout.addWidget(self.result_area)
        layout.addWidget(results_group)

        self.setLayout(layout)
        self.setWindowTitle("Security Scanner with AI Analysis")
        self.setGeometry(300, 300, 900, 700)
        
        # Connect signals
        self.scan_button.clicked.connect(self.run_nmap_scan)
        self.analyze_button.clicked.connect(self.analyze_with_ai)
        self.txt_report_button.clicked.connect(self.export_text_report)
        self.pdf_report_button.clicked.connect(self.export_pdf_report)
        self.history_button.clicked.connect(self.show_history)
        self.refresh_history_btn.clicked.connect(self.update_history_combo)
        
        
        
    def update_history_combo(self):
        """Update the history dropdown with current history"""
        self.history_combo.clear()
        self.load_history()  # Reload history in case it changed
        targets = sorted({item['target'] for item in self.scan_history}, reverse=True)
        self.history_combo.addItems(targets)
        
    def load_environment(self):
        try:
            load_dotenv()
            self.api_key = os.getenv("API_KEY")
            if not self.api_key:
                self.show_warning("API Key not found in .env file")
        except Exception as e:
            self.show_error(f"Failed to load environment: {str(e)}")

    def load_history(self):
        """Load scan history from file"""
        self.scan_history = []
        try:
            if os.path.exists(self.history_file):
                with open(self.history_file, 'r') as f:
                    self.scan_history = json.load(f)
        except Exception as e:
            self.show_error(f"Could not load history: {str(e)}")

    def save_to_history(self, target, scan_type):
        """Save target to scan history"""
        entry = {
            'target': target,
            'type': scan_type,
            'timestamp': datetime.now().isoformat()
        }
        
        # Check if target already exists in history
        exists = any(item['target'] == target for item in self.scan_history)
        if not exists:
            self.scan_history.append(entry)
            try:
                with open(self.history_file, 'w') as f:
                    json.dump(self.scan_history, f, indent=2)
                self.update_history_combo()  # Update the dropdown
            except Exception as e:
                self.show_error(f"Could not save history: {str(e)}")

    def get_cache_filename(self, target, file_type):
        """Generate standardized cache filenames"""
        safe_target = target.replace('.', '_').replace(':', '_')
        return f"{self.cache_dir}/{safe_target}_{file_type}.txt"

    def check_cache(self, target):
        """Check if we have cached results for this target"""
        nmap_cache = self.get_cache_filename(target, "nmap")
        ai_cache = self.get_cache_filename(target, "ai")
        
        cached_data = {}
        try:
            if os.path.exists(nmap_cache):
                with open(nmap_cache, 'r') as f:
                    cached_data['nmap'] = f.read()
            
            if os.path.exists(ai_cache):
                with open(ai_cache, 'r') as f:
                    cached_data['ai'] = f.read()
                    
            return cached_data if cached_data else None
        except Exception as e:
            self.show_error(f"Cache read error: {str(e)}")
            return None

    def save_to_cache(self, target, data_type, data):
        """Save results to cache"""
        try:
            cache_file = self.get_cache_filename(target, data_type)
            with open(cache_file, 'w') as f:
                f.write(data)
        except Exception as e:
            self.show_error(f"Could not save to cache: {str(e)}")

    def run_nmap_scan(self):
        target = self.target_input.text().strip()
        if not target:
            self.show_warning("Please enter a valid target (IP or domain)")
            return
            
        # Disable buttons during scan
        self.scan_button.setEnabled(False)
        self.target_input.setEnabled(False)
        self.result_area.append(f"[*] Scanning {target}...\n")
        
        # Store original target (domain or IP)
        self.original_target = target
        
        # Check cache first
        cached = self.check_cache(target)
        if cached and 'nmap' in cached:
            self.result_area.append("[*] Loading Nmap results from cache...\n")
            self.on_nmap_finished(target, cached['nmap'])
            return
        
        # Create and start worker thread
        self.nmap_worker = NmapWorker(target)
        self.nmap_worker.finished.connect(self.on_nmap_finished)
        self.nmap_worker.error.connect(self.on_scan_error)
        self.nmap_worker.start()

    def on_nmap_finished(self, target, results):
        try:
            # Resolve domain to IP if needed
            if not self.is_valid_ip(self.original_target):
                try:
                    target_ip = socket.gethostbyname(self.original_target)
                    self.result_area.append(f"[*] Resolved {self.original_target} to {target_ip}\n")
                    target = target_ip
                except socket.gaierror:
                    self.show_error(f"Could not resolve domain: {self.original_target}")
                    return

            self.current_target = target
            self.nmap_results = results
            
            # Check cache and save results
            cached = self.check_cache(self.current_target)
            if not cached or 'nmap' not in cached:
                self.save_to_cache(self.current_target, "nmap", results)
                self.save_to_history(self.current_target, "nmap")
                
                # Save full results to file
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                result_file = f"{self.results_dir}/{self.original_target}_{self.current_target}_{timestamp}.txt"
                with open(result_file, 'w') as f:
                    f.write(f"Nmap scan results for {self.original_target} ({self.current_target})\n")
                    f.write(results)

            self.result_area.append(results)
            self.result_area.append("\n[*] Nmap scan completed successfully\n")
            self.analyze_button.setEnabled(True)
            
        except Exception as e:
            self.show_error(f"Error processing scan results: {str(e)}")
        finally:
            self.scan_button.setEnabled(True)
            self.target_input.setEnabled(True)

    def analyze_with_ai(self):
        if not hasattr(self, 'current_target') or not self.current_target:
            self.show_warning("No target scanned yet. Run Nmap scan first.")
            return
            
        if not self.api_key:
            self.show_warning("OpenAI API key not configured")
            return

        # Check cache first
        cached = self.check_cache(self.current_target)
        if cached and 'ai' in cached:
            self.ai_analysis = cached['ai']
            self.result_area.append("\n[*] Loading AI analysis from cache...\n")
            self.result_area.append(self.ai_analysis)
            self.process_ai_results()
            return
            
        # Disable buttons during analysis
        self.analyze_button.setEnabled(False)
        self.result_area.append("\n[*] Analyzing with AI...\n")
        
        # Create and start worker thread
        self.ai_worker = AIWorker(self.api_key, self.nmap_results)
        self.ai_worker.finished.connect(self.on_ai_finished)
        self.ai_worker.error.connect(self.on_scan_error)
        self.ai_worker.start()
    
    def on_ai_finished(self, analysis):
        try:
            self.ai_analysis = analysis
            self.save_to_cache(self.current_target, "ai", analysis)
            
            # Save analysis to file
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            analysis_file = f"{self.results_dir}/{self.original_target}_{self.current_target}_analysis_{timestamp}.txt"
            with open(analysis_file, 'w') as f:
                f.write(f"AI Analysis for {self.original_target} ({self.current_target})\n")
                f.write(analysis)
            
            self.result_area.append(analysis)
            self.result_area.append("\n[*] AI analysis completed\n")
            self.process_ai_results()
            
        except Exception as e:  
            self.show_error(f"Error processing AI results: {str(e)}")
        finally:
            self.analyze_button.setEnabled(True)

    def process_ai_results(self):
        """Common processing for both cached and fresh AI results"""
        # Extract CVEs
        self.cves = re.findall(r'CVE-\d{4}-\d{4,7}', self.ai_analysis)
        if self.cves:
            self.result_area.append("\n=== CVE Details ===\n")
            for cve in self.cves:
                info = self.fetch_cve_info(cve)
                self.result_area.append(info + "\n")
            self.result_area.append("\n")
        
        self.txt_report_button.setEnabled(True)
        self.pdf_report_button.setEnabled(True)

    def on_scan_error(self, error_msg):
        self.show_error(error_msg)
        self.scan_button.setEnabled(True)
        self.analyze_button.setEnabled(True)
        self.target_input.setEnabled(True)

    def show_history(self):
        """Display scan history in the results area"""
        self.result_area.append("\n=== Scan History ===\n")
        if not self.scan_history:
            self.result_area.append("No history available\n")
            return
            
        for i, entry in enumerate(self.scan_history, 1):
            self.result_area.append(
                f"{i}. {entry['target']} ({entry['type']}) - {entry['timestamp']}\n"
            )

    def export_text_report(self):
        try:
            filename = "security_report.txt"
            with open(filename, "w", encoding="utf-8") as f:
                f.write("=== Security Scan Report ===\n\n")
                f.write("=== Nmap Scan Results ===\n")
                f.write(self.nmap_results + "\n\n")
                f.write("=== AI Vulnerability Analysis ===\n")
                f.write(self.ai_analysis + "\n\n")
                
                if hasattr(self, 'cves') and self.cves:
                    f.write("=== CVE Details ===\n")
                    for cve in self.cves:
                        info = self.fetch_cve_info(cve)
                        f.write(info + "\n\n")
            
            self.show_info(f"Report saved as {filename}")
        except Exception as e:
            self.show_error(f"Error saving text report: {str(e)}")

    def export_pdf_report(self):
        try:
            filename = "security_report.pdf"
            c = canvas.Canvas(filename)
            
            # PDF constants
            width, height = 612, 792  # Letter size (8.5x11 inches in points)
            margin = 72
            line_height = 14
            y_position = height - margin
            page_number = 1  # Initialize page number
            
            # Set font
            c.setFont("Courier", 10)
            
            def add_header():
                """Helper function to add header to each page"""
                nonlocal y_position
                c.setFont("Helvetica-Bold", 16)
                c.drawString(margin, height - margin + 10, "Security Scan Report")
                c.setFont("Helvetica", 10)
                c.drawString(margin, height - margin - 10, 
                            f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
                c.line(margin, height - margin - 20, width - margin, height - margin - 20)
                y_position = height - margin - 40  # Reset y_position after header
            
            # Add first header
            add_header()
            
            # Helper function to add wrapped text
            def add_wrapped_text(text, style="Courier", size=10, is_bold=False):
                nonlocal y_position, page_number
                c.setFont(style + ("-Bold" if is_bold else ""), size)
                
                # Split text into paragraphs
                paragraphs = text.split('\n')
                
                for paragraph in paragraphs:
                    words = paragraph.split(' ')
                    line = []
                    
                    for word in words:
                        test_line = ' '.join(line + [word])
                        if c.stringWidth(test_line) < (width - 2*margin):
                            line.append(word)
                        else:
                            if y_position < margin + line_height:
                                c.showPage()
                                page_number += 1
                                add_header()
                            
                            c.drawString(margin, y_position, ' '.join(line))
                            y_position -= line_height
                            line = [word]
                    
                    # Write remaining words
                    if line:
                        if y_position < margin + line_height:
                            c.showPage()
                            page_number += 1
                            add_header()
                        
                        c.drawString(margin, y_position, ' '.join(line))
                        y_position -= line_height
                
                # Add extra space after paragraph
                y_position -= line_height/2
            
            # Add Nmap results
            c.setFont("Helvetica-Bold", 12)
            c.drawString(margin, y_position, "Nmap Scan Results:")
            y_position -= line_height * 1.5
            
            if hasattr(self, 'nmap_results'):
                add_wrapped_text(self.nmap_results)
            
            # Add AI analysis
            c.showPage()
            page_number += 1
            add_header()
            
            c.setFont("Helvetica-Bold", 12)
            c.drawString(margin, y_position, "AI Vulnerability Analysis:")
            y_position -= line_height * 1.5
            
            if hasattr(self, 'ai_analysis'):
                add_wrapped_text(self.ai_analysis)
            
            # Add CVE details if available
            if hasattr(self, 'ai_analysis'):
                cves_in_analysis = re.findall(r'CVE-\d{4}-\d{4,7}', self.ai_analysis)
                if cves_in_analysis:
                    c.showPage()
                    page_number += 1
                    add_header()
                    
                    c.setFont("Helvetica-Bold", 12)
                    c.drawString(margin, y_position, "CVE Details:")
                    y_position -= line_height * 1.5
                    
                    for cve in set(cves_in_analysis):
                        info = self.fetch_cve_info(cve)
                        add_wrapped_text(info, "Helvetica", 10)
                        y_position -= line_height/2
            
            c.save()
            self.show_info(f"PDF report saved as {filename}")
        except Exception as e:
            self.show_error(f"Error saving PDF report: {str(e)}")

    def fetch_cve_info(self, cve_id, format='string'):
        try:
            # Try Vulners API first
            url = f"https://vulners.com/api/v3/search/id/?id={cve_id}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                # Check if we got valid data
                if data.get("result") == "OK" and data.get("data", {}).get("documents", {}).get(cve_id):
                    cve_data = data["data"]["documents"][cve_id]
                    return self._format_cve_info(cve_id, cve_data, format)
            
            return f"{cve_id}: No vulnerability data available from any source"
            
        except requests.exceptions.RequestException as e:
            return f"{cve_id}: Network error - {str(e)}"
        except Exception as e:
            return f"{cve_id}: Processing error - {str(e)}"

    def _format_cve_info(self, cve_id, cve_data, format):
        """Format Vulners API response"""
        info = {
            "id": cve_id,
            "title": cve_data.get("title", "No title available"),
            "description": cve_data.get("description", "No description available"),
            "cvss": {
                "v3_score": cve_data.get("cvss", {}).get("score", "N/A"),
                "v3_severity": cve_data.get("cvss", {}).get("severity", "N/A"),
                "v3_vector": cve_data.get("cvss", {}).get("vector", "N/A")
            },
            "published": cve_data.get("published", "Unknown date"),
            "references": cve_data.get("references", [])
        }
        
        if format == 'dict':
            return info
        
        return self._format_as_text(info)

    def _format_as_text(self, info):
        """Common text formatting for all sources"""
        text =  f"=== {info['id']} ===\n"
        text += f"Title: {info['title']}\n"
        text += f"Description: {info['description']}\n"
        text += f"CVSS v3 Score: {info['cvss']['v3_score']} ({info['cvss']['v3_severity']})\n"
        text += f"Vector: {info['cvss']['v3_vector']}\n"
        text += f"Published: {info['published']}\n"
        
        if info['references']:
            text += "References:\n- " + "\n- ".join(ref for ref in info['references'] if ref) + "\n"
        
        return text

    def is_valid_ip(self, address):
        try:
            socket.inet_aton(address)
            return True
        except socket.error:
            return False

    def show_error(self, message):
        QMessageBox.critical(self, "Error", message)
        self.result_area.append(f"[!] ERROR: {message}\n")

    def show_warning(self, message):
        QMessageBox.warning(self, "Warning", message)
        self.result_area.append(f"[!] WARNING: {message}\n")

    def show_info(self, message):
        QMessageBox.information(self, "Information", message)
        self.result_area.append(f"[*] INFO: {message}\n")

if __name__ == '__main__':
    app = QApplication(sys.argv)
    scanner = SecurityScanner()
    scanner.show()
    sys.exit(app.exec_())