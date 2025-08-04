#!/usr/bin/env python3
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, scrolledtext
import threading
import time
import zipfile
import itertools
import string
import os
from pathlib import Path
import queue
import subprocess
import chardet

class UniversalPasswordCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Universal Password Cracker - Multi-Format Support v4.0")
        self.root.geometry("950x750")
        self.root.resizable(True, True)
        
        # Variables
        self.encrypted_file_path = tk.StringVar()
        self.wordlist_file_path = tk.StringVar()
        self.attack_mode = tk.StringVar(value="dictionary")
        self.charset = tk.StringVar(value="abcdefghijklmnopqrstuvwxyz0123456789")
        self.min_length = tk.IntVar(value=1)
        self.max_length = tk.IntVar(value=6)
        self.is_running = False
        self.stop_attack = False
        self.debug_mode = tk.BooleanVar(value=True)
        self.encoding_mode = tk.StringVar(value="auto")
        
        # Queue for thread communication
        self.result_queue = queue.Queue()
        
        # Check for available libraries
        self.check_libraries()
        
        self.create_widgets()
        self.check_queue()
    
    def check_libraries(self):
        """Check which libraries are available for different file types"""
        self.libraries = {
            'py7zr': False,
            '7zip_cli': False,
            'pypdf2': False,
            'pycryptodome': False,
            'rarfile': False,
            'msoffcrypto': False,
            'chardet': False
        }
        
        # Check py7zr (ZIP/7Z with AES)
        try:
            import py7zr
            self.libraries['py7zr'] = True
        except ImportError:
            pass
        
        # Check 7zip CLI
        try:
            subprocess.run(['7z'], capture_output=True, timeout=5)
            self.libraries['7zip_cli'] = True
        except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.SubprocessError):
            pass
        
        # Check PyPDF2 (PDF files)
        try:
            import PyPDF2
            self.libraries['pypdf2'] = True
        except ImportError:
            pass
        
        # Check pycryptodome (Advanced encryption)
        try:
            from Crypto.Cipher import AES
            self.libraries['pycryptodome'] = True
        except ImportError:
            pass
        
        # Check rarfile (RAR files)
        try:
            import rarfile
            self.libraries['rarfile'] = True
        except ImportError:
            pass
        
        # Check msoffcrypto (Office files)
        try:
            import msoffcrypto
            self.libraries['msoffcrypto'] = True
        except ImportError:
            pass
        
        # Check chardet (encoding detection)
        try:
            import chardet
            self.libraries['chardet'] = True
        except ImportError:
            pass
    
    def create_widgets(self):
        # Main frame
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # File selection section
        ttk.Label(main_frame, text="Encrypted File:", font=("Arial", 11, "bold")).grid(
            row=0, column=0, sticky=tk.W, pady=5)
        
        file_frame = ttk.Frame(main_frame)
        file_frame.grid(row=1, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5)
        file_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(file_frame, textvariable=self.encrypted_file_path, width=50).grid(
            row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(file_frame, text="Browse", command=self.browse_encrypted_file).grid(
            row=0, column=1)
        ttk.Button(file_frame, text="Analyze File", command=self.analyze_file).grid(
            row=0, column=2, padx=(5, 0))
        
        # Library status section
        status_frame = ttk.LabelFrame(main_frame, text="Supported File Types & Libraries", padding="5")
        status_frame.grid(row=2, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5, padx=5)
        status_frame.columnconfigure(0, weight=1)
        status_frame.columnconfigure(1, weight=1)
        
        # Create library status in two columns
        lib_info = [
            ("ZIP/7Z (Standard)", "✅ Built-in zipfile"),
            ("ZIP/7Z (AES)", "✅ Available" if self.libraries['py7zr'] else "❌ pip install py7zr"),
            ("PDF Files", "✅ Available" if self.libraries['pypdf2'] else "❌ pip install PyPDF2"),
            ("RAR Files", "✅ Available" if self.libraries['rarfile'] else "❌ pip install rarfile"),
            ("Office Files", "✅ Available" if self.libraries['msoffcrypto'] else "❌ pip install msoffcrypto-tool"),
            ("7zip CLI", "✅ Available" if self.libraries['7zip_cli'] else "❌ apt install p7zip-full"),
            ("Encoding Detection", "✅ Available" if self.libraries['chardet'] else "❌ pip install chardet"),
            ("Advanced Crypto", "✅ Available" if self.libraries['pycryptodome'] else "❌ pip install pycryptodome")
        ]
        
        for i, (name, status) in enumerate(lib_info):
            col = i % 2
            row = i // 2
            ttk.Label(status_frame, text=f"{name}: {status}", font=("Consolas", 8)).grid(
                row=row, column=col, sticky=tk.W, padx=5, pady=1)
        
        # Encoding selection section
        encoding_frame = ttk.LabelFrame(main_frame, text="Encoding Settings", padding="5")
        encoding_frame.grid(row=3, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=5, padx=5)
        
        ttk.Label(encoding_frame, text="Password Encoding:").grid(row=0, column=0, sticky=tk.W, pady=2)
        encoding_combo = ttk.Combobox(encoding_frame, textvariable=self.encoding_mode, values=[
            "auto", "utf-8", "latin-1", "cp437", "ascii", "cp1252", "iso-8859-1", 
            "windows-1252", "utf-16", "utf-32", "big5", "gb2312", "shift_jis"
        ], state="readonly", width=15)
        encoding_combo.grid(row=0, column=1, sticky=tk.W, padx=(10, 0), pady=2)
        
        ttk.Label(encoding_frame, text="Auto: Detect encoding automatically").grid(row=0, column=2, sticky=tk.W, padx=(20, 0), pady=2)
        
        # Attack mode selection
        ttk.Label(main_frame, text="Attack Mode:", font=("Arial", 11, "bold")).grid(
            row=4, column=0, sticky=tk.W, pady=(15, 5))
        
        mode_frame = ttk.Frame(main_frame)
        mode_frame.grid(row=5, column=0, columnspan=3, sticky=tk.W, pady=5)
        
        ttk.Radiobutton(mode_frame, text="Dictionary Attack", variable=self.attack_mode, 
                       value="dictionary", command=self.on_mode_change).grid(row=0, column=0, padx=(0, 20))
        ttk.Radiobutton(mode_frame, text="Brute Force Attack", variable=self.attack_mode, 
                       value="brute_force", command=self.on_mode_change).grid(row=0, column=1)
        ttk.Checkbutton(mode_frame, text="Debug Mode", variable=self.debug_mode).grid(row=0, column=2, padx=(20, 0))
        
        # Dictionary attack section
        self.dict_frame = ttk.LabelFrame(main_frame, text="Dictionary Attack Settings", padding="5")
        self.dict_frame.grid(row=6, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10, padx=5)
        self.dict_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.dict_frame, text="Wordlist File:").grid(row=0, column=0, sticky=tk.W, pady=5)
        
        wordlist_frame = ttk.Frame(self.dict_frame)
        wordlist_frame.grid(row=0, column=1, columnspan=2, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        wordlist_frame.columnconfigure(0, weight=1)
        
        ttk.Entry(wordlist_frame, textvariable=self.wordlist_file_path).grid(
            row=0, column=0, sticky=(tk.W, tk.E), padx=(0, 5))
        ttk.Button(wordlist_frame, text="Browse", command=self.browse_wordlist_file).grid(
            row=0, column=1)
        ttk.Button(wordlist_frame, text="Preview", command=self.preview_wordlist).grid(
            row=0, column=2, padx=(5, 0))
        
        # Brute force section
        self.brute_frame = ttk.LabelFrame(main_frame, text="Brute Force Attack Settings", padding="5")
        self.brute_frame.grid(row=7, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10, padx=5)
        self.brute_frame.columnconfigure(1, weight=1)
        
        ttk.Label(self.brute_frame, text="Character Set:").grid(row=0, column=0, sticky=tk.W, pady=5)
        charset_entry = ttk.Entry(self.brute_frame, textvariable=self.charset, width=40)
        charset_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        
        # Preset buttons for character sets
        preset_frame = ttk.Frame(self.brute_frame)
        preset_frame.grid(row=1, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        ttk.Button(preset_frame, text="ASCII", 
                  command=lambda: self.charset.set("abcdefghijklmnopqrstuvwxyz0123456789")).grid(row=0, column=0, padx=(0, 3))
        ttk.Button(preset_frame, text="Alpha+Num", 
                  command=lambda: self.charset.set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")).grid(row=0, column=1, padx=3)
        ttk.Button(preset_frame, text="Symbols", 
                  command=lambda: self.charset.set("!@#$%^&*()_+-=[]{}|;:,.<>?")).grid(row=0, column=2, padx=3)
        ttk.Button(preset_frame, text="All Printable", 
                  command=lambda: self.charset.set(string.printable.strip())).grid(row=0, column=3, padx=(3, 0))
        
        ttk.Label(self.brute_frame, text="Min Length:").grid(row=2, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(self.brute_frame, from_=1, to=15, textvariable=self.min_length, width=10).grid(
            row=2, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        ttk.Label(self.brute_frame, text="Max Length:").grid(row=3, column=0, sticky=tk.W, pady=5)
        ttk.Spinbox(self.brute_frame, from_=1, to=15, textvariable=self.max_length, width=10).grid(
            row=3, column=1, sticky=tk.W, pady=5, padx=(10, 0))
        
        # Control buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=8, column=0, columnspan=3, pady=15)
        
        self.start_button = ttk.Button(button_frame, text="Start Attack", command=self.start_attack)
        self.start_button.grid(row=0, column=0, padx=5)
        
        self.stop_button = ttk.Button(button_frame, text="Stop Attack", command=self.stop_attack_func, state="disabled")
        self.stop_button.grid(row=0, column=1, padx=5)
        
        ttk.Button(button_frame, text="Clear Log", command=self.clear_log).grid(row=0, column=2, padx=5)
        
        # Progress section
        progress_frame = ttk.LabelFrame(main_frame, text="Progress", padding="5")
        progress_frame.grid(row=9, column=0, columnspan=3, sticky=(tk.W, tk.E), pady=10, padx=5)
        progress_frame.columnconfigure(0, weight=1)
        
        self.progress_var = tk.StringVar(value="Ready to start...")
        ttk.Label(progress_frame, textvariable=self.progress_var).grid(row=0, column=0, sticky=tk.W, pady=2)
        
        self.attempts_var = tk.StringVar(value="Attempts: 0")
        ttk.Label(progress_frame, textvariable=self.attempts_var).grid(row=1, column=0, sticky=tk.W, pady=2)
        
        self.progress_bar = ttk.Progressbar(progress_frame, mode='indeterminate')
        self.progress_bar.grid(row=2, column=0, sticky=(tk.W, tk.E), pady=5)
        
        # Results section
        results_frame = ttk.LabelFrame(main_frame, text="Results & Log", padding="5")
        results_frame.grid(row=10, column=0, columnspan=3, sticky=(tk.W, tk.E, tk.N, tk.S), pady=10, padx=5)
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)
        main_frame.rowconfigure(10, weight=1)
        
        self.results_text = scrolledtext.ScrolledText(results_frame, height=10, width=80, font=("Consolas", 9))
        self.results_text.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Initial mode setup
        self.on_mode_change()
    
    def browse_encrypted_file(self):
        filename = filedialog.askopenfilename(
            title="Select Encrypted File",
            filetypes=[
                ("All Supported", "*.zip;*.7z;*.rar;*.pdf;*.docx;*.xlsx;*.pptx"),
                ("ZIP files", "*.zip"),
                ("7Z files", "*.7z"), 
                ("RAR files", "*.rar"),
                ("PDF files", "*.pdf"),
                ("Office files", "*.docx;*.xlsx;*.pptx;*.doc;*.xls;*.ppt"),
                ("All files", "*.*")
            ]
        )
        if filename:
            self.encrypted_file_path.set(filename)
    
    def browse_wordlist_file(self):
        filename = filedialog.askopenfilename(
            title="Select Wordlist File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if filename:
            self.wordlist_file_path.set(filename)
    
    def detect_encoding(self, file_path):
        """Detect the encoding of a text file"""
        if not self.libraries['chardet']:
            return 'utf-8'
        
        try:
            import chardet
            with open(file_path, 'rb') as f:
                raw_data = f.read(10000)  # Read first 10KB
                result = chardet.detect(raw_data)
                encoding = result.get('encoding', 'utf-8')
                confidence = result.get('confidence', 0)
                
                if self.debug_mode.get():
                    self.queue_message("log", f"🔍 Detected encoding: {encoding} (confidence: {confidence:.2f})", "debug")
                
                return encoding if confidence > 0.7 else 'utf-8'
        except Exception:
            return 'utf-8'
    
    def get_encoding_list(self):
        """Get list of encodings to try based on user selection"""
        if self.encoding_mode.get() == "auto":
            # Try to detect wordlist encoding if it exists
            wordlist_encoding = 'utf-8'
            if self.wordlist_file_path.get() and os.path.exists(self.wordlist_file_path.get()):
                wordlist_encoding = self.detect_encoding(self.wordlist_file_path.get())
            
            # Return comprehensive encoding list
            return [wordlist_encoding, 'utf-8', 'latin-1', 'cp437', 'ascii', 'cp1252', 'iso-8859-1', 'windows-1252']
        else:
            return [self.encoding_mode.get()]
    
    def analyze_file(self):
        """Comprehensive file analysis"""
        file_path = self.encrypted_file_path.get()
        if not file_path or not os.path.exists(file_path):
            messagebox.showerror("Error", "Please select a valid file first")
            return
        
        try:
            file_ext = Path(file_path).suffix.lower()
            file_size = os.path.getsize(file_path)
            
            analysis_text = f"📁 File Analysis Report\n"
            analysis_text += f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            analysis_text += f"File: {Path(file_path).name}\n"
            analysis_text += f"Extension: {file_ext}\n"
            analysis_text += f"Size: {file_size:,} bytes ({file_size/1024/1024:.2f} MB)\n\n"
            
            # Analyze based on file type
            if file_ext == '.zip':
                analysis_text += self.analyze_zip(file_path)
            elif file_ext == '.7z':
                analysis_text += self.analyze_7z(file_path)
            elif file_ext == '.rar':
                analysis_text += self.analyze_rar(file_path)
            elif file_ext == '.pdf':
                analysis_text += self.analyze_pdf(file_path)
            elif file_ext in ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt']:
                analysis_text += self.analyze_office(file_path)
            else:
                analysis_text += f"❓ Unknown file type: {file_ext}\n"
                analysis_text += f"Will attempt generic password testing...\n"
            
            # Show magic bytes
            try:
                with open(file_path, 'rb') as f:
                    magic_bytes = f.read(16)
                    hex_bytes = ' '.join([f'{b:02X}' for b in magic_bytes])
                    analysis_text += f"\n🔍 Magic Bytes: {hex_bytes}\n"
            except Exception as e:
                analysis_text += f"\n⚠️ Could not read magic bytes: {e}\n"
            
            messagebox.showinfo("File Analysis", analysis_text)
            
        except Exception as e:
            messagebox.showerror("Analysis Error", f"Error analyzing file: {e}")
    
    def analyze_zip(self, file_path):
        """Analyze ZIP file"""
        try:
            analysis = "🗜️ ZIP File Analysis:\n"
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                encrypted_files = [f for f in zip_file.infolist() if f.flag_bits & 0x1]
                
                analysis += f"Total files: {len(zip_file.infolist())}\n"
                analysis += f"Encrypted files: {len(encrypted_files)}\n"
                
                if encrypted_files:
                    analysis += "\nEncryption Details:\n"
                    compression_methods = {}
                    for file_info in encrypted_files:
                        comp_type = file_info.compress_type
                        if comp_type not in compression_methods:
                            compression_methods[comp_type] = 0
                        compression_methods[comp_type] += 1
                    
                    compression_names = {
                        0: "Stored (no compression)",
                        8: "Deflated (standard)",
                        12: "BZIP2", 
                        14: "LZMA",
                        99: "AES Encrypted"
                    }
                    
                    for comp_type, count in compression_methods.items():
                        comp_name = compression_names.get(comp_type, f"Unknown ({comp_type})")
                        if comp_type == 99:
                            analysis += f"🔒 {comp_name}: {count} files (Requires py7zr/7zip)\n"
                        elif comp_type in [0, 8]:
                            analysis += f"✅ {comp_name}: {count} files (Supported)\n"
                        else:
                            analysis += f"⚠️ {comp_name}: {count} files (May need py7zr)\n"
                else:
                    analysis += "❌ No encrypted files found!\n"
                    
            return analysis
        except Exception as e:
            return f"❌ ZIP analysis failed: {e}\n"
    
    def analyze_7z(self, file_path):
        """Analyze 7Z file"""
        analysis = "🗜️ 7Z File Analysis:\n"
        if self.libraries['py7zr']:
            try:
                import py7zr
                with py7zr.SevenZipFile(file_path, mode="r") as archive:
                    file_list = archive.getnames()
                    analysis += f"Files: {len(file_list)}\n"
                    analysis += "🔒 Password protected (detected)\n"
                    analysis += "✅ py7zr available for cracking\n"
            except Exception as e:
                analysis += f"🔒 Likely password protected: {e}\n"
        else:
            analysis += "❌ py7zr not available (pip install py7zr)\n"
        
        return analysis
    
    def analyze_rar(self, file_path):
        """Analyze RAR file"""
        analysis = "🗜️ RAR File Analysis:\n"
        if self.libraries['rarfile']:
            try:
                import rarfile
                with rarfile.RarFile(file_path) as rf:
                    file_list = rf.getnames()
                    analysis += f"Files: {len(file_list)}\n"
                    analysis += "🔒 Password protected (detected)\n"
                    analysis += "✅ rarfile available for cracking\n"
            except Exception as e:
                analysis += f"🔒 Likely password protected: {e}\n"
        else:
            analysis += "❌ rarfile not available (pip install rarfile)\n"
        
        return analysis
    
    def analyze_pdf(self, file_path):
        """Analyze PDF file"""
        analysis = "📄 PDF File Analysis:\n"
        if self.libraries['pypdf2']:
            try:
                import PyPDF2
                with open(file_path, 'rb') as file:
                    pdf_reader = PyPDF2.PdfReader(file)
                    analysis += f"Pages: {len(pdf_reader.pages)}\n"
                    if pdf_reader.is_encrypted:
                        analysis += "🔒 Password protected (confirmed)\n"
                        analysis += "✅ PyPDF2 available for cracking\n"
                    else:
                        analysis += "❌ Not password protected\n"
            except Exception as e:
                analysis += f"⚠️ Analysis error: {e}\n"
        else:
            analysis += "❌ PyPDF2 not available (pip install PyPDF2)\n"
        
        return analysis
    
    def analyze_office(self, file_path):
        """Analyze Microsoft Office file"""
        analysis = "📊 Office File Analysis:\n"
        if self.libraries['msoffcrypto']:
            try:
                import msoffcrypto
                with open(file_path, 'rb') as file:
                    office_file = msoffcrypto.OfficeFile(file)
                    if office_file.is_encrypted():
                        analysis += "🔒 Password protected (confirmed)\n"
                        analysis += "✅ msoffcrypto available for cracking\n"
                    else:
                        analysis += "❌ Not password protected\n"
            except Exception as e:
                analysis += f"⚠️ Analysis error: {e}\n"
        else:
            analysis += "❌ msoffcrypto not available (pip install msoffcrypto-tool)\n"
        
        return analysis
    
    def preview_wordlist(self):
        """Preview wordlist with encoding detection"""
        wordlist_path = self.wordlist_file_path.get()
        if not wordlist_path or not os.path.exists(wordlist_path):
            messagebox.showerror("Error", "Please select a valid wordlist file first")
            return
        
        try:
            # Detect encoding
            detected_encoding = self.detect_encoding(wordlist_path)
            
            with open(wordlist_path, 'r', encoding=detected_encoding, errors='ignore') as f:
                lines = []
                for i, line in enumerate(f):
                    if i >= 10:
                        break
                    clean_line = line.strip()
                    lines.append(f"{i+1}: '{clean_line}' (len: {len(clean_line)})")
                
                f.seek(0)
                total_lines = sum(1 for line in f if line.strip())
            
            preview_text = f"Detected Encoding: {detected_encoding}\n\n"
            preview_text += "\n".join(lines)
            if total_lines > 10:
                preview_text += f"\n... and {total_lines - 10} more passwords"
            
            messagebox.showinfo("Wordlist Preview", f"Total passwords: {total_lines}\n\n{preview_text}")
        except Exception as e:
            messagebox.showerror("Preview Error", f"Error reading wordlist: {e}")
    
    def clear_log(self):
        self.results_text.delete(1.0, tk.END)
    
    def on_mode_change(self):
        if self.attack_mode.get() == "dictionary":
            self.dict_frame.grid()
            self.brute_frame.grid_remove()
        else:
            self.dict_frame.grid_remove()
            self.brute_frame.grid()
    
    def log_message(self, message, color=None):
        """Add message to results text widget"""
        timestamp = time.strftime("%H:%M:%S")
        full_message = f"[{timestamp}] {message}\n"
        
        self.results_text.insert(tk.END, full_message)
        
        if color:
            start_line = self.results_text.index("end-2l")
            end_line = self.results_text.index("end-1l")
            self.results_text.tag_add(color, start_line, end_line)
            
        self.results_text.see(tk.END)
        self.root.update_idletasks()
    
    def queue_message(self, msg_type, message, color=None):
        """Helper method to ensure all queue messages have consistent format"""
        self.result_queue.put((msg_type, message, color))
    
    def start_attack(self):
        if self.is_running:
            return
        
        # Validate inputs
        if not self.encrypted_file_path.get():
            messagebox.showerror("Error", "Please select an encrypted file")
            return
        
        if not os.path.exists(self.encrypted_file_path.get()):
            messagebox.showerror("Error", "Encrypted file does not exist")
            return
        
        if self.attack_mode.get() == "dictionary":
            if not self.wordlist_file_path.get():
                messagebox.showerror("Error", "Please select a wordlist file")
                return
            if not os.path.exists(self.wordlist_file_path.get()):
                messagebox.showerror("Error", "Wordlist file does not exist")
                return
        
        # Start attack in separate thread
        self.is_running = True
        self.stop_attack = False
        self.start_button.config(state="disabled")
        self.stop_button.config(state="normal")
        self.progress_bar.start()
        self.results_text.delete(1.0, tk.END)
        
        # Configure text tags for colored output
        self.results_text.tag_configure("success", foreground="green", font=("Consolas", 9, "bold"))
        self.results_text.tag_configure("error", foreground="red")
        self.results_text.tag_configure("debug", foreground="blue")
        self.results_text.tag_configure("warning", foreground="orange")
        
        if self.attack_mode.get() == "dictionary":
            attack_thread = threading.Thread(target=self.dictionary_attack, daemon=True)
        else:
            attack_thread = threading.Thread(target=self.brute_force_attack, daemon=True)
        
        attack_thread.start()
    
    def stop_attack_func(self):
        self.stop_attack = True
        self.log_message("🛑 Stopping attack...", "warning")
    
    def dictionary_attack(self):
        try:
            self.queue_message("log", "🚀 Starting universal dictionary attack...", None)
            
            encrypted_file = self.encrypted_file_path.get()
            wordlist_file = self.wordlist_file_path.get()
            
            # Detect wordlist encoding
            wordlist_encoding = self.detect_encoding(wordlist_file)
            self.queue_message("log", f"📝 Using wordlist encoding: {wordlist_encoding}", None)
            
            # Count total words
            try:
                with open(wordlist_file, 'r', encoding=wordlist_encoding, errors='ignore') as f:
                    total_words = sum(1 for line in f if line.strip())
                self.queue_message("log", f"📋 Loaded wordlist with {total_words} entries", None)
            except Exception as e:
                self.queue_message("log", f"⚠️ Could not count wordlist entries: {e}", "warning")
                total_words = 0
            
            attempts = 0
            start_time = time.time()
            
            with open(wordlist_file, 'r', encoding=wordlist_encoding, errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    if self.stop_attack:
                        break
                    
                    password = line.strip('\n\r\t ')
                    if not password or password.startswith('#'):
                        continue
                    
                    attempts += 1
                    
                    if self.debug_mode.get() and (attempts <= 5 or attempts % 100 == 0):
                        self.queue_message("log", f"🔍 Trying '{password}' (attempt {attempts})", "debug")
                    
                    if attempts % 50 == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        self.queue_message("progress", f"Attempted {attempts}/{total_words} passwords... Rate: {rate:.1f}/sec", None)
                        self.queue_message("attempts", f"Attempts: {attempts}", None)
                    
                    result = self.try_password_universal(encrypted_file, password)
                    if result == "success":
                        elapsed = time.time() - start_time
                        self.queue_message("success", f"🎉 PASSWORD FOUND: '{password}'", None)
                        self.queue_message("log", f"✅ Attack completed successfully after {attempts} attempts in {elapsed:.2f} seconds", "success")
                        return
            
            elapsed = time.time() - start_time
            if not self.stop_attack:
                self.queue_message("log", f"❌ Dictionary attack completed. No password found after {attempts} attempts in {elapsed:.2f} seconds.", "error")
            else:
                self.queue_message("log", f"⏹️ Dictionary attack stopped by user after {attempts} attempts in {elapsed:.2f} seconds.", "warning")
                
        except Exception as e:
            self.queue_message("error", f"Dictionary attack error: {e}", None)
        finally:
            self.queue_message("finished", "Attack finished", None)
    
    def brute_force_attack(self):
        try:
            self.queue_message("log", "🚀 Starting universal brute force attack...", None)
            
            encrypted_file = self.encrypted_file_path.get()
            charset = self.charset.get()
            min_len = self.min_length.get()
            max_len = self.max_length.get()
            
            if min_len > max_len:
                self.queue_message("error", "Minimum length cannot be greater than maximum length", None)
                return
            
            total_combinations = sum(len(charset) ** length for length in range(min_len, max_len + 1))
            self.queue_message("log", f"📊 Total combinations to try: {total_combinations:,}", None)
            
            attempts = 0
            start_time = time.time()
            
            for length in range(min_len, max_len + 1):
                if self.stop_attack:
                    break
                
                self.queue_message("log", f"🔤 Trying passwords of length {length}...", None)
                
                for password_tuple in itertools.product(charset, repeat=length):
                    if self.stop_attack:
                        break
                    
                    password = ''.join(password_tuple)
                    attempts += 1
                    
                    if attempts % 1000 == 0:
                        elapsed = time.time() - start_time
                        rate = attempts / elapsed if elapsed > 0 else 0
                        progress = (attempts / total_combinations) * 100 if total_combinations > 0 else 0
                        self.queue_message("progress", f"Progress: {progress:.2f}% - Rate: {rate:.1f}/sec - Current: {password}", None)
                        self.queue_message("attempts", f"Attempts: {attempts:,}", None)
                    
                    if self.debug_mode.get() and attempts % 5000 == 0:
                        self.queue_message("log", f"🔍 Current password: '{password}'", "debug")
                    
                    result = self.try_password_universal(encrypted_file, password)
                    if result == "success":
                        elapsed = time.time() - start_time
                        self.queue_message("success", f"🎉 PASSWORD FOUND: '{password}'", None)
                        self.queue_message("log", f"✅ Attack completed successfully after {attempts:,} attempts in {elapsed:.2f} seconds", "success")
                        return
            
            elapsed = time.time() - start_time
            if not self.stop_attack:
                self.queue_message("log", f"❌ Brute force attack completed. No password found after {attempts:,} attempts in {elapsed:.2f} seconds.", "error")
            else:
                self.queue_message("log", f"⏹️ Brute force attack stopped by user after {attempts:,} attempts in {elapsed:.2f} seconds.", "warning")
                
        except Exception as e:
            self.queue_message("error", f"Brute force attack error: {e}", None)
        finally:
            self.queue_message("finished", "Attack finished", None)
    
    def try_password_universal(self, file_path, password):
        """Universal password testing for multiple file formats"""
        file_ext = Path(file_path).suffix.lower()
        
        try:
            # ZIP files
            if file_ext == '.zip':
                return self.try_password_zip(file_path, password)
            
            # 7Z files
            elif file_ext == '.7z':
                return self.try_password_7z(file_path, password)
            
            # RAR files
            elif file_ext == '.rar':
                return self.try_password_rar(file_path, password)
            
            # PDF files
            elif file_ext == '.pdf':
                return self.try_password_pdf(file_path, password)
            
            # Office files
            elif file_ext in ['.docx', '.xlsx', '.pptx', '.doc', '.xls', '.ppt']:
                return self.try_password_office(file_path, password)
            
            # Try 7zip CLI as fallback for unknown formats
            else:
                return self.try_password_7zip_cli(file_path, password)
                
        except Exception as e:
            if self.debug_mode.get():
                self.queue_message("log", f"Error testing password '{password}': {e}", "debug")
            return "failed"
    
    def try_password_zip(self, file_path, password):
        """Test password on ZIP files with multiple encoding support"""
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                encrypted_files = [f for f in zip_file.infolist() if f.flag_bits & 0x1]
                if not encrypted_files:
                    return "success"
                
                first_encrypted = encrypted_files[0]
                
                # For AES encrypted files
                if first_encrypted.compress_type == 99:
                    if self.libraries['py7zr']:
                        try:
                            import py7zr
                            with py7zr.SevenZipFile(file_path, mode="r", password=password) as archive:
                                archive.getnames()
                                return "success"
                        except:
                            pass
                    
                    return self.try_password_7zip_cli(file_path, password)
                
                # Standard ZIP encryption
                else:
                    encodings = self.get_encoding_list()
                    for encoding in encodings:
                        try:
                            zip_file.read(first_encrypted, pwd=password.encode(encoding))
                            return "success"
                        except (RuntimeError, UnicodeEncodeError):
                            continue
                    
        except Exception:
            pass
        
        return "failed"
    
    def try_password_7z(self, file_path, password):
        """Test password on 7Z files"""
        if self.libraries['py7zr']:
            try:
                import py7zr
                with py7zr.SevenZipFile(file_path, mode="r", password=password) as archive:
                    archive.getnames()
                    return "success"
            except:
                pass
        
        return self.try_password_7zip_cli(file_path, password)
    
    def try_password_rar(self, file_path, password):
        """Test password on RAR files"""
        if self.libraries['rarfile']:
            try:
                import rarfile
                with rarfile.RarFile(file_path) as rf:
                    rf.setpassword(password)
                    rf.testrar()
                    return "success"
            except:
                pass
        
        return self.try_password_7zip_cli(file_path, password)
    
    def try_password_pdf(self, file_path, password):
        """Test password on PDF files"""
        if self.libraries['pypdf2']:
            try:
                import PyPDF2
                with open(file_path, 'rb') as file:
                    pdf_reader = PyPDF2.PdfReader(file)
                    if pdf_reader.is_encrypted:
                        if pdf_reader.decrypt(password):
                            return "success"
            except:
                pass
        
        return "failed"
    
    def try_password_office(self, file_path, password):
        """Test password on Microsoft Office files"""
        if self.libraries['msoffcrypto']:
            try:
                import msoffcrypto
                import io
                
                with open(file_path, 'rb') as file:
                    office_file = msoffcrypto.OfficeFile(file)
                    if office_file.is_encrypted():
                        office_file.load_key(password=password)
                        decrypted = io.BytesIO()
                        office_file.decrypt(decrypted)
                        return "success"
            except:
                pass
        
        return "failed"
    
    def try_password_7zip_cli(self, file_path, password):
        """Fallback method using 7zip CLI"""
        if self.libraries['7zip_cli']:
            try:
                result = subprocess.run(
                    ['7z', 't', file_path, f'-p{password}'], 
                    capture_output=True, text=True, timeout=15
                )
                return "success" if result.returncode == 0 else "failed"
            except:
                pass
        
        return "failed"
    
    def check_queue(self):
        """Check for messages from worker threads"""
        try:
            while True:
                try:
                    queue_item = self.result_queue.get_nowait()
                    
                    if isinstance(queue_item, tuple):
                        if len(queue_item) == 3:
                            message_type, message, color = queue_item
                        elif len(queue_item) == 2:
                            message_type, message = queue_item
                            color = None
                        else:
                            continue
                    else:
                        continue
                    
                    if message_type == "log":
                        self.log_message(message, color)
                    elif message_type == "progress":
                        self.progress_var.set(message)
                    elif message_type == "attempts":
                        self.attempts_var.set(message)
                    elif message_type == "success":
                        self.log_message("🎉 " + message, "success")
                        messagebox.showinfo("Success!", message)
                    elif message_type == "error":
                        self.log_message("❌ " + message, "error")
                        messagebox.showerror("Error", message)
                    elif message_type == "finished":
                        self.attack_finished()
                        break
                        
                except ValueError:
                    continue
                    
        except queue.Empty:
            pass
        except Exception as e:
            print(f"Queue error: {e}")
        
        self.root.after(100, self.check_queue)
    
    def attack_finished(self):
        """Clean up after attack is finished"""
        self.is_running = False
        self.stop_attack = False
        self.start_button.config(state="normal")
        self.stop_button.config(state="disabled")
        self.progress_bar.stop()
        self.progress_var.set("Attack finished.")

def main():
    root = tk.Tk()
    app = UniversalPasswordCrackerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()

