import sys
import subprocess
import importlib
import os
import json
import tempfile
import hashlib
import tkinter as tk
from tkinter import filedialog
from contextlib import redirect_stderr
from datetime import datetime

# Check if PyQt6 is installed
try:
    from PyQt6 import QtWidgets, QtCore, QtGui
    from PyQt6.QtWidgets import (
        QApplication, QMainWindow, QPushButton, QLabel, QLineEdit,
        QFileDialog, QVBoxLayout, QWidget, QRadioButton, QButtonGroup,
        QMessageBox, QTextEdit, QProgressBar, QHBoxLayout, QFormLayout, QGroupBox
    )
    from PyQt6.QtCore import Qt
    pyqt_installed = True
except ImportError:
    pyqt_installed = False

# Check if rich is installed for enhanced output; otherwise, use basic print functions.
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.prompt import Prompt
    from rich.progress import Progress
    console = Console()
    use_rich = True
except ImportError:
    use_rich = False

def display_message(message, style=""):
    """Display messages with rich if available, otherwise use basic print."""
    if use_rich:
        console.print(message, style=style)
    else:
        print(message)

def check_requirements():
    """Check and install missing required packages."""
    required_packages = ["rich", "cryptography", "PyQt6"]
    missing_packages = []

    # Check for each required package
    for package in required_packages:
        try:
            importlib.import_module(package)
        except ImportError:
            missing_packages.append(package)

    # If there are missing packages, prompt the user to install them
    if missing_packages:
        display_message(f"Missing required packages: {', '.join(missing_packages)}", style="bold red")
        install = input("Would you like to install them now? (y/n): ").strip().lower()
        if install == 'y':
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", *missing_packages])
                display_message("Required packages installed successfully!", style="bold green")
                
                # Re-import modules if they were missing previously
                if "rich" in missing_packages:
                    global console, use_rich, Prompt, Panel, Progress
                    from rich.console import Console
                    from rich.panel import Panel
                    from rich.prompt import Prompt
                    from rich.progress import Progress
                    console = Console()
                    use_rich = True
                if "PyQt6" in missing_packages:
                    global QtWidgets, QtCore, QtGui
                    from PyQt6 import QtWidgets, QtCore, QtGui
            except subprocess.CalledProcessError:
                display_message("Failed to install required packages. Please install them manually and try again.", style="bold red")
                sys.exit(1)
        else:
            display_message("Cannot proceed without required packages. Exiting...", style="bold red")
            sys.exit(1)

# Check and install unmet requirements before running the main code
check_requirements()

# Import necessary libraries after checking for dependencies
import hashlib
import os
import tempfile
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.exceptions import InvalidTag

# ========== Constants and Configuration ==========

# Questions for generating the encryption password
QUESTIONS = [
    "What is your favorite color?",
    "What month is your birthday?",
    "What city do you live in?",
    "What is the Disk ID"
]

# Note: The first group of questions (indices 0 to 2) are ones where the order matters.
# The second group (spouse names) is where the order does not matter.
# The Disk ID is meant to change to allow the questions to be the same across different encryption jobs.

# Application metadata
VERSION = "1.0.0"
DEVELOPER = "Sean S"
GITHUB_URL = "https://github.com/pitterpatter22/EasyCrypt"

# ========== Core Encryption Functions ==========

def ask_questions_cli():
    """
    Ask questions in CLI mode to generate the password.

    There are two types of questions:
    - The first group (indices 0 to 2 in QUESTIONS) where the order matters.
    - The second group (spouse names) where the order does not matter.

    The Disk ID (QUESTIONS[3]) is meant to change to allow the other questions to remain the same across different encryption jobs.
    """
    console.rule("[bold cyan]Password Setup Questions[/bold cyan]", style="cyan")
    hashed_answers = []

    # First group of questions (order matters)
    for question in QUESTIONS[:3]:
        answer = Prompt.ask(f"[cyan]{question}[/cyan]").strip().lower()
        hashed_answer = hashlib.sha256(answer.encode()).hexdigest()
        hashed_answers.append(hashed_answer)

    # Disk ID question (changes per job)
    disk_id = Prompt.ask(f"[cyan]{QUESTIONS[3]}[/cyan]").strip().lower()
    hashed_disk_id = hashlib.sha256(disk_id.encode()).hexdigest()
    hashed_answers.append(hashed_disk_id)

    # Second group of questions (order does not matter)
    name = Prompt.ask("[green]What is your name?[/green]").strip().lower()
    spouse_name = Prompt.ask("[green]What is your spouse's name?[/green]").strip().lower()
    sorted_names = sorted([name, spouse_name])
    combined_names = ''.join(sorted_names)
    hashed_names = hashlib.sha256(combined_names.encode()).hexdigest()
    hashed_answers.append(hashed_names)

    # Combine all hashed answers to form the final password
    combined_hash = ''.join(hashed_answers)
    final_hash = hashlib.sha256(combined_hash.encode()).hexdigest()
    password = final_hash[:32]

    console.print(Panel(f"[bold magenta]Your generated password is:[/bold magenta]\n[white]{password}[/white]", title="[bold green]Password Generator[/bold green]", border_style="blue"))
    console.rule("")  # Adds a separator line
    return password

def derive_key(password, salt):
    """
    Derive a cryptographic key from the password and salt using PBKDF2HMAC.

    Args:
        password (str): The password to derive the key from.
        salt (bytes): A random salt.

    Returns:
        bytes: The derived key.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(password.encode())

def hash_filename(filename):
    """
    Hash the filename using SHA-256 to obscure original file names.

    Args:
        filename (str): The original filename.

    Returns:
        str: The hashed filename.
    """
    return hashlib.sha256(filename.encode()).hexdigest()

def encrypt_file(password, input_file, output_file, log_function=None):
    """
    Encrypt a file using AES-GCM with the provided password.

    Args:
        password (str): The password for encryption.
        input_file (str): Path to the input file.
        output_file (str): Path to the output encrypted file.
        log_function (callable, optional): Function to log messages.

    Returns:
        bool: True if encryption was successful, False otherwise.
    """
    salt = os.urandom(16)
    key = derive_key(password, salt)
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)

    try:
        with open(input_file, "rb") as f:
            data = f.read()

        encrypted_data = aesgcm.encrypt(nonce, data, None)
        with open(output_file, "wb") as f:
            f.write(salt + nonce + encrypted_data)
        if log_function:
            log_function(f"Encrypted file: {input_file}", "green")
        return True
    except Exception as e:
        if log_function:
            log_function(f"Error encrypting file {input_file}: {e}", "red")
        return False

def decrypt_file(password, input_file, output_file, log_function=None):
    """
    Decrypt a file using AES-GCM with the provided password.

    Args:
        password (str): The password for decryption.
        input_file (str): Path to the encrypted input file.
        output_file (str): Path to the decrypted output file.
        log_function (callable, optional): Function to log messages.

    Returns:
        bool: True if decryption was successful, False otherwise.
    """
    try:
        with open(input_file, "rb") as f:
            salt = f.read(16)
            nonce = f.read(12)
            encrypted_data = f.read()

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)
        decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)

        with open(output_file, "wb") as f:
            f.write(decrypted_data)
        if log_function:
            log_function(f"Decrypted file: {input_file}", "green")
        return True
    except InvalidTag:
        if log_function:
            log_function("Decryption failed. Incorrect password or corrupted file.", "red")
        return False
    except Exception as e:
        if log_function:
            log_function(f"Error decrypting file {input_file}: {e}", "red")
        return False

def run_tests():
    """
    Run a self-test to verify that encryption and decryption work correctly.

    Returns:
        bool: True if the self-test passed, False otherwise.
    """
    display_message("Running Encryption Self-Test...", style="bold yellow")
    password = "testpassword1234567890abcdef"  # Fixed password for testing
    test_data = b"This is a test."  # Test content to encrypt and decrypt

    # Create temporary files for testing
    with tempfile.NamedTemporaryFile(delete=False) as original_file:
        original_file.write(test_data)
        original_path = original_file.name

    encrypted_path = original_path + ".enc"
    decrypted_path = original_path + ".dec"

    # Test encryption
    if not encrypt_file(password, original_path, encrypted_path):
        display_message("Self-test failed during encryption.", style="bold red")
        return False

    # Test decryption
    if not decrypt_file(password, encrypted_path, decrypted_path):
        display_message("Self-test failed during decryption.", style="bold red")
        return False

    # Verify decrypted data matches original
    with open(decrypted_path, "rb") as f:
        decrypted_data = f.read()

    # Clean up temporary files
    os.remove(original_path)
    os.remove(encrypted_path)
    os.remove(decrypted_path)

    if decrypted_data == test_data:
        display_message("Self-test passed. Starting program...", style="bold green")
        return True
    else:
        display_message("Self-test failed. Decrypted data does not match original.", style="bold red")
        return False

def process_folder(password, input_folder, output_folder, mode="e", log_function=None, progress_callback=None):
    """
    Process a folder for encryption or decryption.

    Args:
        password (str): The password for encryption/decryption.
        input_folder (str): Path to the input folder.
        output_folder (str): Path to the output folder.
        mode (str): 'e' for encryption, 'd' for decryption.
        log_function (callable, optional): Function to log messages.
        progress_callback (callable, optional): Function to update progress.
    """
    metadata = {"files": {}, "folders": {}}
    metadata_file_path = os.path.join(input_folder, "metadata.json.enc")

    if mode == "d":
        try:
            with open(metadata_file_path, "rb") as f:
                salt = f.read(16)
                nonce = f.read(12)
                encrypted_data = f.read()
            key = derive_key(password, salt)
            aesgcm = AESGCM(key)
            decrypted_data = aesgcm.decrypt(nonce, encrypted_data, None)
            metadata = json.loads(decrypted_data.decode("utf-8"))
            if log_function:
                log_function("Metadata decrypted successfully.", "green")
        except Exception as e:
            if log_function:
                log_function(f"Error reading metadata: {e}", "red")
            return

    # Count total files for progress bar
    total_files = sum(len(files) for _, _, files in os.walk(input_folder))
    processed_files = 0

    for root, dirs, files in os.walk(input_folder):
        rel_path = os.path.relpath(root, input_folder)
        if rel_path == ".":
            rel_path = ""
        if mode == "e":
            hashed_folder_name = hash_filename(rel_path)
            metadata["folders"][hashed_folder_name] = rel_path
            target_dir = os.path.join(output_folder, hashed_folder_name)
        else:
            original_folder_name = metadata["folders"].get(rel_path, rel_path)
            target_dir = os.path.join(output_folder, original_folder_name)
        os.makedirs(target_dir, exist_ok=True)

        for file in files:
            input_file_path = os.path.join(root, file)
            if mode == "d" and file == "metadata.json.enc":
                continue
            if mode == "e":
                hashed_name = hash_filename(file)
                output_file_path = os.path.join(target_dir, f"{hashed_name}.enc")
                if encrypt_file(password, input_file_path, output_file_path, log_function):
                    metadata["files"][hashed_name] = file
            else:
                hashed_name, _ = os.path.splitext(file)
                original_name = metadata["files"].get(hashed_name, hashed_name)
                output_file_path = os.path.join(target_dir, original_name)
                decrypt_file(password, input_file_path, output_file_path, log_function)
            processed_files += 1
            if progress_callback:
                progress_callback(processed_files, total_files)

    if mode == "e":
        metadata_file = os.path.join(output_folder, "metadata.json")
        with open(metadata_file, "w") as f:
            json.dump(metadata, f)
        encrypt_file(password, metadata_file, os.path.join(output_folder, "metadata.json.enc"), log_function)
        os.remove(metadata_file)
        if log_function:
            log_function("Metadata encrypted successfully.", "green")

# ========== CLI Mode Functions ==========

def main_cli():
    """
    Main function for CLI mode.
    """
    # Run self-test before starting
    display_message("Validating Encryption Self-Test...", style="bold yellow")
    if not run_tests():
        display_message("Exiting due to failed self-test.", style="bold red")
        sys.exit(1)
    password = ask_questions_cli()

    while True:
        mode = Prompt.ask("Would you like to (e)ncrypt or (d)ecrypt a file or folder?", choices=["e", "d"])

        # Start with the current working directory
        initial_dir = os.getcwd()

        choice = Prompt.ask("Select (f)ile or (d)irectory").strip().lower()
        
        if choice == "f":
            input_path = select_path(initial_dir, select_type="file")
            if input_path:
                initial_dir = os.path.dirname(input_path)
                output_path = select_path(initial_dir, select_type="folder")
            else:
                display_message("No file selected. Please try again.", style="bold red")
                continue
        elif choice == "d":
            input_path = select_path(initial_dir, select_type="folder")
            if input_path:
                initial_dir = input_path
                output_path = select_path(initial_dir, select_type="folder")
                if mode == "e":
                    output_path = os.path.join(output_path, "encrypted_files")
                    os.makedirs(output_path, exist_ok=True)
            else:
                display_message("No folder selected. Please try again.", style="bold red")
                continue
        else:
            display_message("Invalid choice. Please try again.", style="bold red")
            continue

        if os.path.isdir(input_path):
            process_folder(password, input_path, output_path, mode)
        else:
            if mode == "e":
                output_file = os.path.join(output_path, f"{os.path.basename(input_path)}.enc")
                encrypt_file(password, input_path, output_file)
            elif mode == "d":
                output_file = os.path.join(output_path, os.path.basename(input_path).replace(".enc", ""))
                decrypt_file(password, input_path, output_file)

        next_action = Prompt.ask("Would you like to use the same password for another file/folder (y), start over with new answers (n), or quit (q)?", choices=["y", "n", "q"])
        
        if next_action == "y":
            continue
        elif next_action == "n":
            password = ask_questions_cli()
        elif next_action == "q":
            display_message("Exiting the program. Goodbye!", style="bold green")
            break

def select_path(initial_dir, select_type="file"):
    """
    Open a file or folder explorer dialog based on select_type, starting from initial_dir.

    Args:
        initial_dir (str): The initial directory to start from.
        select_type (str): 'file' to select a file, 'folder' to select a folder.

    Returns:
        str: The selected path.
    """
    root = tk.Tk()
    root.withdraw()  # Hide the main tkinter window

    with open(os.devnull, "w") as f, redirect_stderr(f):
        if select_type == "file":
            path = filedialog.askopenfilename(initialdir=initial_dir, title="Select a File")
        elif select_type == "folder":
            path = filedialog.askdirectory(initialdir=initial_dir, title="Select a Folder")
        else:
            raise ValueError("select_type must be 'file' or 'folder'")
    
    root.destroy()
    return path

# ========== GUI Mode Classes and Functions ==========

class PasswordDialog(QtWidgets.QDialog):
    """
    Dialog for entering or importing the password.
    """
    def __init__(self, previous_answers=None):
        super().__init__()
        self.setWindowTitle("Password Setup")
        self.password = None  # Stores the encryption code if imported
        self.init_ui(previous_answers)

    def init_ui(self, previous_answers):
        """
        Initialize the UI components of the dialog.

        Args:
            previous_answers (dict, optional): Previous answers to pre-fill the fields.
        """
        layout = QVBoxLayout()

        # Heading
        heading = QLabel("Password Setup")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading.setStyleSheet("font-size: 18px; font-weight: bold;")
        layout.addWidget(heading)

        form_layout = QFormLayout()

        # Questions and input fields
        self.questions = [(question, QLineEdit()) for question in QUESTIONS]
        self.name_edit = QLineEdit()
        self.spouse_name_edit = QLineEdit()

        if previous_answers:
            for i, (_, edit) in enumerate(self.questions):
                edit.setText(previous_answers.get(f"q{i+1}", ""))
            self.name_edit.setText(previous_answers.get("name", ""))
            self.spouse_name_edit.setText(previous_answers.get("spouse_name", ""))

        # First group of questions (order matters)
        for question, edit in self.questions:
            form_layout.addRow(question, edit)

        # Second group of questions (order does not matter)
        form_layout.addRow("What is your name?", self.name_edit)
        form_layout.addRow("What is your spouse's name?", self.spouse_name_edit)

        # Import Encryption Code Button
        self.import_button = QPushButton("Import Encryption Code")
        self.import_button.clicked.connect(self.import_encryption_code)
        self.import_button.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DialogOpenButton))

        # Save Answers Checkbox
        self.save_answers_checkbox = QtWidgets.QCheckBox("Remember my answers")

        # Button Box
        self.button_box = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok | QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        self.button_box.accepted.connect(self.accept)
        self.button_box.rejected.connect(self.reject)

        # Layout Adjustments
        layout.addLayout(form_layout)
        layout.addWidget(self.import_button)
        layout.addWidget(self.save_answers_checkbox)
        layout.addWidget(self.button_box)
        self.setLayout(layout)

    def get_password(self):
        """
        Generate the password based on the answers provided.

        Returns:
            str: The generated password.
        """
        if self.password:
            return self.password  # Return the imported encryption code

        hashed_answers = []

        # First group of questions (order matters)
        for i in range(len(QUESTIONS[:3])):
            answer = self.questions[i][1].text().strip().lower()
            hashed_answer = hashlib.sha256(answer.encode()).hexdigest()
            hashed_answers.append(hashed_answer)

        # Disk ID question (changes per job)
        disk_id = self.questions[3][1].text().strip().lower()
        hashed_disk_id = hashlib.sha256(disk_id.encode()).hexdigest()
        hashed_answers.append(hashed_disk_id)

        # Second group of questions (order does not matter)
        name = self.name_edit.text().strip().lower()
        spouse_name = self.spouse_name_edit.text().strip().lower()
        sorted_names = sorted([name, spouse_name])
        combined_names = ''.join(sorted_names)
        hashed_names = hashlib.sha256(combined_names.encode()).hexdigest()
        hashed_answers.append(hashed_names)

        # Combine all hashed answers to form the final password
        combined_hash = ''.join(hashed_answers)
        final_hash = hashlib.sha256(combined_hash.encode()).hexdigest()
        password = final_hash[:32]
        return password

    def get_answers(self):
        """
        Retrieve the answers from the input fields.

        Returns:
            dict: A dictionary of answers.
        """
        answers = {}
        for i, (_, edit) in enumerate(self.questions):
            answers[f"q{i+1}"] = edit.text()
        answers["name"] = self.name_edit.text()
        answers["spouse_name"] = self.spouse_name_edit.text()
        return answers

    def should_save_answers(self):
        """
        Check if the user wants to save the answers.

        Returns:
            bool: True if the answers should be saved, False otherwise.
        """
        return self.save_answers_checkbox.isChecked()

    def import_encryption_code(self):
        """
        Import an encryption code from a file.
        """
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Encryption Code", "", "Encryption Code Files (*.enc)")
        if file_path:
            with open(file_path, 'r') as f:
                self.password = f.read().strip()
            QMessageBox.information(self, "Success", "Encryption code imported successfully.")
            self.accept()

class MainWindow(QMainWindow):
    """
    Main window class for the GUI application.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("EasyCrypt")
        self.password = ""
        self.selected_path = ""
        self.previous_answers = None  # Stores the previous answers
        self.init_ui()

    def init_ui(self):
        """
        Initialize the UI components of the main window.
        """
        # Apply Fusion style for a modern look
        QApplication.setStyle('Fusion')

        # Set window icon
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_FileDialogInfoView))

        main_layout = QVBoxLayout()

        # Heading
        heading = QLabel("EasyCrypt")
        heading.setAlignment(Qt.AlignmentFlag.AlignCenter)
        heading.setStyleSheet("font-size: 24px; font-weight: bold; margin-bottom: 20px;")
        main_layout.addWidget(heading)

        # Mode Selection
        mode_group_box = QGroupBox("Select Mode")
        mode_layout = QHBoxLayout()
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio.setChecked(True)
        mode_layout.addWidget(self.encrypt_radio)
        mode_layout.addWidget(self.decrypt_radio)
        mode_group_box.setLayout(mode_layout)
        main_layout.addWidget(mode_group_box)

        # File Selection
        file_group_box = QGroupBox("File/Folder Selection")
        file_layout = QHBoxLayout()
        self.select_file_button = QPushButton("Select File")
        self.select_file_button.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_FileIcon))
        self.select_folder_button = QPushButton("Select Folder")
        self.select_folder_button.setIcon(self.style().standardIcon(QtWidgets.QStyle.StandardPixmap.SP_DirIcon))
        file_layout.addWidget(self.select_file_button)
        file_layout.addWidget(self.select_folder_button)
        file_group_box.setLayout(file_layout)
        main_layout.addWidget(file_group_box)

        # Selected Path Display
        self.selected_path_label = QLabel("Selected Path: None")
        self.selected_path_label.setWordWrap(True)
        main_layout.addWidget(self.selected_path_label)

        # Start and Quit Buttons
        action_layout = QHBoxLayout()
        self.start_button = QPushButton("Start")
        self.start_button.setEnabled(False)
        # Make the Start button green
        self.start_button.setStyleSheet("background-color: green; color: white; font-weight: bold; padding: 10px;")
        self.reset_button = QPushButton("Reset")
        self.save_code_button = QPushButton("Save Encryption Code")
        self.help_button = QPushButton("Help")
        self.about_button = QPushButton("About")
        self.quit_button = QPushButton("Quit")
        self.quit_button.setStyleSheet("background-color: red; color: white; font-weight: bold; padding: 10px;")
        action_layout.addWidget(self.start_button)
        action_layout.addWidget(self.quit_button)
        main_layout.addLayout(action_layout)

        # Additional Buttons
        extra_button_layout = QHBoxLayout()
        extra_button_layout.addWidget(self.reset_button)
        extra_button_layout.addWidget(self.save_code_button)
        extra_button_layout.addWidget(self.help_button)
        extra_button_layout.addWidget(self.about_button)
        main_layout.addLayout(extra_button_layout)

        # Log area
        log_group_box = QGroupBox("Status Messages")
        self.log_text_edit = QTextEdit()
        self.log_text_edit.setReadOnly(True)
        log_layout = QVBoxLayout()
        log_layout.addWidget(self.log_text_edit)
        log_group_box.setLayout(log_layout)
        main_layout.addWidget(log_group_box)

        # Progress bar
        progress_group_box = QGroupBox("Progress")
        self.progress_bar = QProgressBar()
        progress_layout = QVBoxLayout()
        progress_layout.addWidget(self.progress_bar)
        progress_group_box.setLayout(progress_layout)
        main_layout.addWidget(progress_group_box)

        # Set main layout
        container = QWidget()
        container.setLayout(main_layout)
        self.setCentralWidget(container)

        # Connect signals
        self.select_file_button.clicked.connect(self.select_file)
        self.select_folder_button.clicked.connect(self.select_folder)
        self.start_button.clicked.connect(self.start_process)
        self.reset_button.clicked.connect(self.reset_password)
        self.save_code_button.clicked.connect(self.save_encryption_code)
        self.help_button.clicked.connect(self.show_help)
        self.about_button.clicked.connect(self.show_about)
        self.quit_button.clicked.connect(self.close_application)

        # Ask for password on startup
        self.get_password()

    def get_password(self):
        """
        Open the password dialog to get or import the password.
        """
        dlg = PasswordDialog(previous_answers=self.previous_answers)
        if dlg.exec():
            self.password = dlg.get_password()
            if dlg.should_save_answers():
                self.previous_answers = dlg.get_answers()
            else:
                self.previous_answers = None
        else:
            QMessageBox.critical(self, "Error", "Password is required to proceed.")
            sys.exit(0)

    def reset_password(self):
        """
        Reset the password by re-opening the password dialog.
        """
        self.get_password()
        QMessageBox.information(self, "Reset", "Password has been reset.")

    def save_encryption_code(self):
        """
        Save the current encryption code to a file.
        """
        if not self.password:
            QMessageBox.warning(self, "Warning", "No encryption code to save.")
            return
        file_path, _ = QFileDialog.getSaveFileName(self, "Save Encryption Code", "", "Encryption Code Files (*.enc)")
        if file_path:
            with open(file_path, 'w') as f:
                f.write(self.password)
            QMessageBox.information(self, "Success", "Encryption code saved successfully.")

    def show_help(self):
        """
        Display the help message.
        """
        help_text = (
            "How to Use the App:\n\n"
            "1. On startup, answer the questions to generate your encryption code.\n"
            "   - The first three questions are order-sensitive.\n"
            "   - The names are order-insensitive.\n"
            "   - The Disk ID is meant to change per encryption job.\n"
            "2. Choose 'Encrypt' or 'Decrypt' mode.\n"
            "3. Select a file or folder to process.\n"
            "4. Click the 'Start' button to begin.\n"
            "5. Monitor progress and status messages.\n"
            "6. Use 'Reset' to change your encryption code.\n"
            "7. Save your encryption code using 'Save Encryption Code' if needed.\n"
            "8. Click 'Quit' to exit the application."
        )
        QMessageBox.information(self, "Help", help_text)

    def show_about(self):
        """
        Display the about message with version and developer info.
        """
        about_text = (
            f"EasyCrypt Tool\n"
            f"Version: {VERSION}\n"
            f"Developer: {DEVELOPER}\n"
            f"GitHub: {GITHUB_URL}"
        )
        QMessageBox.information(self, "About", about_text)

    def select_file(self):
        """
        Open a dialog to select a file.
        """
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select File", "", "All Files (*)"
        )
        if file_path:
            self.selected_path = file_path
            self.selected_path_label.setText(f"Selected Path: {file_path}")
            self.start_button.setEnabled(True)

    def select_folder(self):
        """
        Open a dialog to select a folder.
        """
        folder_path = QFileDialog.getExistingDirectory(
            self, "Select Folder"
        )
        if folder_path:
            self.selected_path = folder_path
            self.selected_path_label.setText(f"Selected Path: {folder_path}")
            self.start_button.setEnabled(True)

    def log_message(self, message, color="black"):
        """
        Log a message to the log area.

        Args:
            message (str): The message to log.
            color (str, optional): The color of the message text.
        """
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        formatted_message = f"<span style='color:{color}'>{timestamp} - {message}</span>"
        self.log_text_edit.append(formatted_message)

    def update_progress(self, value, total):
        """
        Update the progress bar.

        Args:
            value (int): The current progress value.
            total (int): The total value for completion.
        """
        percentage = int((value / total) * 100)
        self.progress_bar.setValue(percentage)

    def start_process(self):
        """
        Start the encryption or decryption process.
        """
        if not self.selected_path:
            QMessageBox.warning(self, "Warning", "No file or folder selected.")
            return

        mode = "e" if self.encrypt_radio.isChecked() else "d"
        input_path = self.selected_path
        output_path = QFileDialog.getExistingDirectory(self, "Select Output Folder")
        if not output_path:
            QMessageBox.warning(self, "Warning", "Output folder is required.")
            return

        self.progress_bar.setValue(0)
        self.log_text_edit.clear()

        if os.path.isdir(input_path):
            if mode == "e":
                output_path = os.path.join(output_path, "encrypted_files")
                os.makedirs(output_path, exist_ok=True)
            self.process_folder_gui(input_path, output_path, mode)
        else:
            if mode == "e":
                output_file = os.path.join(output_path, f"{os.path.basename(input_path)}.enc")
                if encrypt_file(self.password, input_path, output_file, self.log_message):
                    QMessageBox.information(self, "Success", "File encrypted successfully.")
                else:
                    QMessageBox.critical(self, "Error", "Failed to encrypt file.")
            else:
                output_file = os.path.join(output_path, os.path.basename(input_path).replace(".enc", ""))
                if decrypt_file(self.password, input_path, output_file, self.log_message):
                    QMessageBox.information(self, "Success", "File decrypted successfully.")
                else:
                    QMessageBox.critical(self, "Error", "Failed to decrypt file.")
            self.progress_bar.setValue(100)

    def process_folder_gui(self, input_folder, output_folder, mode):
        """
        Process a folder in GUI mode using a separate thread.

        Args:
            input_folder (str): Path to the input folder.
            output_folder (str): Path to the output folder.
            mode (str): 'e' for encryption, 'd' for decryption.
        """
        # Run the folder processing in a separate thread to keep the GUI responsive
        self.thread = ProcessFolderThread(self.password, input_folder, output_folder, mode)
        self.thread.log_signal.connect(self.log_message)
        self.thread.progress_signal.connect(self.update_progress)
        self.thread.finished_signal.connect(self.process_finished)
        self.thread.start()

    def process_finished(self, success):
        """
        Handle the completion of the processing thread.

        Args:
            success (bool): True if processing was successful, False otherwise.
        """
        if success:
            QMessageBox.information(self, "Success", "Process completed successfully.")
        else:
            QMessageBox.critical(self, "Error", "An error occurred during processing.")
        self.progress_bar.setValue(100)

    def close_application(self):
        """
        Close the application with a confirmation dialog.
        """
        choice = QMessageBox.question(self, 'Exit', "Are you sure you want to quit?", QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No)
        if choice == QMessageBox.StandardButton.Yes:
            sys.exit()
        else:
            pass

class ProcessFolderThread(QtCore.QThread):
    """
    Thread class for processing folders without freezing the GUI.
    """
    log_signal = QtCore.pyqtSignal(str, str)
    progress_signal = QtCore.pyqtSignal(int, int)
    finished_signal = QtCore.pyqtSignal(bool)

    def __init__(self, password, input_folder, output_folder, mode):
        super().__init__()
        self.password = password
        self.input_folder = input_folder
        self.output_folder = output_folder
        self.mode = mode

    def run(self):
        """
        Run the folder processing in a separate thread.
        """
        try:
            process_folder(
                self.password,
                self.input_folder,
                self.output_folder,
                self.mode,
                log_function=self.emit_log,
                progress_callback=self.emit_progress
            )
            self.finished_signal.emit(True)
        except Exception as e:
            self.emit_log(f"Error: {e}", "red")
            self.finished_signal.emit(False)

    def emit_log(self, message, color):
        """
        Emit a log message to the main thread.

        Args:
            message (str): The message to log.
            color (str): The color of the message text.
        """
        self.log_signal.emit(message, color)

    def emit_progress(self, value, total):
        """
        Emit a progress update to the main thread.

        Args:
            value (int): The current progress value.
            total (int): The total value for completion.
        """
        self.progress_signal.emit(value, total)

# ========== Entry Point ==========

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--cli":
        try:
            main_cli()
        except KeyboardInterrupt:
            display_message("Exiting...", style="bold red")
            sys.exit()
    else:
        app = QApplication(sys.argv)
        window = MainWindow()
        window.show()
        sys.exit(app.exec())
