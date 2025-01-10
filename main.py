import sys
import os
import json
import hashlib
import base64
import pyperclip
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, 
    QMessageBox, QTableWidget, QMenu, QHBoxLayout, QAction, QDialog, QFormLayout, 
    QDialogButtonBox, QInputDialog, QComboBox, QFileDialog, QHeaderView, QTableWidgetItem  # Added QTableWidgetItem
)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QEvent, QPoint, QPropertyAnimation, QRect, QTimer
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import string
from PyQt5.QtWidgets import QStyle  # Add this import
import qtawesome as qta  # Add this import

# Constants for file paths
KEY_FILE = "vault_key.key"
VAULT_FILE = "vault.json"

# Generate a key for encryption if it doesn't exist
def generate_key():
    if not os.path.exists(KEY_FILE):
        key = Fernet.generate_key()
        with open(KEY_FILE, "wb") as key_file:
            key_file.write(key)

# Load the encryption key
def load_key():
    if not os.path.exists(KEY_FILE):
        generate_key()
    with open(KEY_FILE, "rb") as key_file:
        return key_file.read()

# Hash the master password using PBKDF2HMAC with a salt
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = kdf.derive(password.encode())
    return {
        'salt': base64.urlsafe_b64encode(salt).decode(),
        'key': base64.urlsafe_b64encode(key).decode()
    }

# Verify the master password
def verify_password(stored_password, stored_salt, provided_password):
    salt = base64.urlsafe_b64decode(stored_salt.encode())
    stored_key = base64.urlsafe_b64decode(stored_password.encode())
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    try:
        kdf.verify(provided_password.encode(), stored_key)
        return True
    except:
        return False

# Generate a strong password
def generate_strong_password(length=12):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(secrets.choice(characters) for i in range(length))

class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Change Master Password")
        self.setModal(True)
        self.setup_ui()
    
    def setup_ui(self):
        layout = QFormLayout()

        self.current_password = QLineEdit()
        self.current_password.setEchoMode(QLineEdit.Password)
        layout.addRow("Current Password:", self.current_password)

        self.new_password = QLineEdit()
        self.new_password.setEchoMode(QLineEdit.Password)
        layout.addRow("New Password:", self.new_password)

        self.confirm_password = QLineEdit()
        self.confirm_password.setEchoMode(QLineEdit.Password)
        layout.addRow("Confirm Password:", self.confirm_password)

        # Password visibility toggle
        self.toggle_visibility_btn = QPushButton()
        self.toggle_visibility_btn.setIcon(qta.icon('fa5s.eye'))
        self.toggle_visibility_btn.setCheckable(True)
        self.toggle_visibility_btn.setToolTip("Show/Hide Passwords")
        self.toggle_visibility_btn.clicked.connect(self.toggle_password_visibility)
        layout.addRow("", self.toggle_visibility_btn)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)

        self.setLayout(layout)
    
    def toggle_password_visibility(self):
        if self.toggle_visibility_btn.isChecked():
            self.current_password.setEchoMode(QLineEdit.Normal)
            self.new_password.setEchoMode(QLineEdit.Normal)
            self.confirm_password.setEchoMode(QLineEdit.Normal)
            self.toggle_visibility_btn.setIcon(qta.icon('fa5s.eye-slash'))
        else:
            self.current_password.setEchoMode(QLineEdit.Password)
            self.new_password.setEchoMode(QLineEdit.Password)
            self.confirm_password.setEchoMode(QLineEdit.Password)
            self.toggle_visibility_btn.setIcon(qta.icon('fa5s.eye'))

class PasswordVault(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()
        self.vault_data = {}
        self.cipher_suite = Fernet(load_key())
        self.master_authenticated = False
        self.inactivity_timer = QTimer()
        self.inactivity_timer.timeout.connect(self.lock_vault)
        self.inactivity_timeout = 5 * 60 * 1000  # 5 minutes
        self.inactivity_timer.start(self.inactivity_timeout)
        self.installEventFilter(self)
        # Set window icon
        self.setWindowIcon(qta.icon('fa5s.lock'))

    def initUI(self):
        self.setWindowTitle('Password Vault')
        self.setGeometry(400, 200, 800, 800)
        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #dcdcdc;
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                font-size: 14px;
            }
            QPushButton {
                background-color: #3a3a3a;
                border: 1px solid #555555;
                padding: 8px 16px;
                border-radius: 5px;
                color: #ffffff;
            }
            QPushButton:hover {
                background-color: #555555;
            }
            QLineEdit {
                padding: 8px;
                border: 1px solid #555555;
                border-radius: 5px;
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QTableWidget {
                background-color: #2b2b2b;
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 5px;
                color: #ffffff;
            }
            QComboBox {
                padding: 8px;
                border: 1px solid #555555;
                border-radius: 5px;
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QToolTip {
                background-color: #555555;
                color: #ffffff;
                border: 1px solid #ffffff;
            }
        """)
        self.layout = QVBoxLayout()
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)

        # Authentication Section
        self.auth_section = QWidget()
        self.auth_layout = QVBoxLayout()
        self.auth_layout.setSpacing(20)

        self.auth_label = QLabel('Enter Master Password:')
        self.auth_label.setFont(QFont('Arial', 16))
        self.auth_layout.addWidget(self.auth_label, alignment=Qt.AlignCenter)

        password_input_layout = QHBoxLayout()
        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setPlaceholderText("Master Password")
        password_input_layout.addWidget(self.password_input)

        self.show_password_btn = QPushButton()
        self.show_password_btn.setIcon(qta.icon('fa5s.eye'))
        self.show_password_btn.setCheckable(True)
        self.show_password_btn.setFixedWidth(30)
        self.show_password_btn.setToolTip("Show/Hide Password")
        self.show_password_btn.clicked.connect(self.toggle_password_visibility)
        password_input_layout.addWidget(self.show_password_btn)

        self.auth_layout.addLayout(password_input_layout)

        self.unlock_button = QPushButton('Unlock Vault')
        self.unlock_button.setStyleSheet("background-color: #4caf50;")
        self.unlock_button.clicked.connect(self.unlock_vault)
        self.auth_layout.addWidget(self.unlock_button, alignment=Qt.AlignCenter)

        self.auth_section.setLayout(self.auth_layout)
        self.layout.addWidget(self.auth_section)

        # Vault Content Section
        self.vault_section = QWidget()
        self.vault_layout = QVBoxLayout()
        self.vault_layout.setSpacing(10)
        self.vault_section.setLayout(self.vault_layout)
        self.vault_section.setVisible(False)  # Hidden until authentication

        # Search Bar
        search_layout = QHBoxLayout()
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search entries...")
        self.search_input.setStyleSheet("background-color: #3b3b3b;")
        self.search_input.textChanged.connect(self.search_entries)
        search_layout.addWidget(self.search_input)

        self.category_filter = QComboBox()
        self.category_filter.addItem("All Categories")
        self.category_filter.currentIndexChanged.connect(self.filter_entries)
        search_layout.addWidget(self.category_filter)

        self.vault_layout.addLayout(search_layout)

        # List of Entries - Using QTableWidget for better structure
        self.result_area = QTableWidget()
        self.result_area.setColumnCount(3)
        self.result_area.setHorizontalHeaderLabels(['Site', 'Username', 'Category'])
        self.result_area.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_area.setStyleSheet("background-color: #3b3b3b; border: 1px solid #555555;")
        self.result_area.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_area.customContextMenuRequested.connect(self.show_context_menu)
        self.vault_layout.addWidget(self.result_area)

        # Add Password Entry Section
        add_layout = QHBoxLayout()

        self.add_site_input = QLineEdit()
        self.add_site_input.setPlaceholderText("Site")
        add_layout.addWidget(self.add_site_input)

        self.add_username_input = QLineEdit()
        self.add_username_input.setPlaceholderText("Username")
        add_layout.addWidget(self.add_username_input)

        self.add_password_input = QLineEdit()
        self.add_password_input.setPlaceholderText("Password")
        self.add_password_input.setEchoMode(QLineEdit.Password)
        add_layout.addWidget(self.add_password_input)

        self.view_password_btn = QPushButton()
        self.view_password_btn.setIcon(qta.icon('fa5s.eye'))
        self.view_password_btn.setCheckable(True)
        self.view_password_btn.setFixedWidth(30)
        self.view_password_btn.setToolTip("Show/Hide Password")
        self.view_password_btn.clicked.connect(self.toggle_add_password_visibility)
        add_layout.addWidget(self.view_password_btn)

        self.add_button = QPushButton('Add Entry')
        self.add_button.setStyleSheet("background-color: #1976d2;")
        self.add_button.setIcon(qta.icon('fa5s.plus'))
        self.add_button.clicked.connect(self.add_password)
        add_layout.addWidget(self.add_button)

        self.generate_button = QPushButton('Generate Password')
        self.generate_button.setStyleSheet("background-color: #ff9800;")
        self.generate_button.setIcon(qta.icon('fa5s.key'))
        self.generate_button.clicked.connect(self.generate_password)
        add_layout.addWidget(self.generate_button)

        self.vault_layout.addLayout(add_layout)

        # Password Strength Indicator
        self.password_strength_label = QLabel("Password Strength: ")
        self.password_strength_label.setFont(QFont('Arial', 12))
        self.password_strength_label.setStyleSheet("color: #ffffff;")
        self.vault_layout.addWidget(self.password_strength_label, alignment=Qt.AlignRight)

        # Connect password input to strength checker
        self.add_password_input.textChanged.connect(self.check_password_strength)

        # Change Password and Export/Import Buttons
        action_layout = QHBoxLayout()

        self.change_password_btn = QPushButton('Change Master Password')
        self.change_password_btn.setStyleSheet("background-color: #ff5722;")
        self.change_password_btn.setIcon(qta.icon('fa5s.lock'))
        self.change_password_btn.clicked.connect(self.change_master_password)
        action_layout.addWidget(self.change_password_btn)

        self.export_button = QPushButton('Export Vault')
        self.export_button.setStyleSheet("background-color: #607d8b;")
        self.export_button.setIcon(qta.icon('fa5s.file-export'))
        self.export_button.clicked.connect(self.export_vault)
        action_layout.addWidget(self.export_button)

        self.import_button = QPushButton('Import Vault')
        self.import_button.setStyleSheet("background-color: #607d8b;")
        self.import_button.setIcon(qta.icon('fa5s.file-import'))
        self.import_button.clicked.connect(self.import_vault)
        action_layout.addWidget(self.import_button)

        self.vault_layout.addLayout(action_layout)

        self.layout.addWidget(self.vault_section)

        self.setLayout(self.layout)

    def toggle_password_visibility(self):
        if self.show_password_btn.isChecked():
            self.password_input.setEchoMode(QLineEdit.Normal)
            self.show_password_btn.setIcon(qta.icon('fa5s.eye-slash'))
        else:
            self.password_input.setEchoMode(QLineEdit.Password)
            self.show_password_btn.setIcon(qta.icon('fa5s.eye'))

    def toggle_add_password_visibility(self):
        if self.view_password_btn.isChecked():
            self.add_password_input.setEchoMode(QLineEdit.Normal)
            self.view_password_btn.setIcon(qta.icon('fa5s.eye-slash'))
        else:
            self.add_password_input.setEchoMode(QLineEdit.Password)
            self.view_password_btn.setIcon(qta.icon('fa5s.eye'))

    def unlock_vault(self):
        password = self.password_input.text()
        if not password:
            QMessageBox.warning(self, 'Error', 'Please enter the master password.')
            return

        if not os.path.exists(VAULT_FILE):
            # First time setup
            confirm = QMessageBox.question(
                self, 'Confirm Setup', 
                'No vault found. Do you want to create a new vault?',
                QMessageBox.Yes | QMessageBox.No, QMessageBox.No
            )
            if confirm == QMessageBox.Yes:
                hashed = hash_password(password)
                self.vault_data = {
                    'master_password': {
                        'salt': hashed['salt'],
                        'hash': hashed['key']
                    },
                    'entries': []
                }
                self.save_vault()
                self.master_authenticated = True
                self.post_unlock_setup()
                QMessageBox.information(self, 'Success', 'Vault created and unlocked.')
            return

        try:
            with open(VAULT_FILE, 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
                vault = json.loads(decrypted_data)
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Error reading vault: {str(e)}')
            return

        stored_master = vault.get('master_password', {})
        if not stored_master:
            QMessageBox.warning(self, 'Error', 'Vault is corrupted or missing master password.')
            return

        if verify_password(stored_master['hash'], stored_master['salt'], password):
            self.vault_data = vault
            self.master_authenticated = True
            self.animate_vault_opening()
        else:
            QMessageBox.warning(self, 'Error', 'Invalid Master Password.')

    def animate_vault_opening(self):
        # Simple fade-in animation for vault section
        self.vault_section.setWindowOpacity(0)
        self.vault_section.setVisible(True)

        self.animation = QPropertyAnimation(self.vault_section, b"windowOpacity")
        self.animation.setDuration(1000)
        self.animation.setStartValue(0)
        self.animation.setEndValue(1)
        self.animation.start()

        # Hide authentication section
        self.auth_section.setVisible(False)

        self.load_vault_entries()

    def post_unlock_setup(self):
        self.vault_section.setVisible(True)
        self.load_vault_entries()

    def load_vault_entries(self):
        self.result_area.setRowCount(0)
        categories = set()
        for entry in self.vault_data.get('entries', []):
            row_position = self.result_area.rowCount()
            self.result_area.insertRow(row_position)
            self.result_area.setItem(row_position, 0, QTableWidgetItem(entry['site']))
            self.result_area.setItem(row_position, 1, QTableWidgetItem(entry['username']))
            self.result_area.setItem(row_position, 2, QTableWidgetItem(entry['category']))
            categories.add(entry['category'])
        # Populate category filter
        self.category_filter.blockSignals(True)  # Prevent triggering filter_entries
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        for category in sorted(categories):
            self.category_filter.addItem(category)
        self.category_filter.blockSignals(False)

    def add_password(self):
        if not self.master_authenticated:
            QMessageBox.warning(self, 'Error', 'Please unlock the vault first.')
            return

        site = self.add_site_input.text().strip()
        username = self.add_username_input.text().strip()
        password = self.add_password_input.text().strip()

        if not site or not username or not password:
            QMessageBox.warning(self, 'Error', 'All fields (Site, Username, Password) are required.')
            return

        # Optional: Category selection
        category, ok = QInputDialog.getText(self, "Add Category", "Enter category for this entry (optional):")
        if not ok:
            category = "Uncategorized"
        category = category.strip() if category.strip() else "Uncategorized"

        # Check for duplicates
        for entry in self.vault_data['entries']:
            if entry['site'].lower() == site.lower() and entry['username'].lower() == username.lower():
                QMessageBox.warning(self, 'Error', 'An entry for this site and username already exists.')
                return

        new_entry = {
            'site': site,
            'username': username,
            'password': password,
            'category': category
        }

        self.vault_data['entries'].append(new_entry)
        self.save_vault()
        self.load_vault_entries()  # Refresh the list and categories
        QMessageBox.information(self, 'Success', 'Password entry added successfully!')
        self.add_site_input.clear()
        self.add_username_input.clear()
        self.add_password_input.clear()

    def generate_password(self):
        generated = generate_strong_password()
        self.add_password_input.setText(generated)
        QMessageBox.information(self, 'Password Generated', f'Generated Password: {generated}\nIt has been added to the password field.')

    def check_password_strength(self, password):
        strength = self.evaluate_password_strength(password)
        self.password_strength_label.setText(f"Password Strength: {strength}")

    def evaluate_password_strength(self, password):
        length = len(password)
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in string.punctuation for c in password)

        score = 0
        if length >= 8:
            score +=1
        if has_upper:
            score +=1
        if has_lower:
            score +=1
        if has_digit:
            score +=1
        if has_special:
            score +=1

        if score <=2:
            return "<span style='color:red;'>Weak</span>"
        elif score ==3 or score ==4:
            return "<span style='color:orange;'>Medium</span>"
        else:
            return "<span style='color:green;'>Strong</span>"

    def show_context_menu(self, pos: QPoint):
        menu = QMenu(self)
        copy_username_action = menu.addAction(qta.icon('fa5s.copy'), "Copy Username")
        copy_password_action = menu.addAction(qta.icon('fa5s.key'), "Copy Password")
        delete_action = menu.addAction(qta.icon('fa5s.trash'), "Delete")
        edit_action = menu.addAction(qta.icon('fa5s.edit'), "Edit")
        action = menu.exec_(self.result_area.viewport().mapToGlobal(pos))

        selected_row = self.result_area.currentRow()
        if selected_row == -1:
            return

        selected_entry = self.vault_data['entries'][selected_row]

        if action == copy_username_action:
            pyperclip.copy(selected_entry['username'])
            QMessageBox.information(self, 'Copied', 'Username copied to clipboard.')
        elif action == copy_password_action:
            pyperclip.copy(selected_entry['password'])
            QMessageBox.information(self, 'Copied', 'Password copied to clipboard. It will be cleared in 30 seconds.')
            # Set timer to clear clipboard
            QTimer.singleShot(30000, lambda: pyperclip.copy(''))
        elif action == delete_action:
            self.delete_entry(selected_row)
        elif action == edit_action:
            self.edit_entry(selected_row)

    def delete_entry(self, index):
        confirm = QMessageBox.question(
            self, 'Confirm Delete', 
            'Are you sure you want to delete this entry?',
            QMessageBox.Yes | QMessageBox.No, QMessageBox.No
        )
        if confirm == QMessageBox.Yes:
            del self.vault_data['entries'][index]
            self.save_vault()
            self.result_area.removeRow(index)
            QMessageBox.information(self, 'Deleted', 'Entry deleted successfully.')
            self.load_vault_entries()  # Refresh categories

    def edit_entry(self, index):
        entry = self.vault_data['entries'][index]
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Entry")
        layout = QFormLayout()

        site_input = QLineEdit(entry['site'])
        username_input = QLineEdit(entry['username'])
        password_input = QLineEdit(entry['password'])
        password_input.setEchoMode(QLineEdit.Password)
        category_input = QLineEdit(entry.get('category', 'Uncategorized'))

        # Password visibility toggle
        toggle_btn = QPushButton()
        toggle_btn.setIcon(qta.icon('fa5s.eye'))
        toggle_btn.setCheckable(True)
        toggle_btn.setFixedWidth(30)
        toggle_btn.setToolTip("Show/Hide Password")
        toggle_btn.clicked.connect(lambda: self.toggle_edit_password_visibility(password_input, toggle_btn))

        layout.addRow("Site:", site_input)
        layout.addRow("Username:", username_input)
        password_layout = QHBoxLayout()
        password_layout.addWidget(password_input)
        password_layout.addWidget(toggle_btn)
        layout.addRow("Password:", password_layout)
        layout.addRow("Category:", category_input)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            new_site = site_input.text().strip()
            new_username = username_input.text().strip()
            new_password = password_input.text().strip()
            new_category = category_input.text().strip() or "Uncategorized"

            if not new_site or not new_username or not new_password:
                QMessageBox.warning(self, 'Error', 'All fields (Site, Username, Password) are required.')
                return

            # Check for duplicates
            for i, existing_entry in enumerate(self.vault_data['entries']):
                if i != index and existing_entry['site'].lower() == new_site.lower() and existing_entry['username'].lower() == new_username.lower():
                    QMessageBox.warning(self, 'Error', 'Another entry with the same site and username already exists.')
                    return

            # Update the entry
            self.vault_data['entries'][index] = {
                'site': new_site,
                'username': new_username,
                'password': new_password,
                'category': new_category
            }
            self.save_vault()
            self.result_area.setItem(index, 0, QTableWidgetItem(new_site))
            self.result_area.setItem(index, 1, QTableWidgetItem(new_username))
            self.result_area.setItem(index, 2, QTableWidgetItem(new_category))
            QMessageBox.information(self, 'Success', 'Entry updated successfully.')
            self.load_vault_entries()  # Refresh categories

    def toggle_edit_password_visibility(self, password_input, toggle_btn):
        if toggle_btn.isChecked():
            password_input.setEchoMode(QLineEdit.Normal)
            toggle_btn.setIcon(qta.icon('fa5s.eye-slash'))
        else:
            password_input.setEchoMode(QLineEdit.Password)
            toggle_btn.setIcon(qta.icon('fa5s.eye'))

    def search_entries(self, text):
        text = text.lower()
        self.result_area.setRowCount(0)
        for entry in self.vault_data.get('entries', []):
            if text in entry['site'].lower() or text in entry['username'].lower() or text in entry['category'].lower():
                row_position = self.result_area.rowCount()
                self.result_area.insertRow(row_position)
                self.result_area.setItem(row_position, 0, QTableWidgetItem(entry['site']))
                self.result_area.setItem(row_position, 1, QTableWidgetItem(entry['username']))
                self.result_area.setItem(row_position, 2, QTableWidgetItem(entry['category']))

    def filter_entries(self):
        selected_category = self.category_filter.currentText()
        self.result_area.setRowCount(0)
        for entry in self.vault_data.get('entries', []):
            if selected_category == "All Categories" or entry['category'] == selected_category:
                row_position = self.result_area.rowCount()
                self.result_area.insertRow(row_position)
                self.result_area.setItem(row_position, 0, QTableWidgetItem(entry['site']))
                self.result_area.setItem(row_position, 1, QTableWidgetItem(entry['username']))
                self.result_area.setItem(row_position, 2, QTableWidgetItem(entry['category']))

    def change_master_password(self):
        if not self.master_authenticated:
            QMessageBox.warning(self, 'Error', 'You need to unlock the vault first.')
            return

        dialog = ChangePasswordDialog(self)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            current_password = dialog.current_password.text()
            new_password = dialog.new_password.text()
            confirm_password = dialog.confirm_password.text()

            if not current_password or not new_password or not confirm_password:
                QMessageBox.warning(self, 'Error', 'All fields are required.')
                return

            if new_password != confirm_password:
                QMessageBox.warning(self, 'Error', 'New passwords do not match.')
                return

            stored_master = self.vault_data.get('master_password', {})
            if not verify_password(stored_master['hash'], stored_master['salt'], current_password):
                QMessageBox.warning(self, 'Error', 'Current password is incorrect.')
                return

            # Update master password
            new_hashed = hash_password(new_password)
            self.vault_data['master_password'] = {
                'salt': new_hashed['salt'],
                'hash': new_hashed['key']
            }
            self.save_vault()
            QMessageBox.information(self, 'Success', 'Master password changed successfully.')
            dialog.close()

    def export_vault(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getSaveFileName(self, "Export Vault", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        if file_path:
            try:
                data_json = json.dumps(self.vault_data).encode()
                encrypted_data = self.cipher_suite.encrypt(data_json)
                with open(file_path, 'wb') as file:
                    file.write(encrypted_data)
                QMessageBox.information(self, 'Export Successful', 'Vault exported successfully!')
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Failed to export vault: {str(e)}')

    def import_vault(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(self, "Import Vault", "", "Encrypted Files (*.enc);;All Files (*)", options=options)
        if file_path:
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                    decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
                    vault = json.loads(decrypted_data)
                # Optionally, verify master password matches
                stored_master = vault.get('master_password', {})
                if not stored_master:
                    QMessageBox.warning(self, 'Error', 'Imported vault is missing master password.')
                    return
                # Optionally, you can prompt for the master password and verify
                self.vault_data = vault
                self.save_vault()
                self.load_vault_entries()
                QMessageBox.information(self, 'Import Successful', 'Vault imported successfully!')
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Failed to import vault: {str(e)}')

    def save_vault(self):
        try:
            data_json = json.dumps(self.vault_data).encode()
            encrypted_data = self.cipher_suite.encrypt(data_json)
            with open(VAULT_FILE, 'wb') as file:
                file.write(encrypted_data)
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Error saving vault: {str(e)}')

    def eventFilter(self, source, event):
        if event.type() in [QEvent.MouseMove, QEvent.KeyPress]:
            if self.master_authenticated:
                self.inactivity_timer.start(self.inactivity_timeout)
        return super().eventFilter(source, event)

    def lock_vault(self):
        self.vault_section.setVisible(False)
        self.auth_section.setVisible(True)
        self.master_authenticated = False
        self.password_input.clear()
        QMessageBox.information(self, 'Auto-Lock', 'Vault has been locked due to inactivity.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    vault = PasswordVault()
    vault.show()
    sys.exit(app.exec_())
