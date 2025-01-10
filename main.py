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
from PyQt5.QtWidgets import QStackedWidget
import pandas as pd
import csv
from datetime import datetime

# Constants for file paths
KEY_FILE = "vault_key.key"
VAULT_FILE = "vault.json"

CATEGORIES = {
    "Login Credentials": ["site", "username", "password"],
    "Social Security": ["name", "ssn", "notes"],
    "Credit Card": ["card_name", "card_number", "expiry_date", "cvv", "pin"],
    "Bank Account": ["bank_name", "account_number", "routing_number", "account_type"],
    "Secure Notes": ["title", "note_content"],
    "License": ["license_type", "license_number", "expiry_date", "holder_name"],
    "Passport": ["passport_number", "full_name", "issue_date", "expiry_date", "country"],
}

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

class CategoryInputDialog(QDialog):
    def __init__(self, category, parent=None):
        super().__init__(parent)
        self.category = category
        self.setWindowTitle(f"Add {category} Entry")
        self.setup_ui()
        
    def setup_ui(self):
        layout = QFormLayout()
        self.inputs = {}
        
        # Create input fields based on category
        for field in CATEGORIES[self.category]:
            if field == "password" or field == "pin" or field == "cvv" or field == "ssn":
                self.inputs[field] = QLineEdit()
                self.inputs[field].setEchoMode(QLineEdit.Password)
                
                # Add visibility toggle for sensitive fields
                toggle_btn = QPushButton()
                toggle_btn.setIcon(qta.icon('fa5s.eye'))
                toggle_btn.setCheckable(True)
                toggle_btn.setFixedWidth(30)
                
                # Create horizontal layout for input and toggle button
                field_layout = QHBoxLayout()
                field_layout.addWidget(self.inputs[field])
                field_layout.addWidget(toggle_btn)
                
                # Connect toggle button
                toggle_btn.clicked.connect(lambda checked, input=self.inputs[field], btn=toggle_btn: 
                    self.toggle_visibility(input, btn))
                
                layout.addRow(field.replace('_', ' ').title() + ":", field_layout)
            else:
                self.inputs[field] = QLineEdit()
                layout.addRow(field.replace('_', ' ').title() + ":", self.inputs[field])
        
        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addWidget(buttons)
        
        self.setLayout(layout)
    
    def toggle_visibility(self, input_field, button):
        if button.isChecked():
            input_field.setEchoMode(QLineEdit.Normal)
            button.setIcon(qta.icon('fa5s.eye-slash'))
        else:
            input_field.setEchoMode(QLineEdit.Password)
            button.setIcon(qta.icon('fa5s.eye'))
    
    def get_values(self):
        return {field: self.inputs[field].text() for field in self.inputs}

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
        self.password_input.returnPressed.connect(self.unlock_vault)  # Add this line

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
            QTableWidget::item {
                color: #ffffff;
            }
            QHeaderView::section {
                background-color: #4a4a4a;
                color: #ffffff;
                font-weight: bold;
                padding: 6px;
                border: 1px solid #555555;
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
        self.result_area.setHorizontalHeaderLabels(['Name/Site', 'ID/Username', 'Category'])
        self.result_area.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.result_area.setStyleSheet("background-color: #3b3b3b; border: 1px solid #555555;")
        self.result_area.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_area.customContextMenuRequested.connect(self.show_context_menu)
        self.vault_layout.addWidget(self.result_area)

        # Add Password Entry Section
        add_layout = QHBoxLayout()

        self.category_select = QComboBox()
        self.category_select.addItems(CATEGORIES.keys())
        add_layout.addWidget(self.category_select)

        self.add_button = QPushButton('Add Entry')
        self.add_button.setStyleSheet("background-color: #1976d2;")
        self.add_button.setIcon(qta.icon('fa5s.plus'))
        self.add_button.clicked.connect(self.add_password)
        add_layout.addWidget(self.add_button)

        self.vault_layout.addLayout(add_layout)

        # Password Strength Indicator
        self.password_strength_label = QLabel("")  # Empty initially
        self.password_strength_label.setFont(QFont('Arial', 12))
        self.password_strength_label.setStyleSheet("color: #ffffff;")
        self.vault_layout.addWidget(self.password_strength_label, alignment=Qt.AlignRight)

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
        self.result_area.setColumnCount(3)
        self.result_area.setHorizontalHeaderLabels(['Name/Site', 'ID/Username', 'Category'])
        categories = set()
        
        for entry in self.vault_data.get('entries', []):
            row_position = self.result_area.rowCount()
            self.result_area.insertRow(row_position)
            category = entry['category']
            
            # Set display values based on category
            if category == "Login Credentials":
                name_value = entry.get('site', '')
                id_value = entry.get('username', '')
            elif category == "Social Security":
                name_value = entry.get('name', '')
                id_value = entry.get('ssn', '')
            elif category == "Credit Card":
                name_value = entry.get('card_name', '')
                id_value = entry.get('card_number', '')
            elif category == "Bank Account":
                name_value = entry.get('bank_name', '')
                id_value = entry.get('account_number', '')
            elif category == "Secure Notes":
                name_value = entry.get('title', '')
                id_value = "Note"
            elif category == "License":
                name_value = entry.get('license_type', '')
                id_value = entry.get('license_number', '')
            elif category == "Passport":
                name_value = entry.get('full_name', '')
                id_value = entry.get('passport_number', '')
            else:
                name_value = "Unknown"
                id_value = "Unknown"
            
            self.result_area.setItem(row_position, 0, QTableWidgetItem(str(name_value)))
            self.result_area.setItem(row_position, 1, QTableWidgetItem(str(id_value)))
            self.result_area.setItem(row_position, 2, QTableWidgetItem(category))
            categories.add(category)
            
        # Populate category filter
        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        for category in sorted(categories):
            self.category_filter.addItem(category)
        self.category_filter.blockSignals(False)

    def add_password(self):
        if not self.master_authenticated:
            QMessageBox.warning(self, 'Error', 'Please unlock the vault first.')
            return

        selected_category = self.category_select.currentText()
        dialog = CategoryInputDialog(selected_category, self)
        
        if dialog.exec_() == QDialog.Accepted:
            values = dialog.get_values()
            
            # Create new entry
            new_entry = {
                'category': selected_category,
                **values
            }
            
            # Check for duplicates based on category-specific unique fields
            duplicate = False
            for entry in self.vault_data['entries']:
                if entry['category'] == selected_category:
                    if selected_category == "Login Credentials" and \
                       entry['site'] == values['site'] and \
                       entry['username'] == values['username']:
                        duplicate = True
                    elif selected_category == "Social Security" and \
                         entry['ssn'] == values['ssn']:
                        duplicate = True
                    # Add more category-specific duplicate checks as needed
            
            if duplicate:
                QMessageBox.warning(self, 'Error', 'A similar entry already exists.')
                return
            
            self.vault_data['entries'].append(new_entry)
            self.save_vault()
            self.load_vault_entries()
            QMessageBox.information(self, 'Success', 'Entry added successfully!')

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
        category = selected_entry['category']

        menu = QMenu(self)
        for field, value in selected_entry.items():
            if field != 'category':
                if field in ['password', 'pin', 'cvv', 'ssn']:
                    action = menu.addAction(qta.icon('fa5s.copy'), f"Copy {field.replace('_', ' ').title()}")
                    action.triggered.connect(lambda checked, v=value: self.copy_sensitive_data(v))
        
        menu.addSeparator()
        delete_action = menu.addAction(qta.icon('fa5s.trash'), "Delete")
        edit_action = menu.addAction(qta.icon('fa5s.edit'), "Edit")
        
        action = menu.exec_(self.result_area.viewport().mapToGlobal(pos))
        
        if action == delete_action:
            self.delete_entry(selected_row)
        elif action == edit_action:
            self.edit_entry(selected_row)

    def copy_sensitive_data(self, value):
        pyperclip.copy(value)
        QMessageBox.information(self, 'Copied', 'Sensitive data copied to clipboard. It will be cleared in 30 seconds.')
        QTimer.singleShot(30000, lambda: pyperclip.copy(''))

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

        # Create input fields based on the entry's category
        inputs = {}
        toggle_buttons = {}  # Keep track of toggle buttons
        for field in CATEGORIES[entry['category']]:
            if field in ['password', 'pin', 'cvv', 'ssn']:
                inputs[field] = QLineEdit(entry.get(field, ''))
                inputs[field].setEchoMode(QLineEdit.Password)
                
                # Add visibility toggle for sensitive fields
                toggle_btn = QPushButton()
                toggle_btn.setIcon(qta.icon('fa5s.eye'))
                toggle_btn.setCheckable(True)
                toggle_btn.setFixedWidth(30)
                toggle_buttons[field] = toggle_btn  # Store the button reference
                
                # Create horizontal layout for input and toggle button
                field_layout = QHBoxLayout()
                field_layout.addWidget(inputs[field])
                field_layout.addWidget(toggle_btn)
                
                # Connect toggle button using lambda with default arguments
                toggle_btn.clicked.connect(
                    lambda checked, f=field: self.toggle_visibility(inputs[f], toggle_buttons[f])
                )
                
                layout.addRow(field.replace('_', ' ').title() + ":", field_layout)
            else:
                inputs[field] = QLineEdit(entry.get(field, ''))
                layout.addRow(field.replace('_', ' ').title() + ":", inputs[field])

        # Display category (read-only)
        category_label = QLineEdit(entry['category'])
        category_label.setReadOnly(True)
        category_label.setStyleSheet("background-color: #3a3a3a; color: #ffffff;")
        layout.addRow("Category:", category_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        
        # Connect Enter key to accept the dialog
        for input_field in inputs.values():
            input_field.returnPressed.connect(dialog.accept)
        
        result = dialog.exec_()

        if result == QDialog.Accepted:
            for field in inputs:
                entry[field] = inputs[field].text().strip()

            self.save_vault()
            self.load_vault_entries()
            QMessageBox.information(self, 'Success', 'Entry updated successfully.')

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
            # Get the display values based on category
            category = entry['category']
            if category == "Login Credentials":
                name_value = entry.get('site', '')
                id_value = entry.get('username', '')
            elif category == "Social Security":
                name_value = entry.get('name', '')
                id_value = entry.get('ssn', '')
            elif category == "Credit Card":
                name_value = entry.get('card_name', '')
                id_value = entry.get('card_number', '')
            elif category == "Bank Account":
                name_value = entry.get('bank_name', '')
                id_value = entry.get('account_number', '')
            elif category == "Secure Notes":
                name_value = entry.get('title', '')
                id_value = "Note"
            elif category == "License":
                name_value = entry.get('license_type', '')
                id_value = entry.get('license_number', '')
            elif category == "Passport":
                name_value = entry.get('full_name', '')
                id_value = entry.get('passport_number', '')
            else:
                name_value = "Unknown"
                id_value = "Unknown"

            # Search in all relevant fields
            if (text in str(name_value).lower() or 
                text in str(id_value).lower() or 
                text in category.lower()):
                row_position = self.result_area.rowCount()
                self.result_area.insertRow(row_position)
                self.result_area.setItem(row_position, 0, QTableWidgetItem(str(name_value)))
                self.result_area.setItem(row_position, 1, QTableWidgetItem(str(id_value)))
                self.result_area.setItem(row_position, 2, QTableWidgetItem(category))

    def filter_entries(self):
        selected_category = self.category_filter.currentText()
        self.result_area.setRowCount(0)
        for entry in self.vault_data.get('entries', []):
            category = entry['category']
            if selected_category == "All Categories" or category == selected_category:
                row_position = self.result_area.rowCount()
                self.result_area.insertRow(row_position)
                
                # Set display values based on category
                if category == "Login Credentials":
                    name_value = entry.get('site', '')
                    id_value = entry.get('username', '')
                elif category == "Social Security":
                    name_value = entry.get('name', '')
                    id_value = entry.get('ssn', '')
                elif category == "Credit Card":
                    name_value = entry.get('card_name', '')
                    id_value = entry.get('card_number', '')
                elif category == "Bank Account":
                    name_value = entry.get('bank_name', '')
                    id_value = entry.get('account_number', '')
                elif category == "Secure Notes":
                    name_value = entry.get('title', '')
                    id_value = "Note"
                elif category == "License":
                    name_value = entry.get('license_type', '')
                    id_value = entry.get('license_number', '')
                elif category == "Passport":
                    name_value = entry.get('full_name', '')
                    id_value = entry.get('passport_number', '')
                else:
                    name_value = "Unknown"
                    id_value = "Unknown"
                
                self.result_area.setItem(row_position, 0, QTableWidgetItem(str(name_value)))
                self.result_area.setItem(row_position, 1, QTableWidgetItem(str(id_value)))
                self.result_area.setItem(row_position, 2, QTableWidgetItem(category))

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

    def get_formatted_entries(self):
        formatted_entries = []
        for entry in self.vault_data.get('entries', []):
            category = entry['category']
            if category == "Login Credentials":
                formatted = {
                    'Category': category,
                    'Name/Site': entry.get('site', ''),
                    'Username': entry.get('username', ''),
                    'Password': entry.get('password', '')
                }
            elif category == "Social Security":
                formatted = {
                    'Category': category,
                    'Name': entry.get('name', ''),
                    'SSN': entry.get('ssn', ''),
                    'Notes': entry.get('notes', '')
                }
            elif category == "Credit Card":
                formatted = {
                    'Category': category,
                    'Card Name': entry.get('card_name', ''),
                    'Card Number': entry.get('card_number', ''),
                    'Expiry Date': entry.get('expiry_date', ''),
                    'CVV': entry.get('cvv', ''),
                    'PIN': entry.get('pin', '')
                }
            # Add other categories as needed...
            formatted_entries.append(formatted)
        return formatted_entries

    def export_vault(self):
        if not self.master_authenticated:
            QMessageBox.warning(self, 'Error', 'Please unlock the vault first.')
            return

        options = QFileDialog.Options()
        formats = {
            'Encrypted Vault (*.enc)': self.export_encrypted,
            'Excel File (*.xlsx)': self.export_excel,
            'CSV File (*.csv)': self.export_csv,
            'JSON File (*.json)': self.export_json
        }
        
        format_str = ';;'.join(formats.keys())
        file_path, selected_format = QFileDialog.getSaveFileName(
            self, "Export Vault", "", format_str, options=options
        )
        
        if file_path:
            try:
                # Get the export function based on selected format
                export_func = formats[selected_format]
                export_func(file_path)
                QMessageBox.information(self, 'Export Successful', 'Data exported successfully!')
            except Exception as e:
                QMessageBox.warning(self, 'Error', f'Failed to export: {str(e)}')

    def export_encrypted(self, file_path):
        data_json = json.dumps(self.vault_data).encode()
        encrypted_data = self.cipher_suite.encrypt(data_json)
        with open(file_path, 'wb') as file:
            file.write(encrypted_data)

    def export_excel(self, file_path):
        formatted_entries = self.get_formatted_entries()
        if not formatted_entries:
            raise ValueError("No entries to export")
        
        df = pd.DataFrame(formatted_entries)
        writer = pd.ExcelWriter(file_path, engine='openpyxl')
        
        # Group entries by category and create separate sheets
        for category in df['Category'].unique():
            category_df = df[df['Category'] == category]
            category_df.to_excel(writer, sheet_name=category, index=False)
        
        writer.close()

    def export_csv(self, file_path):
        formatted_entries = self.get_formatted_entries()
        if not formatted_entries:
            raise ValueError("No entries to export")
        
        # Get all possible field names from all entries
        fieldnames = set()
        for entry in formatted_entries:
            fieldnames.update(entry.keys())
        
        with open(file_path, 'w', newline='', encoding='utf-8') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=sorted(fieldnames))
            writer.writeheader()
            writer.writerows(formatted_entries)

    def export_json(self, file_path):
        formatted_entries = self.get_formatted_entries()
        if not formatted_entries:
            raise ValueError("No entries to export")
        
        with open(file_path, 'w', encoding='utf-8') as jsonfile:
            json.dump(formatted_entries, jsonfile, indent=2)

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

    def toggle_visibility(self, input_field, button):
        """Helper method to toggle password visibility"""
        if button.isChecked():
            input_field.setEchoMode(QLineEdit.Normal)
            button.setIcon(qta.icon('fa5s.eye-slash'))
        else:
            input_field.setEchoMode(QLineEdit.Password)
            button.setIcon(qta.icon('fa5s.eye'))

    def edit_entry(self, index):
        entry = self.vault_data['entries'][index]
        dialog = QDialog(self)
        dialog.setWindowTitle("Edit Entry")
        layout = QFormLayout()

        # Create input fields based on the entry's category
        inputs = {}
        toggle_buttons = {}  # Keep track of toggle buttons
        for field in CATEGORIES[entry['category']]:
            if field in ['password', 'pin', 'cvv', 'ssn']:
                inputs[field] = QLineEdit(entry.get(field, ''))
                inputs[field].setEchoMode(QLineEdit.Password)
                
                # Add visibility toggle for sensitive fields
                toggle_btn = QPushButton()
                toggle_btn.setIcon(qta.icon('fa5s.eye'))
                toggle_btn.setCheckable(True)
                toggle_btn.setFixedWidth(30)
                toggle_buttons[field] = toggle_btn  # Store the button reference
                
                # Create horizontal layout for input and toggle button
                field_layout = QHBoxLayout()
                field_layout.addWidget(inputs[field])
                field_layout.addWidget(toggle_btn)
                
                # Connect toggle button using lambda with default arguments
                toggle_btn.clicked.connect(
                    lambda checked, f=field: self.toggle_visibility(inputs[f], toggle_buttons[f])
                )
                
                layout.addRow(field.replace('_', ' ').title() + ":", field_layout)
            else:
                inputs[field] = QLineEdit(entry.get(field, ''))
                layout.addRow(field.replace('_', ' ').title() + ":", inputs[field])

        # Display category (read-only)
        category_label = QLineEdit(entry['category'])
        category_label.setReadOnly(True)
        category_label.setStyleSheet("background-color: #3a3a3a; color: #ffffff;")
        layout.addRow("Category:", category_label)

        buttons = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)

        dialog.setLayout(layout)
        
        # Connect Enter key to accept the dialog
        for input_field in inputs.values():
            input_field.returnPressed.connect(dialog.accept)
        
        result = dialog.exec_()

        if result == QDialog.Accepted:
            for field in inputs:
                entry[field] = inputs[field].text().strip()

            self.save_vault()
            self.load_vault_entries()
            QMessageBox.information(self, 'Success', 'Entry updated successfully.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    vault = PasswordVault()
    vault.show()
    sys.exit(app.exec_())
