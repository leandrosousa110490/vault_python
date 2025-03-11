import sys
import os
import json
import hashlib
import base64
import pyperclip
import traceback
from PyQt5.QtWidgets import (
    QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, 
    QMessageBox, QTableWidget, QMenu, QHBoxLayout, QAction, QDialog, QFormLayout, 
    QDialogButtonBox, QInputDialog, QComboBox, QFileDialog, QHeaderView, QTableWidgetItem, QStyle, QGraphicsOpacityEffect, QShortcut, QCheckBox
)
from PyQt5.QtGui import QFont, QIcon, QBrush, QKeySequence, QColor, QPalette
from PyQt5.QtCore import Qt, QEvent, QPoint, QPropertyAnimation, QRect, QTimer, QEasingCurve
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets
import string
import qtawesome as qta  # Add this import
from PyQt5.QtWidgets import QStackedWidget
import pandas as pd
import csv
from datetime import datetime, timedelta
import platform

# Constants for file paths
KEY_FILE = "vault_key.key"
VAULT_FILE = "vault.json"

CATEGORIES = {
    "Login Credentials": ["site", "username", "password", "notes", "created_date", "expiry_date"],
    "Social Security": ["name", "ssn", "notes", "created_date"],
    "Credit Card": ["card_name", "card_number", "expiry_date", "cvv", "pin", "created_date"],
    "Bank Account": ["bank_name", "account_number", "routing_number", "account_type", "created_date"],
    "Secure Notes": ["title", "note_content", "created_date"],
    "License": ["license_type", "license_number", "expiry_date", "holder_name", "created_date"],
    "Passport": ["passport_number", "full_name", "issue_date", "expiry_date", "country", "created_date"],
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
        iterations=310000,  # Increased from 100000 for better security
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
        iterations=310000,  # Increased from 100000 to match hash_password
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
        self.toggle_buttons = {}  # Initialize the dictionary to store toggle buttons
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
                self.toggle_buttons[field] = toggle_btn  # Store the button reference
                
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
        self.detect_system_theme()
        self.initUI()
        self.vault_data = {}
        self.cipher_suite = Fernet(load_key())
        self.master_authenticated = False
        self.inactivity_timer = QTimer()
        self.inactivity_timer.timeout.connect(self.lock_vault)
        self.inactivity_timeout = 5 * 60 * 1000  # 5 minutes
        self.backup_directory = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
        self.error_log_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), "error_log.txt")
        
        # No longer creating backup directory automatically
        # Only create it when needed during backup operations
        
        self.inactivity_timer.start(self.inactivity_timeout)
        self.installEventFilter(self)
        # Set window icon
        self.setWindowIcon(qta.icon('fa5s.lock'))
        self.password_input.returnPressed.connect(self.unlock_vault)
        
        # Setup keyboard shortcuts
        self.setup_shortcuts()

    def detect_system_theme(self):
        """Set professional white and grey color scheme"""
        # Professional color scheme with whites and greys
        self.theme = {
            'bg_primary': '#ffffff',         # Pure white background
            'bg_secondary': '#f8f9fa',       # Very light grey for secondary elements
            'bg_tertiary': '#e9ecef',        # Light grey for tertiary elements
            'text_primary': '#212529',       # Dark grey, almost black for text
            'text_secondary': '#495057',     # Medium grey for secondary text
            'accent': '#4361ee',             # Professional blue accent
            'accent_light': '#4895ef',       # Lighter blue for hover states
            'warning': '#e63946',            # Professional red for warnings/delete
            'success': '#2a9d8f',            # Teal green for success messages
            'border': '#dee2e6',             # Light grey for borders
            'highlight': '#e7f5ff',          # Very light blue highlight
            'hover': '#f1f3f5',              # Light grey for hover states
            'selected': '#e7f5ff',           # Light blue for selected items
            'row_alt': '#f8f9fa',            # Alternating row color (light grey)
            'row_primary': '#ffffff',        # Primary row color (white)
            'header': '#e9ecef',             # Header background (light grey)
            'tooltip_bg': '#ffffff',         # White background for tooltips
            'tooltip_text': '#212529',       # Dark grey for tooltip text
            'menu_bg': '#ffffff',            # White background for menus
            'menu_text': '#212529',          # Dark grey for menu text
            'button_bg': '#f8f9fa',          # Light grey button background
            'button_text': '#212529',        # Dark grey button text
            'button_hover': '#e9ecef',       # Slightly darker grey for button hover
            'input_bg': '#ffffff',           # White input background
            'input_text': '#212529',         # Dark grey input text
            'input_border': '#ced4da',       # Medium grey input border
            'shadow': '0 2px 5px rgba(0,0,0,0.1)'  # Subtle shadow for depth
        }
        
    def setup_shortcuts(self):
        # Ctrl+C to copy selected item
        self.copy_shortcut = QShortcut(QKeySequence("Ctrl+C"), self)
        self.copy_shortcut.activated.connect(self.copy_selected_item)
        
        # Ctrl+F to focus search
        self.search_shortcut = QShortcut(QKeySequence("Ctrl+F"), self)
        self.search_shortcut.activated.connect(lambda: self.search_input.setFocus())
        
        # Ctrl+N to add new entry
        self.new_shortcut = QShortcut(QKeySequence("Ctrl+N"), self)
        self.new_shortcut.activated.connect(self.add_password)
        
        # Ctrl+E to edit selected entry
        self.edit_shortcut = QShortcut(QKeySequence("Ctrl+E"), self)
        self.edit_shortcut.activated.connect(lambda: self.edit_entry(self.result_area.currentRow()))
        
        # Delete key to delete selected entry
        self.delete_shortcut = QShortcut(QKeySequence("Delete"), self)
        self.delete_shortcut.activated.connect(lambda: self.delete_entry(self.result_area.currentRow()))
        
        # Escape to lock vault
        self.lock_shortcut = QShortcut(QKeySequence("Escape"), self)
        self.lock_shortcut.activated.connect(self.lock_vault)
        
        # F5 to refresh entries
        self.refresh_shortcut = QShortcut(QKeySequence("F5"), self)
        self.refresh_shortcut.activated.connect(self.load_vault_entries)

    def apply_theme_styles(self):
        """Apply the professional white and grey theme to all UI elements"""
        theme = self.theme
        self.setStyleSheet(f"""
            QWidget {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
                font-family: 'Segoe UI', Arial, sans-serif;
                font-size: 14px;
            }}
            QPushButton {{
                background-color: {theme['button_bg']};
                color: {theme['button_text']};
                border: 1px solid {theme['border']};
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
                min-height: 20px;
            }}
            QPushButton:hover {{
                background-color: {theme['button_hover']};
                border: 1px solid {theme['accent_light']};
            }}
            QPushButton:pressed {{
                background-color: {theme['bg_tertiary']};
            }}
            QLineEdit {{
                background-color: {theme['input_bg']};
                color: {theme['input_text']};
                border: 1px solid {theme['input_border']};
                border-radius: 4px;
                padding: 8px;
                selection-background-color: {theme['accent_light']};
            }}
            QLineEdit:focus {{
                border: 1px solid {theme['accent']};
            }}
            QTableWidget {{
                background-color: {theme['bg_primary']};
                alternate-background-color: {theme['row_alt']};
                color: {theme['text_primary']};
                gridline-color: {theme['border']};
                border: 1px solid {theme['border']};
                border-radius: 4px;
                selection-background-color: {theme['selected']};
                selection-color: {theme['text_primary']};
            }}
            QTableWidget::item {{
                padding: 8px;
                border-bottom: 1px solid {theme['border']};
            }}
            QTableWidget::item:selected {{
                background-color: {theme['selected']};
                color: {theme['text_primary']};
            }}
            QTableWidget::item:hover {{
                background-color: {theme['hover']};
            }}
            QHeaderView::section {{
                background-color: {theme['header']};
                color: {theme['text_primary']};
                font-weight: bold;
                padding: 8px;
                border: none;
                border-right: 1px solid {theme['border']};
                border-bottom: 1px solid {theme['border']};
            }}
            QHeaderView::section:checked {{
                background-color: {theme['selected']};
            }}
            QComboBox {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border']};
                border-radius: 4px;
                padding: 8px;
                min-height: 20px;
            }}
            QComboBox:hover {{
                border: 1px solid {theme['accent_light']};
            }}
            QComboBox::drop-down {{
                subcontrol-origin: padding;
                subcontrol-position: top right;
                width: 20px;
                border-left: 1px solid {theme['border']};
            }}
            QComboBox QAbstractItemView {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
                selection-background-color: {theme['selected']};
                selection-color: {theme['text_primary']};
                border: 1px solid {theme['border']};
            }}
            QToolTip {{
                background-color: {theme['tooltip_bg']};
                color: {theme['tooltip_text']};
                border: 1px solid {theme['border']};
                padding: 5px;
                border-radius: 3px;
                opacity: 255;
                font-weight: normal;
            }}
            QLabel {{
                color: {theme['text_primary']};
                font-weight: normal;
            }}
            QCheckBox {{
                color: {theme['text_primary']};
                spacing: 8px;
            }}
            QCheckBox::indicator {{
                width: 18px;
                height: 18px;
                border: 1px solid {theme['border']};
                border-radius: 3px;
            }}
            QCheckBox::indicator:checked {{
                background-color: {theme['accent']};
                border: 1px solid {theme['accent']};
            }}
            QMenu {{
                background-color: {theme['menu_bg']};
                color: {theme['menu_text']};
                border: 1px solid {theme['border']};
                border-radius: 4px;
            }}
            QMenu::item {{
                padding: 8px 20px;
            }}
            QMenu::item:selected {{
                background-color: {theme['selected']};
            }}
            QMenu::separator {{
                height: 1px;
                background-color: {theme['border']};
                margin: 5px 15px;
            }}
            QScrollBar:vertical {{
                background-color: {theme['bg_secondary']};
                width: 12px;
                margin: 0px;
            }}
            QScrollBar::handle:vertical {{
                background-color: {theme['bg_tertiary']};
                min-height: 20px;
                border-radius: 6px;
            }}
            QScrollBar::handle:vertical:hover {{
                background-color: #c5c9cc;
            }}
            QScrollBar:horizontal {{
                background-color: {theme['bg_secondary']};
                height: 12px;
                margin: 0px;
            }}
            QScrollBar::handle:horizontal {{
                background-color: {theme['bg_tertiary']};
                min-width: 20px;
                border-radius: 6px;
            }}
            QScrollBar::handle:horizontal:hover {{
                background-color: #c5c9cc;
            }}
            QTabWidget::pane {{
                border: 1px solid {theme['border']};
                border-radius: 4px;
                top: -1px;
            }}
            QTabBar::tab {{
                background-color: {theme['bg_secondary']};
                color: {theme['text_primary']};
                border: 1px solid {theme['border']};
                padding: 8px 16px;
                margin-right: 2px;
                border-top-left-radius: 4px;
                border-top-right-radius: 4px;
            }}
            QTabBar::tab:selected {{
                background-color: {theme['bg_primary']};
                border-bottom-color: {theme['bg_primary']};
            }}
            QDialog {{
                background-color: {theme['bg_primary']};
                color: {theme['text_primary']};
            }}
            QDialogButtonBox {{
                button-layout: 3;
            }}
        """)
        
    def initUI(self):
        self.setWindowTitle('Password Vault')
        self.setGeometry(400, 200, 800, 800)
        self.apply_theme_styles()
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
        self.result_area.setStyleSheet("""
            QTableWidget {
                background-color: #3b3b3b; 
                border: 1px solid #555555;
                border-radius: 5px;
                padding: 5px;
                selection-background-color: #555555;
            }
            QTableWidget::item {
                padding: 8px;
                border-bottom: 1px solid #555555;
            }
            QTableWidget::item:hover {
                background-color: #4a4a4a;
                color: #ffffff;
            }
            QTableWidget::item:selected {
                background-color: #2d5f8b;
                color: #ffffff;
            }
        """)
        self.result_area.setSelectionBehavior(QTableWidget.SelectRows)
        self.result_area.setEditTriggers(QTableWidget.NoEditTriggers)  # Make cells non-editable
        self.result_area.setAlternatingRowColors(True)  # Alternating row colors
        self.result_area.verticalHeader().setVisible(False)  # Hide row numbers
        self.result_area.setShowGrid(False)  # Hide the grid lines
        self.result_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_area.customContextMenuRequested.connect(self.show_context_menu)
        
        # Add hover effect for rows
        self.result_area.setMouseTracking(True)
        self.result_area.entered.connect(self.highlight_row)
        
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

        # Add backup toggle in settings
        self.enable_backups = False  # Default to disabled
        
        # Add a checkbox for enabling/disabling backups in the toolbar section
        backup_layout = QHBoxLayout()
        self.backup_checkbox = QCheckBox("Enable Automatic Backups")
        self.backup_checkbox.setChecked(False)
        self.backup_checkbox.stateChanged.connect(self.toggle_backups)
        backup_layout.addWidget(self.backup_checkbox)
        
        # Add restore backup button (initially hidden)
        self.restore_backup_btn = QPushButton('Restore Backup')
        self.restore_backup_btn.setIcon(qta.icon('fa5s.history'))
        self.restore_backup_btn.clicked.connect(self.restore_from_backup)
        self.restore_backup_btn.setVisible(False)  # Hidden by default
        backup_layout.addWidget(self.restore_backup_btn)
        
        # Add this to your toolbar or appropriate section
        action_layout.addLayout(backup_layout)

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
                        'hash': hashed['key'],
                        'last_changed': datetime.now().strftime("%Y-%m-%d")
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
            self.log_error("Error reading vault", e)
            QMessageBox.warning(self, 'Error', f'Error reading vault: {str(e)}')
            return

        stored_master = vault.get('master_password', {})
        if not stored_master:
            QMessageBox.warning(self, 'Error', 'Vault is corrupted or missing master password.')
            return

        if verify_password(stored_master['hash'], stored_master['salt'], password):
            self.vault_data = vault
            self.master_authenticated = True
            
            # Check master password age
            self.check_master_password_age()
            
            # Check for expiring passwords
            self.check_password_expirations()
            
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
        
        # Display keyboard shortcut help on first unlock
        self.show_keyboard_shortcuts_tooltip()

    def load_vault_entries(self):
        self.result_area.setRowCount(0)
        self.result_area.setColumnCount(3)
        self.result_area.setHorizontalHeaderLabels(['Name/Site', 'ID/Username', 'Category'])
        categories = set()
        
        # Enable grid for better visibility
        self.result_area.setShowGrid(True)
        self.result_area.setGridStyle(Qt.SolidLine)
        self.result_area.setAlternatingRowColors(True)
        
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
                id_value = "****" + entry.get('ssn', '')[-4:] if entry.get('ssn') and len(entry.get('ssn', '')) > 4 else '****'
            elif category == "Credit Card":
                name_value = entry.get('card_name', '')
                id_value = "****" + entry.get('card_number', '')[-4:] if entry.get('card_number') and len(entry.get('card_number', '')) > 4 else '****'
            elif category == "Bank Account":
                name_value = entry.get('bank_name', '')
                id_value = "****" + entry.get('account_number', '')[-4:] if entry.get('account_number') and len(entry.get('account_number', '')) > 4 else '****'
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
            
            # Create items with styles
            name_item = QTableWidgetItem(str(name_value))
            id_item = QTableWidgetItem(str(id_value))
            category_item = QTableWidgetItem(category)
            
            # Add icons based on category
            if category == "Login Credentials":
                name_item.setIcon(qta.icon('fa5s.globe', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.user', color=self.theme['accent']))
            elif category == "Social Security":
                name_item.setIcon(qta.icon('fa5s.id-card', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.shield-alt', color=self.theme['accent']))
            elif category == "Credit Card":
                name_item.setIcon(qta.icon('fa5s.credit-card', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.money-check', color=self.theme['accent']))
            elif category == "Bank Account":
                name_item.setIcon(qta.icon('fa5s.university', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.money-check-alt', color=self.theme['accent']))
            elif category == "Secure Notes":
                name_item.setIcon(qta.icon('fa5s.sticky-note', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.file-alt', color=self.theme['accent']))
            elif category == "License":
                name_item.setIcon(qta.icon('fa5s.id-badge', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.address-card', color=self.theme['accent']))
            elif category == "Passport":
                name_item.setIcon(qta.icon('fa5s.passport', color=self.theme['accent']))
                id_item.setIcon(qta.icon('fa5s.plane', color=self.theme['accent']))
                
            # Add tooltip with all field information
            tooltip = f"<h3 style='color: {self.theme['text_primary']};'>{category}</h3><table style='color: {self.theme['text_primary']};'>"
            for field, value in entry.items():
                if field != 'category' and value:
                    field_label = field.replace('_', ' ').title()
                    
                    # Mask sensitive information in tooltip
                    display_value = value
                    if field in ['password', 'ssn', 'cvv', 'pin']:
                        display_value = '•' * len(value)
                    elif field == 'card_number' and len(value) > 4:
                        display_value = '•' * (len(value) - 4) + value[-4:]
                    elif field == 'account_number' and len(value) > 4:
                        display_value = '•' * (len(value) - 4) + value[-4:]
                        
                    tooltip += f"<tr><td><b>{field_label}:</b></td><td>{display_value}</td></tr>"
            tooltip += "</table>"
            
            name_item.setToolTip(tooltip)
            id_item.setToolTip(tooltip)
            category_item.setToolTip(tooltip)
            
            self.result_area.setItem(row_position, 0, name_item)
            self.result_area.setItem(row_position, 1, id_item)
            self.result_area.setItem(row_position, 2, category_item)
            
            # Add category icon
            if category in ["Login Credentials", "Social Security", "Credit Card", "Bank Account", "Secure Notes", "License", "Passport"]:
                category_item.setIcon(qta.icon('fa5s.folder', color=self.theme['accent']))
            
            categories.add(category)
            
        # Populate category filter
        self.category_filter.blockSignals(True)
        self.category_filter.clear()
        self.category_filter.addItem("All Categories")
        for category in sorted(categories):
            self.category_filter.addItem(category)
        self.category_filter.blockSignals(False)
        
        # Resize the table for better display
        self.result_area.resizeRowsToContents()
        self.result_area.resizeColumnsToContents()

    def add_password(self):
        if not self.master_authenticated:
            QMessageBox.warning(self, 'Error', 'Please unlock the vault first.')
            return

        selected_category = self.category_select.currentText()
        dialog = CategoryInputDialog(selected_category, self)
        
        if dialog.exec_() == QDialog.Accepted:
            values = dialog.get_values()
            
            # Check if entry with same key information already exists
            duplicate = False
            
            if selected_category == "Login Credentials":
                for entry in self.vault_data.get('entries', []):
                    if (entry.get('category') == selected_category and 
                        entry.get('site') == values.get('site') and 
                        entry.get('username') == values.get('username')):
                        duplicate = True
                        break
            # Add similar checks for other categories
            
            if duplicate:
                QMessageBox.warning(self, 'Error', 'A similar entry already exists.')
                return
                
            # Add creation date
            values['created_date'] = datetime.now().strftime("%Y-%m-%d")
                
            self.vault_data.setdefault('entries', []).append({
                'category': selected_category,
                **values
            })
            
            self.save_vault()
            self.load_vault_entries()
            
            QMessageBox.information(self, 'Success', 'Entry added successfully.')

    def generate_password(self):
        generated = generate_strong_password()
        self.add_password_input.setText(generated)
        QMessageBox.information(self, 'Password Generated', f'Generated Password: {generated}\nIt has been added to the password field.')

    def check_password_strength(self, password):
        strength, feedback = self.evaluate_password_strength(password)
        self.password_strength_label.setText(f"Password Strength: {strength}")
        self.password_strength_label.setToolTip("<br>".join(feedback))

    def evaluate_password_strength(self, password):
        # More robust password strength checking
        score = 0
        feedback = []
        
        if len(password) < 8:
            feedback.append("Password is too short (minimum 8 characters)")
        else:
            score += 1
        
        if len(password) >= 12:
            score += 1
        
        if any(c.islower() for c in password):
            score += 1
        else:
            feedback.append("Add lowercase letters")
        
        if any(c.isupper() for c in password):
            score += 1
        else:
            feedback.append("Add uppercase letters")
        
        if any(c.isdigit() for c in password):
            score += 1
        else:
            feedback.append("Add numbers")
        
        if any(c in string.punctuation for c in password):
            score += 1
        else:
            feedback.append("Add special characters")
        
        # Check for common patterns
        common_patterns = ['123456', 'password', 'qwerty', 'admin', 'welcome']
        if any(pattern in password.lower() for pattern in common_patterns):
            score -= 1
            feedback.append("Avoid common patterns")
        
        # Return strength level and feedback
        if score <= 2:
            return "Weak", feedback
        elif score <= 4:
            return "Medium", feedback
        else:
            return "Strong", feedback

    def show_context_menu(self, pos: QPoint):
        selected_row = self.result_area.currentRow()
        if selected_row == -1:
            return
            
        # Get the item that was clicked on
        item = self.result_area.itemAt(pos)
        if not item:
            return
            
        # Get column to know what was clicked
        column = self.result_area.columnAt(pos.x())
        
        # Get the corresponding entry
        try:
            selected_entry = self.vault_data['entries'][selected_row]
        except (IndexError, KeyError):
            return
            
        category = selected_entry['category']
        
        # Create the menu
        menu = QMenu(self)
        
        # Determine what to copy based on the clicked column and category
        if column == 0:  # First column (Name/Site)
            if category == "Login Credentials":
                site = selected_entry.get('site', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Site ({site})")
                copy_action.triggered.connect(lambda checked, v=site: self.copy_sensitive_data(v, "Site"))
            elif category == "Social Security":
                name = selected_entry.get('name', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Name ({name})")
                copy_action.triggered.connect(lambda checked, v=name: self.copy_sensitive_data(v, "Name"))
            elif category == "Credit Card":
                card_name = selected_entry.get('card_name', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Card Name ({card_name})")
                copy_action.triggered.connect(lambda checked, v=card_name: self.copy_sensitive_data(v, "Card Name"))
            elif category == "Bank Account":
                bank_name = selected_entry.get('bank_name', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Bank Name ({bank_name})")
                copy_action.triggered.connect(lambda checked, v=bank_name: self.copy_sensitive_data(v, "Bank Name"))
            elif category == "Secure Notes":
                title = selected_entry.get('title', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Title ({title})")
                copy_action.triggered.connect(lambda checked, v=title: self.copy_sensitive_data(v, "Title"))
            elif category == "License":
                license_type = selected_entry.get('license_type', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy License Type ({license_type})")
                copy_action.triggered.connect(lambda checked, v=license_type: self.copy_sensitive_data(v, "License Type"))
            elif category == "Passport":
                full_name = selected_entry.get('full_name', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Full Name ({full_name})")
                copy_action.triggered.connect(lambda checked, v=full_name: self.copy_sensitive_data(v, "Full Name"))
                
        elif column == 1:  # Second column (ID/Username)
            if category == "Login Credentials":
                username = selected_entry.get('username', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Username ({username})")
                copy_action.triggered.connect(lambda checked, v=username: self.copy_sensitive_data(v, "Username"))
                
                # Also add password option when clicking on username
                password = selected_entry.get('password', '')
                copy_pass_action = menu.addAction(qta.icon('fa5s.key'), "Copy Password")
                copy_pass_action.triggered.connect(lambda checked, v=password: self.copy_sensitive_data(v, "Password"))
            elif category == "Social Security":
                ssn = selected_entry.get('ssn', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy SSN")
                copy_action.triggered.connect(lambda checked, v=ssn: self.copy_sensitive_data(v, "SSN"))
            elif category == "Credit Card":
                card_number = selected_entry.get('card_number', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Card Number")
                copy_action.triggered.connect(lambda checked, v=card_number: self.copy_sensitive_data(v, "Card Number"))
                
                # Add other credit card fields
                cvv = selected_entry.get('cvv', '')
                copy_cvv_action = menu.addAction(qta.icon('fa5s.shield-alt'), "Copy CVV")
                copy_cvv_action.triggered.connect(lambda checked, v=cvv: self.copy_sensitive_data(v, "CVV"))
                
                expiry = selected_entry.get('expiry_date', '')
                copy_expiry_action = menu.addAction(qta.icon('fa5s.calendar'), "Copy Expiry Date")
                copy_expiry_action.triggered.connect(lambda checked, v=expiry: self.copy_sensitive_data(v, "Expiry Date"))
            elif category == "Bank Account":
                account_number = selected_entry.get('account_number', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Account Number")
                copy_action.triggered.connect(lambda checked, v=account_number: self.copy_sensitive_data(v, "Account Number"))
                
                routing_number = selected_entry.get('routing_number', '')
                copy_routing_action = menu.addAction(qta.icon('fa5s.university'), "Copy Routing Number")
                copy_routing_action.triggered.connect(lambda checked, v=routing_number: self.copy_sensitive_data(v, "Routing Number"))
            elif category == "License":
                license_number = selected_entry.get('license_number', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy License Number")
                copy_action.triggered.connect(lambda checked, v=license_number: self.copy_sensitive_data(v, "License Number"))
            elif category == "Passport":
                passport_number = selected_entry.get('passport_number', '')
                copy_action = menu.addAction(qta.icon('fa5s.copy'), f"Copy Passport Number")
                copy_action.triggered.connect(lambda checked, v=passport_number: self.copy_sensitive_data(v, "Passport Number"))
        
        # Add general copy all fields menu
        if menu.actions():
            menu.addSeparator()
            
        copy_all_menu = menu.addMenu(qta.icon('fa5s.copy'), "Copy All Fields")
        
        # Add all fields that can be copied
        for field, value in selected_entry.items():
            if field != 'category' and value:
                field_name = field.replace('_', ' ').title()
                icon = qta.icon('fa5s.key') if field in ['password', 'pin', 'cvv', 'ssn'] else qta.icon('fa5s.copy')
                action = copy_all_menu.addAction(icon, f"Copy {field_name}")
                action.triggered.connect(lambda checked, f=field_name, v=value: self.copy_sensitive_data(v, f))
        
        # Add edit and delete options
        menu.addSeparator()
        edit_action = menu.addAction(qta.icon('fa5s.edit'), "Edit Entry")
        edit_action.triggered.connect(lambda: self.edit_entry(selected_row))
        
        delete_action = menu.addAction(qta.icon('fa5s.trash'), "Delete Entry")
        delete_action.triggered.connect(lambda: self.delete_entry(selected_row))
        
        # Show the menu
        menu.exec_(self.result_area.viewport().mapToGlobal(pos))

    def copy_sensitive_data(self, value, field_name=""):
        if not value:
            QMessageBox.information(self, 'Copy Failed', f'No {field_name.lower()} to copy.')
            return
            
        pyperclip.copy(value)
        
        # Show a transient success message (tooltip style)
        self.show_copy_notification(field_name)
        
        # Auto-clear clipboard after 30 seconds for security
        QTimer.singleShot(30000, lambda: pyperclip.copy(''))
        
    def show_copy_notification(self, field_name):
        """Show a non-blocking notification that fades out"""
        notification = QLabel(f"{field_name} copied to clipboard!", self)
        notification.setStyleSheet(f"""
            background-color: {self.theme['bg_primary']};
            color: {self.theme['text_primary']};
            border: 1px solid {self.theme['border']};
            border-radius: 6px;
            padding: 12px;
            font-weight: normal;
            box-shadow: {self.theme['shadow']};
        """)
        notification.setAlignment(Qt.AlignCenter)
        notification.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint)
        
        # Position at bottom right of main window
        main_pos = self.pos()
        main_size = self.size()
        notification.move(main_pos.x() + main_size.width() - 250, 
                         main_pos.y() + main_size.height() - 100)
        
        notification.show()
        
        # Setup fade-out animation
        opacity_effect = QGraphicsOpacityEffect(notification)
        notification.setGraphicsEffect(opacity_effect)
        
        fade_anim = QPropertyAnimation(opacity_effect, b"opacity")
        fade_anim.setDuration(2000)  # 2 seconds
        fade_anim.setStartValue(1.0)
        fade_anim.setEndValue(0.0)
        fade_anim.setEasingCurve(QEasingCurve.OutCubic)
        fade_anim.finished.connect(notification.deleteLater)
        
        # Start animation after a short delay
        QTimer.singleShot(800, fade_anim.start)

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
        if dialog.exec_() == QDialog.Accepted:
            current_password = dialog.current_password.text()
            new_password = dialog.new_password.text()
            confirm_password = dialog.confirm_password.text()
            
            # Validate inputs
            if not all([current_password, new_password, confirm_password]):
                QMessageBox.warning(self, 'Error', 'All fields are required.')
                return
                
            if new_password != confirm_password:
                QMessageBox.warning(self, 'Error', 'New passwords do not match.')
                return
                
            # Verify current password
            stored_master = self.vault_data.get('master_password', {})
            if not verify_password(stored_master['hash'], stored_master['salt'], current_password):
                QMessageBox.warning(self, 'Error', 'Current password is incorrect.')
                return
                
            try:
                # Update master password
                hashed = hash_password(new_password)
                self.vault_data['master_password'] = {
                    'salt': hashed['salt'],
                    'hash': hashed['key'],
                    'last_changed': datetime.now().strftime("%Y-%m-%d")
                }
                
                # Re-encrypt and save the vault
                self.save_vault()
                QMessageBox.information(self, 'Success', 'Master password changed successfully.')
            except Exception as e:
                self.log_error("Error changing master password", e)
                QMessageBox.critical(self, 'Error', f'Failed to change password: {str(e)}')

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
                # Add extension if not provided
                extension = selected_format.split('(*.')[1].split(')')[0]
                if not file_path.lower().endswith(f'.{extension}'):
                    file_path = f"{file_path}.{extension}"
                
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
            # Ask for master password
            password, ok = QInputDialog.getText(
                self, 'Master Password Required', 
                'Enter the master password for this vault:',
                QLineEdit.Password
            )
            if not ok or not password:
                return
                
            try:
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()
                    decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
                    vault = json.loads(decrypted_data)
                
                # Verify master password
                stored_master = vault.get('master_password', {})
                if not stored_master:
                    QMessageBox.warning(self, 'Error', 'Imported vault is missing master password.')
                    return
                    
                if not verify_password(stored_master['hash'], stored_master['salt'], password):
                    QMessageBox.warning(self, 'Error', 'Incorrect master password for imported vault.')
                    return
                
                # Confirm replacement
                confirm = QMessageBox.question(
                    self, 'Confirm Import', 
                    'This will replace your current vault. Continue?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if confirm == QMessageBox.Yes:
                    # Create backup of current vault before replacement
                    if os.path.exists(VAULT_FILE):
                        with open(VAULT_FILE, 'rb') as current_file:
                            current_data = current_file.read()
                            self.create_backup(current_data)
                    
                    self.vault_data = vault
                    self.save_vault()
                    
                    # If already authenticated, reload entries
                    if self.master_authenticated:
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
                
            # Only create backup if explicitly enabled
            if hasattr(self, 'enable_backups') and self.enable_backups:
                self.create_backup(encrypted_data)
                
        except Exception as e:
            self.log_error("Error saving vault", e)
            QMessageBox.warning(self, 'Error', f'Error saving vault: {str(e)}')
            
    def create_backup(self, encrypted_data):
        """Create a backup only if explicitly requested"""
        # Check if backups are enabled
        if not hasattr(self, 'enable_backups') or not self.enable_backups:
            return
            
        # Create backup directory if it doesn't exist yet
        if not os.path.exists(self.backup_directory):
            os.makedirs(self.backup_directory)
            
        # Create a backup with timestamp
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_file = os.path.join(self.backup_directory, f"vault_backup_{timestamp}.enc")
        
        try:
            with open(backup_file, 'wb') as file:
                file.write(encrypted_data)
                
            # Cleanup old backups (keep last 10)
            self.cleanup_old_backups()
        except Exception as e:
            print(f"Backup creation failed: {str(e)}")
            
    def cleanup_old_backups(self):
        try:
            # List all backups and sort by creation time
            backups = [os.path.join(self.backup_directory, f) for f in os.listdir(self.backup_directory) 
                      if f.startswith("vault_backup_") and f.endswith(".enc")]
            backups.sort(key=lambda x: os.path.getctime(x))
            
            # Remove oldest backups if we have more than 10
            while len(backups) > 10:
                os.remove(backups[0])
                backups.pop(0)
        except Exception as e:
            print(f"Backup cleanup failed: {str(e)}")
            
    def eventFilter(self, source, event):
        # Reset inactivity timer on user interaction
        if event.type() in [QEvent.MouseButtonPress, QEvent.KeyPress]:
            if self.master_authenticated:
                self.inactivity_timer.start(self.inactivity_timeout)
        return super().eventFilter(source, event)
        
    def lock_vault(self):
        if self.master_authenticated:
            self.master_authenticated = False
            self.vault_section.setVisible(False)
            self.auth_section.setVisible(True)
            self.password_input.clear()
            QMessageBox.information(self, 'Vault Locked', 'Your vault has been locked due to inactivity.')

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

    def restore_from_backup(self):
        """List available backups"""
        # Check if backups are enabled
        if not hasattr(self, 'enable_backups') or not self.enable_backups:
            QMessageBox.information(self, 'Backups Disabled', 'Automatic backups are currently disabled. Enable them first to use this feature.')
            return
            
        # Check if backup directory exists
        if not os.path.exists(self.backup_directory):
            QMessageBox.information(self, 'No Backups', 'No backup directory found. Enable backups and make changes to create backups.')
            return
            
        # List available backups
        backups = [f for f in os.listdir(self.backup_directory) 
                  if f.startswith("vault_backup_") and f.endswith(".enc")]
        
        if not backups:
            QMessageBox.information(self, 'No Backups', 'No backup files found.')
            return
            
        try:
            # Sort by date (newest first)
            backups.sort(reverse=True)
            
            # Format dates for display
            backup_display = []
            for backup in backups:
                try:
                    # Extract date from filename
                    date_str = backup.replace("vault_backup_", "").replace(".enc", "")
                    date_obj = datetime.strptime(date_str, "%Y%m%d_%H%M%S")
                    formatted_date = date_obj.strftime("%Y-%m-%d %H:%M:%S")
                    backup_display.append(f"{formatted_date} - {backup}")
                except:
                    backup_display.append(backup)
            
            # Let user select a backup
            selected, ok = QInputDialog.getItem(
                self, 'Restore Backup', 
                'Select a backup to restore:',
                backup_display, 0, False
            )
            
            if ok and selected:
                # Extract filename from selected item
                backup_file = selected.split(" - ")[1] if " - " in selected else selected
                backup_path = os.path.join(self.backup_directory, backup_file)
                
                # Ask for master password
                password, password_ok = QInputDialog.getText(
                    self, 'Master Password Required', 
                    'Enter the master password for this backup:',
                    QLineEdit.Password
                )
                
                if not password_ok or not password:
                    return
                    
                # Verify and restore
                with open(backup_path, 'rb') as file:
                    encrypted_data = file.read()
                    decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
                    vault = json.loads(decrypted_data)
                
                # Verify master password
                stored_master = vault.get('master_password', {})
                if not stored_master:
                    QMessageBox.warning(self, 'Error', 'Backup is missing master password data.')
                    return
                    
                if not verify_password(stored_master['hash'], stored_master['salt'], password):
                    QMessageBox.warning(self, 'Error', 'Incorrect master password for backup.')
                    return
                
                # Confirm replacement
                confirm = QMessageBox.question(
                    self, 'Confirm Restore', 
                    'This will replace your current vault with the selected backup. Continue?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                
                if confirm == QMessageBox.Yes:
                    # Backup current state before restoration
                    if os.path.exists(VAULT_FILE):
                        with open(VAULT_FILE, 'rb') as current_file:
                            current_data = current_file.read()
                            self.create_backup(current_data)
                    
                    # Restore from backup
                    with open(VAULT_FILE, 'wb') as vault_file:
                        vault_file.write(encrypted_data)
                    
                    self.vault_data = vault
                    
                    # If already authenticated, reload entries
                    if self.master_authenticated:
                        self.load_vault_entries()
                    
                    QMessageBox.information(self, 'Restore Successful', 'Vault has been restored from backup.')
                
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Failed to restore backup: {str(e)}')

    def log_error(self, error_msg, exception=None):
        """Log errors to a file for debugging"""
        try:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            with open(self.error_log_file, 'a') as log_file:
                log_file.write(f"\n[{timestamp}] {error_msg}\n")
                if exception:
                    log_file.write(f"Exception details: {str(exception)}\n")
                    log_file.write(traceback.format_exc())
                    log_file.write("\n" + "-"*50 + "\n")
        except:
            # If we can't even log the error, there's not much we can do
            pass

    def check_master_password_age(self):
        """Check if master password is older than 90 days"""
        master_info = self.vault_data.get('master_password', {})
        last_changed = master_info.get('last_changed')
        
        if not last_changed:
            # Add the field if it doesn't exist
            self.vault_data['master_password']['last_changed'] = datetime.now().strftime("%Y-%m-%d")
            self.save_vault()
            return
            
        try:
            change_date = datetime.strptime(last_changed, "%Y-%m-%d")
            days_old = (datetime.now() - change_date).days
            
            if days_old > 90:
                result = QMessageBox.question(
                    self, 'Security Alert', 
                    f'Your master password is {days_old} days old. It is recommended to change it regularly.\n\nDo you want to change it now?',
                    QMessageBox.Yes | QMessageBox.No, QMessageBox.No
                )
                if result == QMessageBox.Yes:
                    self.change_master_password()
        except Exception as e:
            self.log_error("Error checking master password age", e)
    
    def check_password_expirations(self):
        """Check for credentials that are about to expire"""
        warning_days = 30  # Warn if expiring within 30 days
        today = datetime.now().date()
        expiring_items = []
        
        try:
            for entry in self.vault_data.get('entries', []):
                # Check expiry date fields based on category
                expiry_date = None
                name = None
                
                if entry['category'] == "Credit Card":
                    expiry_date = entry.get('expiry_date')
                    name = entry.get('card_name')
                elif entry['category'] == "License":
                    expiry_date = entry.get('expiry_date')
                    name = entry.get('license_type')
                elif entry['category'] == "Passport":
                    expiry_date = entry.get('expiry_date')
                    name = f"Passport: {entry.get('full_name')}"
                elif entry['category'] == "Login Credentials":
                    expiry_date = entry.get('expiry_date')
                    name = entry.get('site')
                
                if expiry_date:
                    try:
                        exp_date = datetime.strptime(expiry_date, "%Y-%m-%d").date()
                        days_to_expiry = (exp_date - today).days
                        
                        if 0 < days_to_expiry <= warning_days:
                            expiring_items.append((name, expiry_date, days_to_expiry))
                    except:
                        # Skip entries with invalid date format
                        pass
                        
            # Show warning for expiring items
            if expiring_items:
                message = "The following items are about to expire:\n\n"
                for name, date, days in expiring_items:
                    message += f"• {name}: {date} ({days} days remaining)\n"
                
                QMessageBox.warning(self, 'Expiration Alert', message)
        except Exception as e:
            self.log_error("Error checking password expirations", e)

    def highlight_row(self, model_index):
        """Highlight row on hover"""
        for i in range(self.result_area.rowCount()):
            for j in range(self.result_area.columnCount()):
                item = self.result_area.item(i, j)
                if item:
                    if i == model_index.row():
                        item.setBackground(QColor(self.theme['highlight']))
                    else:
                        # Let the alternating row colors handle this
                        item.setBackground(QColor())

    def copy_selected_item(self):
        if not self.master_authenticated:
            return
            
        selected_row = self.result_area.currentRow()
        if selected_row == -1:
            return
            
        try:
            selected_entry = self.vault_data['entries'][selected_row]
            category = selected_entry['category']
            
            # Determine what to copy based on the category
            if category == "Login Credentials":
                username = selected_entry.get('username', '')
                self.copy_sensitive_data(username, "Username")
            elif category == "Social Security":
                ssn = selected_entry.get('ssn', '')
                self.copy_sensitive_data(ssn, "SSN")
            elif category == "Credit Card":
                card_number = selected_entry.get('card_number', '')
                self.copy_sensitive_data(card_number, "Card Number")
            elif category == "Bank Account":
                account_number = selected_entry.get('account_number', '')
                self.copy_sensitive_data(account_number, "Account Number")
            elif category == "Secure Notes":
                note_content = selected_entry.get('note_content', '')
                self.copy_sensitive_data(note_content, "Note Content")
            elif category == "License":
                license_number = selected_entry.get('license_number', '')
                self.copy_sensitive_data(license_number, "License Number")
            elif category == "Passport":
                passport_number = selected_entry.get('passport_number', '')
                self.copy_sensitive_data(passport_number, "Passport Number")
        except (IndexError, KeyError) as e:
            self.log_error("Error copying selected item", e)

    def show_keyboard_shortcuts_tooltip(self):
        """Show a tooltip with keyboard shortcuts"""
        shortcuts_tooltip = QLabel(f"""
            <h3 style='color: {self.theme['text_primary']};'>Keyboard Shortcuts</h3>
            <table style='color: {self.theme['text_primary']};'>
                <tr><td><b>Ctrl+C</b></td><td>Copy selected item</td></tr>
                <tr><td><b>Ctrl+F</b></td><td>Focus search</td></tr>
                <tr><td><b>Ctrl+N</b></td><td>Add new entry</td></tr>
                <tr><td><b>Ctrl+E</b></td><td>Edit selected entry</td></tr>
                <tr><td><b>Delete</b></td><td>Delete selected entry</td></tr>
                <tr><td><b>Escape</b></td><td>Lock vault</td></tr>
                <tr><td><b>F5</b></td><td>Refresh entries</td></tr>
            </table>
            <p style='color: {self.theme['text_primary']};'>Right-click on any entry to see more options.</p>
        """, self)
        
        shortcuts_tooltip.setStyleSheet(f"""
            background-color: {self.theme['bg_primary']};
            color: {self.theme['text_primary']};
            border: 1px solid {self.theme['border']};
            border-radius: 8px;
            padding: 15px;
            font-weight: normal;
            box-shadow: {self.theme['shadow']};
        """)
        shortcuts_tooltip.setWindowFlags(Qt.FramelessWindowHint | Qt.Tool | Qt.WindowStaysOnTopHint)
        shortcuts_tooltip.setAlignment(Qt.AlignLeft)
        
        # Position in center of window
        main_pos = self.pos()
        main_size = self.size()
        tooltip_size = shortcuts_tooltip.sizeHint()
        
        shortcuts_tooltip.move(
            main_pos.x() + (main_size.width() - tooltip_size.width()) // 2,
            main_pos.y() + (main_size.height() - tooltip_size.height()) // 2
        )
        
        shortcuts_tooltip.show()
        
        # Fade out after 8 seconds
        opacity_effect = QGraphicsOpacityEffect(shortcuts_tooltip)
        shortcuts_tooltip.setGraphicsEffect(opacity_effect)
        
        fade_anim = QPropertyAnimation(opacity_effect, b"opacity")
        fade_anim.setDuration(1000)  # 1 second
        fade_anim.setStartValue(1.0)
        fade_anim.setEndValue(0.0)
        fade_anim.setEasingCurve(QEasingCurve.OutCubic)
        fade_anim.finished.connect(shortcuts_tooltip.deleteLater)
        
        # Start fade animation after 8 seconds
        QTimer.singleShot(8000, fade_anim.start)

    def toggle_backups(self, state):
        """Enable or disable automatic backups"""
        self.enable_backups = (state == Qt.Checked)
        
        # Show/hide restore button based on backup status
        self.restore_backup_btn.setVisible(self.enable_backups)
        
        if self.enable_backups and not os.path.exists(self.backup_directory):
            os.makedirs(self.backup_directory)
            
        status = "enabled" if self.enable_backups else "disabled"
        QMessageBox.information(self, 'Backup Settings', f'Automatic backups are now {status}.')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    vault = PasswordVault()
    vault.show()
    sys.exit(app.exec_())
