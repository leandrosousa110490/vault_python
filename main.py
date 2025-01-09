import sys
from PyQt5.QtWidgets import (QApplication, QWidget, QVBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QMessageBox, QListWidget, QMenu)
from PyQt5.QtGui import QFont
from PyQt5.QtCore import Qt, QPoint
import hashlib
from cryptography.fernet import Fernet
import os

# Generate a key for encryption if it doesn't exist
def generate_key():
    if not os.path.exists("vault_key.key"):
        key = Fernet.generate_key()
        with open("vault_key.key", "wb") as key_file:
            key_file.write(key)

# Load the encryption key
def load_key():
    with open("vault_key.key", "rb") as key_file:
        return key_file.read()

# Ensure key exists
generate_key()
key = load_key()
cipher_suite = Fernet(key)

class PasswordVault(QWidget):
    def __init__(self):
        super().__init__()
        self.initUI()

    def initUI(self):
        self.setWindowTitle('Password Vault')
        self.setGeometry(400, 200, 500, 500)
        self.setStyleSheet("background-color: #2b2b2b; color: #dcdcdc;")

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(20)

        self.label = QLabel('Enter Vault Password:')
        self.label.setFont(QFont('Arial', 14))
        layout.addWidget(self.label)

        self.password_input = QLineEdit()
        self.password_input.setEchoMode(QLineEdit.Password)
        self.password_input.setStyleSheet("padding: 8px; border: 1px solid #555; border-radius: 5px; background-color: #3b3b3b;")
        layout.addWidget(self.password_input)

        self.unlock_button = QPushButton('Unlock Vault')
        self.unlock_button.setStyleSheet("background-color: #4caf50; padding: 10px; border-radius: 5px;")
        self.unlock_button.clicked.connect(self.unlock_vault)
        layout.addWidget(self.unlock_button)

        self.result_area = QListWidget()
        self.result_area.setContextMenuPolicy(Qt.CustomContextMenu)
        self.result_area.customContextMenuRequested.connect(self.show_context_menu)
        self.result_area.setStyleSheet("background-color: #3b3b3b; padding: 10px; border-radius: 5px;")
        layout.addWidget(self.result_area)

        self.add_password_label = QLabel('Add New Password Entry (Format: site,username,password):')
        self.add_password_label.setFont(QFont('Arial', 12))
        layout.addWidget(self.add_password_label)

        self.add_password_input = QLineEdit()
        self.add_password_input.setStyleSheet("padding: 8px; border: 1px solid #555; border-radius: 5px; background-color: #3b3b3b;")
        layout.addWidget(self.add_password_input)

        self.add_button = QPushButton('Add Entry')
        self.add_button.setStyleSheet("background-color: #1976d2; padding: 10px; border-radius: 5px;")
        self.add_button.clicked.connect(self.add_password)
        layout.addWidget(self.add_button)

        self.setLayout(layout)

    def unlock_vault(self):
        password = self.password_input.text()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        try:
            with open('vault.txt', 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
                stored_password, *entries = decrypted_data.split('\n')

                if hashed_password == stored_password:
                    self.result_area.addItems([entry for entry in entries if entry.strip()])
                else:
                    QMessageBox.warning(self, 'Error', 'Invalid Password')
        except FileNotFoundError:
            QMessageBox.warning(self, 'Error', 'Vault not found. Add a password to create the vault.')
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Error unlocking vault: {str(e)}')

    def add_password(self):
        new_entry = self.add_password_input.text().strip()
        password = self.password_input.text()
        hashed_password = hashlib.sha256(password.encode()).hexdigest()

        if not new_entry:
            QMessageBox.warning(self, 'Error', 'Cannot add an empty entry.')
            return

        try:
            with open('vault.txt', 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = cipher_suite.decrypt(encrypted_data).decode()
        except FileNotFoundError:
            decrypted_data = f'{hashed_password}\n'

        if new_entry not in decrypted_data.split('\n'):
            updated_data = decrypted_data + new_entry + '\n'
            encrypted_data = cipher_suite.encrypt(updated_data.encode())
            
            with open('vault.txt', 'wb') as file:
                file.write(encrypted_data)
            self.result_area.addItem(new_entry)
            QMessageBox.information(self, 'Success', 'Password added successfully!')
        else:
            QMessageBox.warning(self, 'Error', 'Duplicate entry detected.')
        self.add_password_input.clear()

    def show_context_menu(self, pos: QPoint):
        menu = QMenu(self)
        delete_action = menu.addAction("Delete")
        edit_action = menu.addAction("Edit")
        action = menu.exec_(self.result_area.mapToGlobal(pos))

        if action == delete_action:
            self.delete_entry()
        elif action == edit_action:
            self.edit_entry()

    def delete_entry(self):
        selected = self.result_area.currentRow()
        if selected != -1:
            item = self.result_area.takeItem(selected).text()
            self.update_vault_file(item, remove=True)

    def edit_entry(self):
        selected = self.result_area.currentRow()
        if selected != -1:
            item = self.result_area.item(selected).text()
            self.add_password_input.setText(item)
            self.result_area.takeItem(selected)
            self.update_vault_file(item, remove=True)

    def update_vault_file(self, entry, remove=False):
        try:
            with open('vault.txt', 'rb') as file:
                encrypted_data = file.read()
                decrypted_data = cipher_suite.decrypt(encrypted_data).decode().split('\n')

            if remove:
                decrypted_data.remove(entry)
            updated_data = '\n'.join(decrypted_data)
            encrypted_data = cipher_suite.encrypt(updated_data.encode())

            with open('vault.txt', 'wb') as file:
                file.write(encrypted_data)
        except Exception as e:
            QMessageBox.warning(self, 'Error', f'Error updating vault: {str(e)}')

if __name__ == '__main__':
    app = QApplication(sys.argv)
    vault = PasswordVault()
    vault.show()
    sys.exit(app.exec_())
