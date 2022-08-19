# PasswordVault
Encrypted Desktop Password Vault

Hugely inspired by Gomez0015's tkinter password vault (https://github.com/Gomez0015/PythonPasswordVault/blob/main/password_vault.py). This is my own take on this project, built for PySimpleGUI.

This program will create a SQLite database to store the master password and recovery key in one table and all of the services, usernames, and passwords in a separate table. All values stored in the table are encrypted with SHA256 encryption.

The Database will be created at the default working directory inside a folder called "Vault".

Dependencies:
  base64
  cryptography
  hashlib
  os
  sqlite3
  uuid
  pyperclip
  PySimpleGUI
