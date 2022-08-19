# PasswordVault
Encrypted Desktop Password Vault

Hugely inspired by Gomez0015's tkinter password vault (https://github.com/Gomez0015/PythonPasswordVault/blob/main/password_vault.py). This is my own take on this project, built for PySimpleGUI.

This program will create a SQLite database to store the master password and recovery key in one table and all of the services, usernames, and passwords in a separate table. All values stored in the table are encrypted with SHA256 encryption.

The encryption algorithm uses the default salt of b"Secret Phrase". This can be changed in line 23.

The Database will be created at the default working directory inside a folder called "Vault". This can be changed in line 52.

Adding or editing passwords has a "Generate Random Password" button that implements my RandomPWGen.py script (also included in this repository). By default, random passwords are 14 characters long and contain at least two upper case characters, two lower case characters, two numerals, and two special characters. The default length can be changed in lines 303 and 385.

Dependencies:
  base64
  cryptography
  hashlib
  os
  sqlite3
  uuid
  pyperclip
  PySimpleGUI
