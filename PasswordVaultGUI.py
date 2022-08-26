import base64
import hashlib
import os
import sqlite3
import uuid

import pyperclip
import PySimpleGUI as sg
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

import RandomPWGen

# ----------------------------------------------------------------
#
# Setup Encryption / Decryption
#
# ----------------------------------------------------------------

backend = default_backend()
salt = b"Secret Phrase"
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000, backend=backend
)

encryptionKey = 0


def encrypt(text: bytes, key: bytes) -> bytes:
    """
    Returns the encrypted string as bytes

        Parameters:
            text (bytes): The bytes of the string to be encrypted
            key (bytes): The bytes of the encryption key to be used

        Returns:
            Fernet(key).encrypt(text) (bytes): The bytes of the encrypted string
    """
    return Fernet(key).encrypt(text)


def decrypt(text: bytes, key: bytes) -> bytes:
    """
    Returns the deecrypted string as bytes

        Parameters:
            text (bytes): The bytes of the string to be decrypted
            key (bytes): The bytes of the encryption key to be used

        Returns:
            Fernet(key).encrypt(text) (bytes): The bytes of the decrypted string
    """
    return Fernet(key).decrypt(text)


def getHash(input: str) -> str:
    """
    Returns a SHA256 hash

        Parameters:
            input (str): The string to be hashed

        Returns:
            hash (str): The hash as a string
    """
    hash = hashlib.sha256(input)
    hash = hash.hexdigest()

    return hash


# ----------------------------------------------------------------
#
# Setup Database
#
# ----------------------------------------------------------------

path = os.getcwd() + "/Vault/vault.db"
with sqlite3.connect(path) as db:
    cursor = db.cursor()

cursor.execute(
    """CREATE TABLE IF NOT EXISTS tblMaster (
        id INTEGER PRIMARY KEY,
        Master TEXT NOT NULL,
        RecoveryKey TEXT NOT NULL);"""
)

cursor.execute(
    """CREATE TABLE IF NOT EXISTS tblVault (
        id INTEGER PRIMARY KEY,
        Service TEXT NOT NULL,
        Username TEXT NOT NULL,
        Password TEXT NOT NULL);"""
)


# ----------------------------------------------------------------
#
# Setup the GUI
#
# ----------------------------------------------------------------

sg.theme("DarkGrey15")


def windowSetMasterPassword():
    layout = [
        [
            sg.Text("Set Master Password:", size=(25, 1)),
            sg.InputText("", key="MasterPass", password_char="*", size=(25, 1)),
        ],
        [
            sg.Text("Confirm Master Password:", size=(25, 1)),
            sg.InputText("", key="ConfMasterPass", password_char="*", size=(25, 1)),
        ],
        [sg.Text("", key="Error", size=(25, 1))],
        [sg.Submit("Submit", bind_return_key=True)],
    ]

    window = sg.Window("Set Master Password", layout, element_justification="c")

    event, values = window.read()

    if event == sg.WIN_CLOSED:
        window.close()
        quit()
    password = values["MasterPass"]
    passwordConfirm = values["ConfMasterPass"]

    if password == passwordConfirm:
        sqlDelete = "DELETE FROM tblMaster WHERE id = 1"
        cursor.execute(sqlDelete)

        hashedMaster = getHash(password.encode("utf-8"))
        key = str(uuid.uuid4().hex)
        recoveryKey = getHash(key.encode("utf-8"))

        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(password.encode()))

        sqlInsert = (
            """INSERT INTO tblMaster (id, Master, RecoveryKey) VALUES (1, ?, ?)"""
        )
        cursor.execute(sqlInsert, ((hashedMaster), (recoveryKey)))
        db.commit()

        window.close()
        windowRecovery(key)
    else:
        window["MasterPass"].update(value="")
        window["ConfMasterPass"].update(value="")
        window["Error"].update(value="Password Mismatch.")
        window["MasterPass"].set_focus()


def windowRecovery(key):
    layout = [
        [sg.Text("Save Recovery Key:")],
        [sg.Text(key, size=(25, 5))],
        [sg.Button("Copy Key", key="Copy", bind_return_key=True)],
        [sg.Button("Done", key="Done")],
    ]

    window = sg.Window("Save Recovery Key", layout, element_justification="c")

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            break
        elif event == "Copy":
            pyperclip.copy(key)
            sg.popup("Recovery Key", key + " copied to clipboard.")
            windowPasswordVault()
            break
        elif event == "Done":
            windowPasswordVault()
            break
    window.close()


def windowResetMaster():
    def recoverPass(enteredKey: str) -> str:
        hashKey = getHash(str(enteredKey).encode("utf-8"))
        cursor.execute(
            "SELECT * FROM tblMaster WHERE id = 1 AND RecoveryKey = ?", [(hashKey)]
        )
        return cursor.fetchall()

    layout = [
        [
            sg.Text("Enter Recovery Key:", size=(25, 1)),
            sg.InputText(size=(25, 1), key="strRecKey"),
        ],
        [sg.Text(size=(25, 1), key="Error")],
        [sg.Button("Recover", key="Recover"), sg.Button("Cancel", key="Cancel")],
    ]

    window = sg.Window("Recovery", layout, element_justification="c")

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            break
        elif event == "Cancel":
            window.close()
            windowLogin()
            break
        elif event == "Recover":
            recoveryKeyKey = recoverPass(values["strRecKey"])
            if recoveryKeyKey:
                window.close()
                windowSetMasterPassword()
                break
            else:
                sg.Popup("Invalid Recovery Key")
                window.close()
                windowResetMaster()
                break

    window.close()


def windowLogin():
    layout = [
        [sg.Text("Master Password:", size=(25, 1))],
        [sg.InputText(size=(25, 1), key="MasterPassword", password_char="*")],
        [sg.Text(size=(25, 1), key="Error")],
        [
            sg.Button("Login", key="Login", bind_return_key=True),
            (sg.Button("Reset Master Password", key="Reset")),
        ],
    ]

    window = sg.Window("Login", layout, element_justification="c")

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            quit()
        elif event == "Login":
            hashedMaster = getHash(values["MasterPassword"].encode("utf-8"))
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(
                kdf.derive(values["MasterPassword"].encode())
            )
            cursor.execute(
                "SELECT * FROM tblMaster WHERE id = 1 AND Master = ?",
                [(hashedMaster)],
            )
            match = cursor.fetchall()

            if match:
                window.close()
                windowPasswordVault()
                break
            else:
                window["Error"].update(value="Invalid Password")
                window["MasterPassword"].update(value="")
                window["MasterPassword"].set_focus
        elif event == "Reset":
            window.close()
            windowResetMaster()
            break

    window.close()


def windowAddEntry():
    def addEntry() -> None:
        """
        Adds an encrypted entry to the database

            Parameters:
                None

            Returns:
                None
        """
        if values["Service"] == "":
            sg.popup("Service is required.")
            window["Service"].set_focus

        elif values["Pass"] == "":
            sg.popup("Password is required.")
            window["Pass"].set_focus

        elif values["ConfPass"] == "":
            sg.popup("Confirm password.")
            window["ConfPass"].set_focus

        elif not (values["Pass"] == values["ConfPass"]):
            sg.popup("Password Mismatch")
            window["Pass"].update(value="")
            window["ConfPass"].update(value="")
            window["Pass"].set_focus
        else:
            service = encrypt(values["Service"].encode(), encryptionKey)
            username = encrypt(values["User"].encode(), encryptionKey)
            password = encrypt(values["Pass"].encode(), encryptionKey)

            sql = """INSERT INTO tblVault (Service, Username, Password)
                        VALUES (?, ?, ?)"""

            cursor.execute(sql, (service, username, password))
            db.commit()

            window.close()
            windowPasswordVault()

    layout = [
        [sg.Text("Service:", size=(25, 1)), sg.InputText(key="Service", size=(25, 1))],
        [sg.Text("Username:", size=(25, 1)), sg.InputText(key="User", size=(25, 1))],
        [sg.Text("Password:", size=(25, 1)), sg.InputText(key="Pass", size=(25, 1))],
        [
            sg.Text("Confirm Password:", size=(25, 1)),
            sg.InputText(key="ConfPass", size=(25, 1)),
        ],
        [sg.Button("Generate Random Password", key="Random")],
        [
            sg.Button("Add Entry", key="AddEntry", bind_return_key=True),
            sg.Button("Cancel", key="Cancel"),
        ],
    ]

    window = sg.Window("Add Entry", layout, element_justification="c")

    while True:
        event, values = window.read()

        if event == sg.WIN_CLOSED:
            break
        elif event == "Cancel":
            window.close()
            windowPasswordVault()
            break
        elif event == "Random":
            hash = RandomPWGen.GenPassword(14)
            window["Pass"].update(value=hash)
            window["ConfPass"].update(value=hash)
        elif event == "AddEntry":
            addEntry()
            break

    window.close()


def windowUpdateEntry(id: int, service: str, username: str):
    def updateEntry(service: str, username: str, password: str) -> None:
        """
        Updates an encrypted entry to the database

            Parameters:
                service (str): Service to be updated as a string
                username (str): Username to be updated as a string
                password (str): Password to be updated as a string

            Returns:
                None
        """
        if values["Service"] == "":
            sg.popup("Service is required.")
            window["Service"].set_focus

        elif values["Pass"] == "":
            sg.popup("Password is required.")
            window["Pass"].set_focus

        elif values["ConfPass"] == "":
            sg.popup("Confirm password.")
            window["ConfPass"].set_focus

        elif not (values["Pass"] == values["ConfPass"]):
            sg.popup("Password Mismatch")
            window["Pass"].update(value="")
            window["ConfPass"].update(value="")
            window["Pass"].set_focus
        else:
            service = encrypt(values["Service"].encode(), encryptionKey)
            username = encrypt(values["User"].encode(), encryptionKey)
            password = encrypt(values["Pass"].encode(), encryptionKey)

        sql = "UPDATE tblVault SET Service = ?, Username = ?, Password = ? WHERE id = ?"

        cursor.execute(sql, (service, username, password, id))
        db.commit()

        window.close()
        windowPasswordVault()

    def removeEntry(id: int) -> None:
        """
        Removes an encrypted entry to the database

            Parameters:
                id (int): ID as integer of row to be eliminated

            Returns:
                None
        """
        cursor.execute("DELETE FROM tblVault WHERE id = ?", (id,))
        db.commit()

        window.close()
        windowPasswordVault()

    layout = [
        [
            sg.Text("Service:", size=(25, 1)),
            sg.InputText(service, key="Service", size=(25, 1)),
        ],
        [
            sg.Text("Username:", size=(25, 1)),
            sg.InputText(username, key="User", size=(25, 1)),
        ],
        [sg.Text("Password:", size=(25, 1)), sg.InputText(key="Pass", size=(25, 1))],
        [
            sg.Text("Confirm Password:", size=(25, 1)),
            sg.InputText(key="ConfPass", size=(25, 1)),
        ],
        [sg.Button("Generate Random Password", key="Random")],
        [
            sg.Button("Update Entry", key="UpdateEntry", bind_return_key=True),
            sg.Button("Remove Entry", key="RemoveEntry"),
            sg.Button("Cancel", key="Cancel"),
        ],
    ]

    window = sg.Window("Update Service", layout, element_justification="c")

    while True:
        event, values = window.read()

        if event in ("Cancel", sg.WIN_CLOSED):
            window.close()
            windowPasswordVault()
            break
        elif event == "Random":
            hash = RandomPWGen.GenPassword(14)
            window["Pass"].update(value=hash)
            window["ConfPass"].update(value=hash)
        elif event == "UpdateEntry":
            updateEntry(values["Service"], values["User"], values["Pass"])
            break
        elif event == "RemoveEntry":
            removeEntry(id)
            break

    window.close()


def windowPasswordVault():
    cursor.execute("SELECT * FROM tblVault")
    resultsList = cursor.fetchall()

    if resultsList == None:
        quit()

    results = []
    for i in range(len(resultsList)):
        plainList = [
            resultsList[i][0],
            decrypt(resultsList[i][1], encryptionKey).decode("utf-8"),
            decrypt(resultsList[i][2], encryptionKey).decode("utf-8"),
            decrypt(resultsList[i][3], encryptionKey).decode("utf-8"),
        ]
        results.append(plainList)
    header = ["ID", "Service", "Username", "Password"]
    layout = [
        [sg.Button("Add Service", key="AddEntry"), sg.Button("Exit", key="Exit")],
        [
            sg.Table(
                values=results,
                headings=header,
                max_col_width=50,
                auto_size_columns=True,
                display_row_numbers=False,
                justification="center",
                num_rows=10,
                enable_events=True,
                key="table",
                row_height=35,
            )
        ],
    ]

    window = sg.Window("Password Vault", layout, element_justification="c")

    while True:
        event, values = window.read()

        if event in ("Exit", sg.WIN_CLOSED):
            break
        elif event == "AddEntry":
            window.close()
            windowAddEntry()
            break
        elif event == "table":
            row = values["table"][0]
            id = results[row][0]
            service = results[row][1]
            username = results[row][2]
            window.close()
            windowUpdateEntry(id, service, username)
            break

    window.close()


if __name__ == "__main__":
    check = cursor.execute("SELECT * FROM tblMaster WHERE id = 1")
    if cursor.fetchall():
        windowLogin()
    else:
        windowSetMasterPassword()
