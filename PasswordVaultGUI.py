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


def encrypt(strMessage: bytes, strKey: bytes) -> bytes:
    return Fernet(strKey).encrypt(strMessage)


def decrypt(strMessage: bytes, strKey: bytes) -> bytes:
    return Fernet(strKey).decrypt(strMessage)


def getHash(strInput):
    strHash = hashlib.sha256(strInput)
    strHash = strHash.hexdigest()

    return strHash


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


def frmSetMasterPassword():
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
    strPass = values["MasterPass"]
    strConfPass = values["ConfMasterPass"]

    if strPass == strConfPass:
        SQL = "DELETE FROM tblMaster WHERE id = 1"
        cursor.execute(SQL)

        strHashedMaster = getHash(strPass.encode("utf-8"))
        strKey = str(uuid.uuid4().hex)
        strRecovery = getHash(strKey.encode("utf-8"))

        global encryptionKey
        encryptionKey = base64.urlsafe_b64encode(kdf.derive(strPass.encode()))

        strSQL = """INSERT INTO tblMaster (id, Master, RecoveryKey) VALUES (1, ?, ?)"""
        cursor.execute(strSQL, ((strHashedMaster), (strRecovery)))
        db.commit()

        window.close()
        frmRecovery(strKey)
    else:
        window["MasterPass"].update(value="")
        window["ConfMasterPass"].update(value="")
        window["Error"].update(value="Password Mismatch.")
        window["MasterPass"].set_focus()


def frmRecovery(strKey):
    layout = [
        [sg.Text("Save Recovery Key:")],
        [sg.Text(strKey, size=(25, 5))],
        [sg.Button("Copy Key", key="btnCopy", bind_return_key=True)],
        [sg.Button("Done", key="btnDone")],
    ]

    window = sg.Window("Save Recovery Key", layout, element_justification="c")

    event, values = window.read()

    while True:
        if event == sg.WIN_CLOSED:
            break
        elif event == "btnCopy":
            pyperclip.copy(strKey)
            sg.popup("Recovery Key", strKey + " copied to clipboard.")
            frmPasswordVault()
            break
        elif event == "btnDone":
            frmPasswordVault()
            break
    window.close()


def frmResetMaster():
    def recoverPass(strEnteredKey):
        strHashKey = getHash(str(strEnteredKey).encode("utf-8"))
        cursor.execute(
            "SELECT * FROM tblMaster WHERE id = 1 AND RecoveryKey = ?", [(strHashKey)]
        )
        return cursor.fetchall()

    layout = [
        [
            sg.Text("Enter Recovery Key:", size=(25, 1)),
            sg.InputText(size=(25, 1), key="strRecKey"),
        ],
        [sg.Text(size=(25, 1), key="Error")],
        [sg.Button("Recover", key="btnRecover"), sg.Button("Cancel", key="btnCancel")],
    ]

    window = sg.Window("Recovery", layout, element_justification="c")

    event, values = window.read()

    while True:
        if event == sg.WIN_CLOSED:
            break
        elif event == "btnCancel":
            window.close()
            frmLogin()
            break
        elif event == "btnRecover":
            strRecoveryKey = recoverPass(values["strRecKey"])
            if strRecoveryKey:
                window.close()
                frmSetMasterPassword()
                break
            else:
                sg.Popup("Invalid Recovery Key")
                window.close()
                frmResetMaster()
                break

    window.close()


def frmLogin():
    layout = [
        [sg.Text("Master Password:", size=(25, 1))],
        [sg.InputText(size=(25, 1), key="MasterPassword", password_char="*")],
        [sg.Text(size=(25, 1), key="Error")],
        [
            sg.Button("Login", key="btnLogin", bind_return_key=True),
            (sg.Button("Reset Master Password", key="btnReset")),
        ],
    ]

    window = sg.Window("Login", layout, element_justification="c")

    event, values = window.read()

    while True:
        if event == sg.WIN_CLOSED:
            quit()
        elif event == "btnLogin":
            strHashedMaster = getHash(values["MasterPassword"].encode("utf-8"))
            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(
                kdf.derive(values["MasterPassword"].encode())
            )
            cursor.execute(
                "SELECT * FROM tblMaster WHERE id = 1 AND Master = ?",
                [(strHashedMaster)],
            )
            match = cursor.fetchall()

            if match:
                window.close()
                frmPasswordVault()
                break
            else:
                window["Error"].update(value="Invalid Password")
                window["MasterPassword"].update(value="")
                window["MasterPassword"].set_focus
        elif event == "btnReset":
            window.close()
            frmResetMaster()
            break

    window.close()


def frmAddEntry():
    def addEntry():
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
            strService = encrypt(values["Service"].encode(), encryptionKey)
            strUsername = encrypt(values["User"].encode(), encryptionKey)
            strPassword = encrypt(values["Pass"].encode(), encryptionKey)

            strSQL = """INSERT INTO tblVault (Service, Username, Password)
                        VALUES (?, ?, ?)"""

            cursor.execute(strSQL, (strService, strUsername, strPassword))
            db.commit()

            window.close()
            frmPasswordVault()

    layout = [
        [sg.Text("Service:", size=(25, 1)), sg.InputText(key="Service", size=(25, 1))],
        [sg.Text("Username:", size=(25, 1)), sg.InputText(key="User", size=(25, 1))],
        [sg.Text("Password:", size=(25, 1)), sg.InputText(key="Pass", size=(25, 1))],
        [
            sg.Text("Confirm Password:", size=(25, 1)),
            sg.InputText(key="ConfPass", size=(25, 1)),
        ],
        [sg.Button("Generate Random Password", key="btnRandom")],
        [
            sg.Button("Add Entry", key="btnAddEntry", bind_return_key=True),
            sg.Button("Cancel", key="btnCancel"),
        ],
    ]

    window = sg.Window("Add Entry", layout, element_justification="c")

    while True:
        event, values = window.read()
        if event == sg.WIN_CLOSED:
            break
        elif event == "btnCancel":
            window.close()
            frmPasswordVault()
            break
        elif event == "btnRandom":
            strHash = RandomPWGen.GenPassword(14)
            window["Pass"].update(value=strHash)
            window["ConfPass"].update(value=strHash)
        elif event == "btnAddEntry":
            addEntry()
            break

    window.close()


def frmUpdateEntry(intId, strService, strUsername):
    def updateEntry(strService, strUsername, strPassword):
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
            strService = encrypt(values["Service"].encode(), encryptionKey)
            strUsername = encrypt(values["User"].encode(), encryptionKey)
            strPassword = encrypt(values["Pass"].encode(), encryptionKey)

        strSQL = (
            "UPDATE tblVault SET Service = ?, Username = ?, Password = ? WHERE id = ?"
        )

        cursor.execute(strSQL, (strService, strUsername, strPassword, intId))
        db.commit()

        window.close()
        frmPasswordVault()

    def removeEntry(intId):
        cursor.execute("DELETE FROM tblVault WHERE id = ?", (intId,))
        db.commit()

        window.close()
        frmPasswordVault()

    layout = [
        [
            sg.Text("Service:", size=(25, 1)),
            sg.InputText(strService, key="Service", size=(25, 1)),
        ],
        [
            sg.Text("Username:", size=(25, 1)),
            sg.InputText(strUsername, key="User", size=(25, 1)),
        ],
        [sg.Text("Password:", size=(25, 1)), sg.InputText(key="Pass", size=(25, 1))],
        [
            sg.Text("Confirm Password:", size=(25, 1)),
            sg.InputText(key="ConfPass", size=(25, 1)),
        ],
        [sg.Button("Generate Random Password", key="btnRandom")],
        [
            sg.Button("Update Entry", key="btnUpdateEntry", bind_return_key=True),
            sg.Button("Remove Entry", key="btnRemoveEntry"),
            sg.Button("Cancel", key="btnCancel"),
        ],
    ]

    window = sg.Window("Update Service", layout, element_justification="c")

    while True:
        event, values = window.read()
        if event in ("btnCancel", sg.WIN_CLOSED):
            window.close()
            frmPasswordVault()
            break
        elif event == "btnRandom":
            strHash = RandomPWGen.GenPassword(14)
            window["Pass"].update(value=strHash)
            window["ConfPass"].update(value=strHash)
        elif event == "btnUpdateEntry":
            updateEntry(values["Service"], values["User"], values["Pass"])
            break
        elif event == "btnRemoveEntry":
            removeEntry(intId)
            break

    window.close()


def frmPasswordVault():
    cursor.execute("SELECT * FROM tblVault")
    arrResults = cursor.fetchall()

    if arrResults == None:
        quit()

    results = []
    for i in range(len(arrResults)):
        arrPlain = [
            arrResults[i][0],
            decrypt(arrResults[i][1], encryptionKey).decode("utf-8"),
            decrypt(arrResults[i][2], encryptionKey).decode("utf-8"),
            decrypt(arrResults[i][3], encryptionKey).decode("utf-8"),
        ]
        results.append(arrPlain)
    header = ["ID", "Service", "Username", "Password"]
    layout = [
        [sg.Button("Add Service", key="btnAddEntry"), sg.Button("Exit", key="btnExit")],
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
        if event in ("btnExit", sg.WIN_CLOSED):
            break
        elif event == "btnAddEntry":
            window.close()
            frmAddEntry()
            break
        elif event == "table":
            row = values["table"][0]
            intId = results[row][0]
            strService = results[row][1]
            strUsername = results[row][2]
            print(strUsername)
            window.close()
            frmUpdateEntry(intId, strService, strUsername)
            break

    window.close()


if __name__ == "__main__":
    check = cursor.execute("SELECT * FROM tblMaster WHERE id = 1")
    if cursor.fetchall():
        frmLogin()
    else:
        frmSetMasterPassword()
