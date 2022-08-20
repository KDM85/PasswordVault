import PySimpleGUI as sg

sg.theme("DarkGrey15")

arrOptions = ["Distance", "Weight", ]
arrLenImp = ["th", "bc", "in", "h", "ft", "yd", "ftm", "ch", "fur", "mi", "nmi", "lea"]
arrLenMet = ["mm", "cm", "dm", "m", "dam", "hm", "km"]


def convert(dblValue, strInUnit, strOutUnit):
    if strInUnit in arrLenImp:
        bIsFromImperial = True
    elif strInUnit in arrLenMet:
        bIsFromImperial = False

    if strOutUnit in arrLenImp:
        bIsToImperial = True
    elif strOutUnit in arrLenMet:
        bIsToImperial = False

    if bIsFromImperial and not bIsToImperial:
        dblConversion = 25.4
    elif not bIsFromImperial and bIsToImperial:
        dblConversion = 1 / 25.4
    elif (bIsFromImperial and bIsToImperial) or (
        not bIsFromImperial and not bIsToImperial
    ):
        dblConversion = 1

    if strInUnit == "th":
        dblConversion = dblConversion / 1000
    elif strInUnit == "bc":
        dblConversion = dblConversion / 3
    elif strInUnit == "in":
        dblConversion = dblConversion
    elif strInUnit == "h":
        dblConversion = dblConversion * 4
    elif strInUnit == "ft":
        dblConversion = dblConversion * 12
    elif strInUnit == "yd":
        dblConversion = dblConversion * 36
    elif strInUnit == "ftm":
        dblConversion = dblConversion * 72.9132
    elif strInUnit == "ch":
        dblConversion = dblConversion * 792
    elif strInUnit == "fur":
        dblConversion = dblConversion * 7920
    elif strInUnit == "mi":
        dblConversion = dblConversion * 63360
    elif strInUnit == "nmi":
        dblConversion = dblConversion * 72913.2
    elif strInUnit == "lea":
        dblConversion = dblConversion * 190080
    elif strInUnit == "mm":
        dblConversion = dblConversion
    elif strInUnit == "cm":
        dblConversion = dblConversion * 10
    elif strInUnit == "dm":
        dblConversion = dblConversion * 100
    elif strInUnit == "m":
        dblConversion = dblConversion * 1000
    elif strInUnit == "dam":
        dblConversion = dblConversion * 10000
    elif strInUnit == "hm":
        dblConversion = dblConversion * 100000
    elif strInUnit == "km":
        dblConversion = dblConversion * 1000000

    if strOutUnit == "th":
        dblConversion = dblConversion * 1000
    elif strOutUnit == "bc":
        dblConversion = dblConversion * 3
    elif strOutUnit == "in":
        dblConversion = dblConversion
    elif strOutUnit == "h":
        dblConversion = dblConversion / 4
    elif strOutUnit == "ft":
        dblConversion = dblConversion / 12
    elif strOutUnit == "yd":
        dblConversion = dblConversion / 36
    elif strOutUnit == "ftm":
        dblConversion = dblConversion / 72.9132
    elif strOutUnit == "ch":
        dblConversion = dblConversion / 792
    elif strOutUnit == "fur":
        dblConversion = dblConversion / 7920
    elif strOutUnit == "mi":
        dblConversion = dblConversion / 63360
    elif strOutUnit == "nmi":
        dblConversion = dblConversion / 72913.2
    elif strOutUnit == "lea":
        dblConversion = dblConversion / 190080
    elif strOutUnit == "mm":
        dblConversion = dblConversion
    elif strOutUnit == "cm":
        dblConversion = dblConversion / 10
    elif strOutUnit == "dm":
        dblConversion = dblConversion / 100
    elif strOutUnit == "m":
        dblConversion = dblConversion / 1000
    elif strOutUnit == "dam":
        dblConversion = dblConversion / 10000
    elif strOutUnit == "hm":
        dblConversion = dblConversion / 100000
    elif strOutUnit == "km":
        dblConversion = dblConversion / 1000000

    return round(dblValue * dblConversion, 4)


arrChoice = arrLenImp
for i in range(0, len(arrLenMet)):
    arrChoice.append(arrLenMet[i])

layout = [
    [
        sg.Text("Input:", size=(10, 1)),
        sg.InputText(key="dblInput", size=(25, 1), enable_events=True),
        sg.Combo(
            arrChoice,
            key="strFromUnit",
            default_value="ft",
        ),
    ],
    [
        sg.Text("Output:", size=(10, 1), key="strOutput"),
        sg.Text(key="dblOutput", size=(25, 1)),
        sg.Combo(
            arrChoice,
            key="strToUnit",
            default_value="m",
        ),
    ],
    [sg.Button("Convert", key="btnConvert")],
]

window = sg.Window("Distance Conversion Tool", layout, element_justification="c")

while True:
    event, values = window.read()
    if event == sg.WIN_CLOSED:
        break

    if (
        event == "dblInput"
        and values["dblInput"]
        and values["dblInput"][-1] not in ("0123456789.")
    ):
        window["dblInput"].update(values["dblInput"][:-1])

    if event == "btnConvert" and values["dblInput"]:
        dblValue = values["dblInput"]
        try:
            dblConversion = convert(
                float(values["dblInput"]), values["strFromUnit"], values["strToUnit"]
            )

            window["dblOutput"].update(value=dblConversion)
        except:
            window["dblOutput"].update(value="Invalid Input")

window.close()
