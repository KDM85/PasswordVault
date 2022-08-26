import random

# Base list for special characters
listSC = [
    "!",
    "@",
    "#",
    "$",
    "%",
    "^",
    "*",
    "(",
    ")",
    "-",
    "_",
    "+",
    "{",
    "[",
    "]",
    "}",
]


def GenPassword(length: int = 8) -> str:
    """
    Returns a random password string

        Parameters:
            length (int): desired length of the password

        Returns:
            strOutput (str): a random password string
    """
    # Default password length is eight characters

    # Lower case characters
    charLC1 = chr(random.randint(97, 122))
    charLC2 = chr(random.randint(97, 122))

    # Upper case characters
    charUC1 = chr(random.randint(65, 90))
    charUC2 = chr(random.randint(65, 90))

    # Numbers
    charNO1 = chr(random.randint(48, 57))
    charNO2 = chr(random.randint(48, 57))

    # Special characters
    charSC1 = listSC[random.randint(0, len(listSC) - 1)]
    charSC2 = listSC[random.randint(0, len(listSC) - 1)]

    # Built output list
    listOutput = [
        charLC1,
        charLC2,
        charUC1,
        charUC2,
        charNO1,
        charNO2,
        charSC1,
        charSC2,
    ]
    # Append output list to meet character length
    while len(listOutput) < length:
        intRand = random.randint(0, 3)
        if intRand == 0:
            charExtra = chr(random.randint(97, 122))
        elif intRand == 1:
            charExtra = chr(random.randint(65, 90))
        elif intRand == 2:
            charExtra = chr(random.randint(48, 57))
        else:
            charExtra = listSC[random.randint(0, len(listSC) - 1)]
        listOutput.append(charExtra)

    # Randomize the order of the characters in the list
    listOutputRandom = random.sample(listOutput, length)

    strOutput = ""
    for k in listOutputRandom:
        strOutput = strOutput + k
    return strOutput
