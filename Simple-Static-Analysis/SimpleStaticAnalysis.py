"""
Simple Static Analysis - A malware analysis tool
Copyright (C) 2024 Lucas Ramage

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

# Imports
import chardet  # Detecting character encoding
import csv  # Gracefully reading CSV files
import datetime  # Allow for timestamps
import hashlib  # Allow for hashing text and files
import mimetypes  # Detect file encoding and mime types
import os  # Allow multi-system compatability with file paths
import re  # Allow the use of regular expressions
import requests  # Allow getting files from web pages
import sys  # Allow command-line arguments and graceful exiting
import yara_x  # Allow the use of YARA rules


# Fingerprinting function
def Full_Fingerprint(File_To_Scan, Output_File, type="default", ConsoleOutput=True):
    """This function generates hashes of the input file using the four most common hash types used in system forensics.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        type (STR): An identifier for how many different hashes to use. default is md5, sha1, sha256, and sha512. extended is all guaranteed hashes. full tries all available hashes.
        ConsoleOutput (boolean): Boolean to determine whether to output to the console

    Returns:
        Hash_List (list): A list of hashes in a certain order to use in scanning
    """
    Hash_List = []
    with open(Output_File, "a+") as OF:  # Open Output file
        if ConsoleOutput:
            print("")
            print(
                "Beginning Fingerprinting"
            )  # Let the user know the fingerprinting has begun
            print("")
        OF.write(
            "\nFingerprinting Results\n"
        )  # Create fingerprinting section in output file
        if type == "default" or type == "Low":
            with open(File_To_Scan, "rb") as f:  # Open the input file
                # Calculate the hashes and write them to the output file
                text = f.read()
                File_MD5 = hashlib.md5(text).hexdigest()
                OF.write(f"\tmd5 Hash: {File_MD5}\n")
                File_SHA1 = hashlib.sha1(text).hexdigest()
                OF.write(f"\tsha_1 Hash: {File_SHA1}\n")
                File_SHA256 = hashlib.sha256(text).hexdigest()
                OF.write(f"\tsha_256 Hash: {File_SHA256}\n")
                File_SHA512 = hashlib.sha512(text).hexdigest()
                OF.write(f"\tsha_512 Hash: {File_SHA512}\n")
                # Put the SHA-256, MD5, and SHA-1 hashes in a list in a specific order and with a specific format for scanning.
                Hash_List.append([File_SHA256, "sha_256"])
                Hash_List.append([File_MD5, "md5"])
                Hash_List.append([File_SHA1, "sha_1"])
                Hash_List.append([File_SHA512, "sha_512"])
        elif type == "extended" or type == "Extended":
            with open(File_To_Scan, "rb") as IF:
                fileText = IF.read()
                try:
                    for hashType in hashlib.algorithms_guaranteed:
                        try:
                            hash = hashlib.new(hashType, fileText).hexdigest()
                            OF.write(f"\t{hashType} hash: {hash}\n")
                            Hash_List.append([hash, hashType])
                        except TypeError:
                            hash = hashlib.new(hashType, fileText).hexdigest(64)
                            OF.write(f"\t{hashType} hash: {hash}\n")
                            Hash_List.append([hash, hashType])
                except Exception as e:
                    OF.write(f"\tCould not hash using {hashType}, encountered {e}.\n")
        elif type == "full" or type == "Full":
            with open(File_To_Scan, "rb") as IF:
                fileText = IF.read()
                try:
                    for hashType in hashlib.algorithms_available:
                        try:
                            hash = hashlib.new(hashType, fileText).hexdigest()
                            OF.write(f"\t{hashType} hash: {hash}\n")
                            Hash_List.append([hash, hashType])
                        except TypeError:
                            hash = hashlib.new(hashType, fileText).hexdigest(64)
                            OF.write(f"\t{hashType} hash: {hash}\n")
                            Hash_List.append([hash, hashType])
                except Exception as e:
                    OF.write(f"\tCould not hash using {hashType}, encountered {e}.\n")
        else:
            pass
        OF.write("\n")
        if ConsoleOutput:
            print(
                "Finished Fingerprinting"
            )  # Let the user know fingerprinting has finished.
    return Hash_List  # Return the list with hashes for use in scanning


# Scanning function
def Scanning(File_Hash_List, Output_File, scan_list="default", ConsoleOutput=True):
    """Scans hashes from the provided list against known malware hashes.

    Args:
        File_Hash_List (list): A list of hashes with their types, e.g., [[hash, type], ...].
        Output_File (str): Path to the output file.
        scan_list (str): Path to the malware hash list CSV. Defaults to recent MalwareBazaar data dump.
        ConsoleOutput (bool): Whether to print progress to the console.

    Returns:
        list: Results of matched hashes with row numbers.
    """
    if scan_list == "default":
        url = "https://bazaar.abuse.ch/export/csv/recent/"
        response = requests.get(url)
        file_path = "recent.csv"
        if response.status_code == 200:
            try:
                with open(file_path, "wb") as scanFile:
                    scanFile.write(response.content)
                scan_list = file_path
            except Exception as e:
                print("Error saving MalwareBazaar data:", e)
        else:
            print(
                "Failed to download recent malware data. Using local file if available."
            )

    Results_List = []
    with open(Output_File, "a+") as OF:
        OF.write("Scanning Results\n")
        if ConsoleOutput:
            print("\nStarting scan\n")

        try:
            with open(scan_list, newline="") as csvfile:
                Hash_Data_Reader = csv.reader(csvfile, delimiter=",")
                File_Hash_Set = {hash[0] for hash in File_Hash_List}  # Optimized lookup
                for rowNum, row in enumerate(Hash_Data_Reader, start=1):
                    for entry in row:
                        if entry in File_Hash_Set:
                            hash_type = next(
                                (h[1] for h in File_Hash_List if h[0] == entry), None
                            )
                            Results_List.append([entry, hash_type, rowNum])

            if not Results_List:
                OF.write("\tNo matches\n")
            else:
                OF.write("\tMatches Found:\n")
                for entry in Results_List:
                    OF.write(
                        f"\t\t{entry[1]} hash {entry[0]} on row number {entry[2]} in {scan_list}\n"
                    )

        except FileNotFoundError:
            print(f"Error: {scan_list} not found.")
            OF.write("\tError: Malware data file not found.\n")
        except Exception as e:
            print("An unexpected error occurred during scanning:", e)
            OF.write(f"\tError during scanning: {e}\n")

        if ConsoleOutput:
            print("Finished scan")

    return Results_List


# String Searching
def String_Searching(File_To_Scan, Output_File, addtnlKeywords=[], ConsoleOutput=True):
    """This function searches the input file for strings that match regular expressions from the regex txt file provided by the program.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        addtnlKeywords (List): An optional list of additional keywords and regular expressions
        ConsoleOutput (boolean): Boolean to determine whether to output to the console
    """
    with open(Output_File, "a+") as OF:  # Open the output file
        if ConsoleOutput:
            print("")
            print(
                "Searching for strings within the file"
            )  # Inform the user that string searching has begun
            print("")
        OF.write(
            "\nString Searching\n"
        )  # Create a string searching section in the output file
        # Open the regular expression file and store the patterns in a list to reference
        Regex_Patterns = []
        with open("stringRegEx.csv", newline="") as CSV_File:
            RegEx_Reader = csv.reader(CSV_File, delimiter=";")
            for row in RegEx_Reader:
                Regex_Patterns.append([row[0], row[1]])
        if len(addtnlKeywords) > 0:
            for row in addtnlKeywords:
                Regex_Patterns.append([row[0], row[1]])
        with open(File_To_Scan, "rb") as IF:
            # Open the input file and read it into a variable
            text_lines = IF.readlines()
            for entry in Regex_Patterns:
                try:
                    if entry[0][0] == "#":
                        continue
                except IndexError:
                    continue
                found = False
                pattern = entry[0].strip()
                OF.write(f"Pattern: {entry[1]}; {pattern}\n")
                for line in text_lines:
                    matches = re.findall(pattern, str(line))
                    # Go through all of the patterns in the regex list and find matches within the input file text
                    if matches:
                        found = True
                        # If there are matches for a pattern, write them all to the output file
                        for match in matches:
                            OF.write(f"\tMatch: {match} in line:\n\t\t{line.strip()}\n")
                if not found:
                    OF.write(f"\tNo matches found\n")
    if ConsoleOutput:
        print(
            "String Searching done"
        )  # Inform the user that string searching has completed.


# Identify Packing and/or Obfuscation
# Identify Encoding
def Identify_Encoding(File_To_Scan, Output_File, ConsoleOutput=True):
    """This function detects character encoding using two different methods.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        ConsoleOutput (boolean): Boolean to determine whether to output to the console
    """
    if ConsoleOutput:
        print("Detecting Encoding")  # Inform the user the encoding detection has begun
    with open(Output_File, "a+") as OF:
        OF.write("\tDetecting Character Encoding\n")
        with open(File_To_Scan, "rb") as f:
            text = f.read()  # Generate a string of the file to detect with this method
            Detect_Results = chardet.detect_all(text)
            OF.write("\t\tUsing Chardet detect:\n")
            if len(Detect_Results) > 0:
                # If an encoding method is found, output the encoding scheme and confidence
                for entry in Detect_Results:
                    OF.write(
                        f"\t\t\tGot {entry['encoding']} encoding with {entry['confidence']} confidence\n"
                    )
        filetype, encoding = mimetypes.guess_type(
            File_To_Scan
        )  # Use mimetypes because magic broke
        OF.write("\t\tUsing mimetypes:\n")
        OF.write(f"\t\t\tDetected {encoding} encoding\n")
        OF.write(f"\t\t\tDetected filetype {filetype}\n")
    if ConsoleOutput:
        print(
            "Finished detecting encoding"
        )  # Inform the user that this process is done


# Identify Packing
def Identify_Packing(File_To_Scan, Output_File, ConsoleOutput=True):
    """This function uses YARA rules to detect file cryptors and packers.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        ConsoleOutput (boolean): Boolean to determine whether to output to the console
    """
    if ConsoleOutput:
        print(
            "Detecting packing"
        )  # Inform the user that the detection of file packing has begun
    # Compile the YARA rules
    with open("crypto_signatures.txt", "r") as rulesFile:
        crypto_Rules = yara_x.compile(rulesFile.read())
    with open("packer.txt", "r") as rulesFile:
        packer_Rules = yara_x.compile(rulesFile.read())
    with open(File_To_Scan, "rb") as scanFile:
        fileText = scanFile.read()
    with open(Output_File, "a+") as OF:
        OF.write("\tDetecting Packing and Cryptors\n")
        cryptor_Matches = crypto_Rules.scan(fileText).matching_rules
        OF.write("\t\tFound Cryptors:\n")
        # If matches are found, output them. Otherwise, output no results found
        if len(cryptor_Matches) > 0:
            for rule in cryptor_Matches:
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        OF.write(f"\t\t\t{pattern.identifier}\n")
        else:
            OF.write("\t\t\tNo Cryptors found\n")
        packer_Matches = packer_Rules.scan(fileText).matching_rules
        OF.write("\t\tFound Packers:\n")
        # If matches are detected, output them. Otherwise, output no results
        if len(packer_Matches) > 0:
            for rule in packer_Matches:
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        OF.write(f"\t\t\t{pattern.identifier}\n")
        else:
            OF.write("\t\t\tNo Packers found\n")
    if ConsoleOutput:
        print(
            "Finished detecting packing"
        )  # Inform the user that this process has finished.


# A function to match with user input YARA rules.
def Misc_YARA_Rules(File_To_Scan, Output_File, Yara_File):
    """This function matches user input YARA rules

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        Yara_File (path STR): The input YARA file to match
    """
    # Compile the YARA rules
    with open(Yara_File, "r") as ruleFile:
        YARA_Rules = yara_x.compile(ruleFile.read())
    # Read the input text as binary
    with open(File_To_Scan, "rb") as IF:
        fileText = IF.read()
    with open(Output_File, "a+") as OF:
        # Create a section in the output file for this particular matching operation
        root, fileName = os.path.split(Yara_File)
        OF.write(f"\tMatching YARA rules from {fileName}\n")
        # Scan the input file to match the YARA rules
        YARA_Matches = YARA_Rules.scan(fileText).matching_rules
        OF.write("\t\tFound Matches:\n")
        if len(YARA_Matches) > 0:
            # Output any matches
            for rule in YARA_Matches:
                for pattern in rule.patterns:
                    for match in pattern.matches:
                        OF.write(f"\t\t\t{pattern.identifier}\n")
                        OF.write(
                            f"\t\t\t{match.offset} characters in, {match.length} characters long.\n"
                        )
        else:
            OF.write("\t\t\tNo matches found\n")


# Identify Obfuscation
def Identify_Obfuscation(File_To_Scan, Output_File, YARA_List=None, ConsoleOutput=True):
    """This function calls Identify_Encoding and Identify_Packing.

    Args:
        File_To_Scan (path STR): The path to the input file
        Output_File (path STR): The path to the output file
        YARA_List (list of path STR): A list containing additional YARA rule files. None by default
        ConsoleOutput (boolean): Boolean to determine whether to output to the console
    """
    if ConsoleOutput:
        print("")
        print(
            "Detecting Obfuscation"
        )  # Inform the user that obfuscation detection has begun
        print("")
    with open(Output_File, "a+") as OF:
        # Create a section in the output file for obfuscation detection
        OF.write("\nObfuscation Methods\n")
    Identify_Encoding(
        File_To_Scan, Output_File, ConsoleOutput
    )  # Call the function to identify encoding
    Identify_Packing(
        File_To_Scan, Output_File, ConsoleOutput
    )  # Call the function to identify packing
    if YARA_List != None:
        for path in YARA_List:
            Misc_YARA_Rules(File_To_Scan, Output_File, path)
    if ConsoleOutput:
        print("")
        print(
            "Finished detecting obfuscation"
        )  # Inform the user that obfuscation detection has finished


# Disassembly
def Disassembly(File_To_Scan, Output_File, Output_Folder=None, ConsoleOutput=True):
    """This function disassembles the input file, outputting all characters as ASCII to a separate file, with newlines at periods or newline characters.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        Output_Folder (path STR): The folder all of the output files go in
        ConsoleOutput (boolean): Boolean to determine whether to output to the console

    Returns:
        Disassembly_File (path STR): Returns the disassembly file so that the GUI can use it
    """
    if ConsoleOutput:
        print("")
        print("Beginning Disassembly")  # Inform the user that disassembly has begun
        print("")
    head, fileName = os.path.split(File_To_Scan)
    trueFileName, ext = os.path.splitext(fileName)
    Disassembly_File_Name = (
        f"{trueFileName}_Disassembled.txt"  # Make a unique disassembly file
    )
    Disassembly_File = os.path.join(Output_Folder, Disassembly_File_Name)
    with open(Output_File, "a+") as OF:
        OF.write("\nDisassembly\n")  # Create a disassembly section in the output file
        with open(File_To_Scan, "rb") as InFile:
            data = InFile.read().decode(
                "utf-8", errors="replace"
            )  # Decode bytes to string
        with open(Disassembly_File, "a+") as DestFile:
            buffer = ""  # Buffer to collect ASCII characters until a newline is found
            for char in data:
                if char == "\r" or char == "\n":  # Check for newline
                    buffer += char  # Include the character in the current line
                    DestFile.write(buffer + "\n")  # Write the buffered line
                    buffer = ""  # Reset buffer for the next line
                else:
                    buffer += char if 32 <= ord(char) < 127 else "."  # Add ASCII or '.'
            if buffer:  # Write any remaining characters in the buffer
                DestFile.write(buffer + "\n")
        OF.write(
            f"\tASCII disassembly written to {Disassembly_File}.\n\tSee that file for an exact ASCII representation of {File_To_Scan}.\n"
        )
    if ConsoleOutput:
        print("Disassembly finished")  # Inform the user that disassembly has finished.
    return Disassembly_File


# Interactive Mode
def Interactive_Mode():
    # This is a function to allow for greater flexibility in this program
    print("Opening Interactive Mode")
    print(
        """
\tSimple Static Analysis Copyright (C) 2024 Lucas Ramage
This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details."""
    )  # Display copyright info and allow user to view warranty info.
    while True:
        print(
            "Press enter to continue, 'q' to quit, or type 'show <option>' as above to display license information: "
        )
        option = input(
            "\t"
        )  # Allow user to continue or view copyright and distrobution conditions
        if option != "":
            if option == "show w":  # Show warranty information
                print(
                    """\tTHERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION."""
                )
            elif option == "show c":
                print(
                    "See the License sections 4, 5, 6, and 7 for redistribution conditions, located in the LICENSE file."
                )  # Direct user to distrobution conditions
            elif option == "q":  # Allow user to quit
                print("quitting")
                sys.exit()
            else:
                print("Invalid entry, try again.")
        else:
            break
    # Display interactive header
    print(
        """
    _____ _____  ___    
   /  ___/  ___|/ _ \\   
   \\ `--.\\ `--./ /_\\ \\  
    `--. \\`--. \\  _  |  
   /\\__/ /\\__/ / | | |  
   \\____/\\____/\\_| |_/  
   """
    )
    print(
        "Welcome to the Simple Static Analysis tool! This is a tool to help analyze suspected malware by automating various tests."
    )
    print(
        "NOTE: This program does not guarantee malware detection, it merely runs tests and displays the results. Just because there are results does not mean a file is malware."
    )
    print(
        "\tThis program may display false positives for malware, and it may not catch unknown malware."
    )
    while True:
        print()
        print(
            "Enter the path of the file to scan or the path of a directory to scan all files within:"
        )
        # Accept user input for input file, repeats until a valid file or directory is entered
        inFile_Path = input("\t")
        inFile_List = []
        if not os.path.exists(inFile_Path):
            print("Entered file path does not exist.")
        else:
            # If the user entered a file, just use the one
            if os.path.isfile(inFile_Path):
                inFile_List.append(inFile_Path)
                break
            # If the user entered a directory, walk through all of the files in that directory and add them to the list.
            else:
                for path, dirs, files in os.walk(inFile_Path, topdown=False):
                    for name in files:
                        inFile_List.append(os.path.join(path, name))
                if len(inFile_List) < 1:
                    print(
                        "Entered directory doesn't have any actual files. Please enter a path to a file or a path to a directory containing files."
                    )
                    continue
                break
    isOutFileChosen = False
    while not isOutFileChosen:
        # Allow user input for the name of the output file
        print()
        print(
            "Enter a name for the output file; NOT A PATH; DO NOT INCLUDE AN EXTENSION:"
        )
        # This is a list of all characters that are excluded from file names or are discouraged in file names.
        excluded_chars = [
            "\\",
            "/",
            ":",
            "*",
            "?",
            '"',
            "<",
            ">",
            "|",
            "~",
            "#",
            "%",
            "&",
            "{",
            "}",
            "(",
            ")",
            "[",
            "]",
            "$",
            "!",
            "'",
            "@",
            "+",
            "`",
            "=",
            " ",
            ",",
            "^",
            ";",
        ]
        outFile_Name = input("\t")
        rejected = False
        # Go through each character in the list
        for char in excluded_chars:
            # If the character is in the entered file name, reject it
            if char in outFile_Name:
                if char == " ":  # I had to add this for readability.
                    print("file name cannot contain a space")
                else:
                    print(f"file name cannot contain character {char}")
                rejected = True
                break
        if rejected:
            # If the file name got rejected, go back to where it accepted input.
            continue
        else:
            isOutFileChosen = True
    # Make a unique output folder to organize the output files.
    outFolder_Name = f"{outFile_Name}_{str(datetime.date.today())}_Folder"
    os.mkdir(outFolder_Name)
    outFile_Name = outFile_Name + ".txt"
    outFile = os.path.join(outFolder_Name, outFile_Name)
    # Write the output header to the chosen output file
    with open(outFile, "w+") as OF:
        with open("OutputHeader.txt", "r") as header:
            # Copy the output header from the OutputHeader file
            FileHeader = header.read()
            OF.write(FileHeader)
        # Write the timestamp of analysis and the name of the analyzed file
        OF.write("Timestamp: " + str(datetime.datetime.now()))
        OF.write("\n")
        # Write all of the input files
        OF.write("Analyzed File(s): ")
        tmp = 0
        for item in inFile_List:
            root, fileName = os.path.split(item)
            if tmp > 0:
                OF.write(r", ")
            OF.write(fileName)
            tmp += 1
        OF.write("\n")
    print()
    # Print the current file choices to the command line
    print("The file(s) to scan is/are; ")
    for entry in inFile_List:
        print(entry)
    print(f"and the output will be saved to {outFile}.")
    input("Press enter to continue:")
    # Allow the user to chose the level of intensity for the fingerprinting
    print("Choose the level of fingerprinting you want:")
    print("\t[1] - Low - Calculates just the four most common hashes")
    print("\t[2] - Extended - Calculates using all guaranteed hashes")
    print("\t[3] - Full - Tries to calculate all available hashes")
    hashLevelChoice = input("\t")
    if hashLevelChoice == "1":
        HashType = "default"
    elif hashLevelChoice == "2":
        HashType = "extended"
    elif hashLevelChoice == "3":
        HashType = "full"
    else:
        print("Invalid option, using Low")
        HashType = "default"
    print()
    # Allow the user to use their own malware signature CSV file
    print("Do you want to use your own hash list csv for the scanning process? y/n")
    while True:
        choice = input("\t").lower()
        if choice == "n":
            defaultScan = True
            print("Using default hash list")
            break
        elif choice == "y":
            # Get path for different csv
            chosen = False
            while not chosen:
                print(
                    "Enter the path to the desired csv file, or enter 'default' to use the included hash list: "
                )
                scanFile_Path = input("\t")
                if (
                    scanFile_Path == "default"
                ):  # This option is for if the user changes their mind
                    defaultScan = True
                    break
                if not os.path.exists(scanFile_Path):
                    print(
                        "Path entered does not exist. This may be due to spelling errors"
                    )
                else:
                    root, extension = os.path.splitext(scanFile_Path)
                    if extension != ".csv":
                        print(
                            "Path entered does not lead to a .csv file. Enter a .csv file"
                        )
                    else:
                        scanFile = root + extension
                        defaultScan = False
                        chosen = True
            break
        else:
            print("Invalid option")
    print()
    # Allow user to add more things to look for when searching the file for strings
    print(
        "Do you wish to add more keywords or regular expressions for this analysis? y/n"
    )
    option = input("\t").lower()
    addtnlKeywords = []
    if option == "n":
        print("Using default string searching")
    elif option == "y":
        while True:
            print(
                "Enter one or more keyword options to search for, enter a regular expression, or enter 'q' to quit. If entering multiple keywords, seperate them with a space."
            )
            user_input = input("\t")
            if user_input == "q":
                break
            for entry in user_input.split(" "):
                addtnlKeywords.append([entry, "User Input"])
    else:
        print("Invalid option, using default string searching.")
    print()
    # Allow more YARA rules from user input
    print("Do you wish to match the file against additional YARA rule files? y/n")
    option = input("\t").lower()
    if option == "n":
        print("Using included YARA rules only")
    elif option == "y":
        done = False
        yara_list = []
        while not done:  # This loop allows the user to enter multiple YARA files
            print(
                "Enter the path to the YARA rule file, or enter 'q' to stop. Please ensure the file is a .txt file, not .yar or .yara"
            )
            new_yara_file = input("\t")
            if new_yara_file == "q":
                print("Finished accepting files")
                done = True
                break
            else:
                if os.path.exists(new_yara_file):
                    if os.path.isfile(new_yara_file):
                        root, extension = os.path.splitext(new_yara_file)
                        if extension == ".txt":
                            with open(new_yara_file, "r") as ruleFile:
                                try:
                                    rules = yara_x.compile(ruleFile.read())
                                except yara_x.CompileError:
                                    print(f"File entered does not contain YARA rules.")
                                    continue
                            yara_list.append(new_yara_file)
                        else:
                            print(
                                "Entered file is not a .txt file. Please ensure the file is a .txt file"
                            )
                    else:
                        print("Entered path is not a file")
                else:
                    print("Entered path does not exist")
    else:
        print("Invalid option, using included YARA rules only")
    # Go through and do all of the operations for each of the input files in the list.
    for inFile in inFile_List:
        with open(outFile, "a+") as OF:
            root, fileName = os.path.split(inFile)
            OF.write(f"\n{fileName}\n")
        Hash_List = Full_Fingerprint(inFile, outFile, HashType)
        if defaultScan:
            Scanning(Hash_List, outFile)
        else:
            Scanning(Hash_List, outFile, scanFile)
        String_Searching(inFile, outFile, addtnlKeywords)
        if yara_list is not None:
            for rule_file in yara_list:
                Identify_Obfuscation(inFile, outFile, rule_file)
        else:
            Identify_Obfuscation(inFile, outFile)
        Disassembly(inFile, outFile, outFolder_Name)
    input("Press enter to end program")
    sys.exit()


# Help function to display syntax if help is input
def Help():
    print(
        "Syntax for one command: SimpleStaticAnalysis.py <file_to_scan> <name_for_output_file>"
    )
    print(
        "NOTE: This program will generate a header in the file, please ensure the file does not exist or is empty."
    )
    print(
        "<file_to_scan> is either a file in the same folder as this program or a path to a file. The extension doesn't matter, but it needs to be included here."
    )
    print(
        "<name_for_output_file> is just a simple name for the output file. Do not include an extension, as this program automatically adds the .txt extension."
    )
    print(
        "Syntax for interactive mode: SimpleStaticAnalysis.py OR SimpleStaticAnalysis.py interactive"
    )
    sys.exit()


# Main function
def main():
    # Detect the amount of arguments and the type of arguments,
    if len(sys.argv) == 1 or sys.argv[1] == "interactive":
        # Run interacctive mode if no arguments are entered or if the 'interactive' argument is entered
        Interactive_Mode()
    elif sys.argv[1] == "help":
        # Show the help function if the 'help' argument is entered
        Help()
    # Show the help function if the program does not recognize the argument entered or if there are too many arguments
    elif len(sys.argv) == 2:
        print("Unrecognized argument")
        Help()
    elif len(sys.argv) > 3:
        print("Too many arguments entered")
        Help()
    else:  # Run in single command mode
        # Save the files for easy use
        inFile = sys.argv[1]
        # Checks if selected file exists, exits if it does not
        try:
            with open(inFile, "r") as IF:
                print(f"{IF} exists")
        except FileNotFoundError:
            print(
                f"{inFile} does not exist. This may be due to spelling errors or from an incorrect path. Please double check the path."
            )
            sys.exit()
        # Creates the output file and folder
        outFolder_Name = f"{sys.argv[2]}_{str(datetime.datetime.now())}_Folder"
        os.mkdir(outFolder_Name)
        outFile_Name = sys.argv[2] + ".txt"
        outFile = os.path.join(outFolder_Name, outFile_Name)
        with open(outFile, "w+") as OF:
            with open("OutputHeader.txt", "r") as header:
                # Copy the output header from the OutputHeader file
                FileHeader = header.read()
                OF.write(FileHeader)
            # Write the timestamp of analysis and the name of the analyzed file
            OF.write("Timestamp: " + str(datetime.datetime.now()))
            OF.write("\n")
            OF.write(f"Analyzed File: {inFile}\n")
        # Perform all of the tests
        Hash_List = Full_Fingerprint(inFile, outFile)
        Scanning(Hash_List, outFile)
        String_Searching(inFile, outFile)
        Identify_Obfuscation(inFile, outFile)
        Disassembly(inFile, outFile, outFolder_Name)


if __name__ == "__main__":
    # This section is so that I can handle Control+C
    try:
        main()
    except KeyboardInterrupt:
        print("Exiting through Keyboard Interrupt")
        sys.exit()
