"""
Simple Static Analysis - A malware analysis tool
Copyright (C) 2024 Lucas Ramage

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import sys
import hashlib
import csv
import datetime
import re
import mimetypes
import chardet
import yara_x
import os
import requests
import signal


# Fingerprinting function
def Full_Fingerprint(File_To_Scan, Output_File, type = "default"):
    """This function generates hashes of the input file using the four most common hash types used in system foresnics.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
        type (STR): an identifier for how many different hashes to use. default is md5, sha1, sha256, and sha512. extended is all guaranteed hashes. full tries all available hashes.

    Returns:
        Hash_List (list): A list of hashes in a certain order to use in scanning
    """
    Hash_List = []
    with open(Output_File, "a+") as OF:  # Open Output file
        print("")
        print(
            "Beginning Fingerprinting"
        )  # Let the user know the fingerprinting has begun
        print("")
        OF.write(
            "\nFingerprinting Results\n"
        )  # Create fingerprinting section in output file
        if type == "default":
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
        elif type == "extended":
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
        elif type == "full":
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
        print(
            "Finished Fingerprinting"
        )  # Let the user know fingerprinting has finished.
    return Hash_List  # Return the list with hashes for use in scanning


# Scanning function
def Scanning(File_Hash_List, Output_File, scan_list = "default"):
    """This function scans the hashes from the provided hash list, taken from the fingerprinting function, and compares them to the csv file included with known malware hashes.

    Args:
        File_Hash_List (list): A list of hashes in a specific format
        Output_File (path STR): The destination output file
        scan_list (path STR): The list to scan against. If left as default, gets the most recent 48 hour data dump from MalwareBazaar
    """
    if scan_list == "default":
        url = "https://bazaar.abuse.ch/export/csv/recent/"
        response = requests.get(url)
        file_Path = "recent.csv"
        if response.status_code == 200:
            try:
                with open(file_Path, "wb") as scanFile:
                    scanFile.write(response.content)
                scan_list = file_Path
            except Exception as e:
                print("Something failed")
                print(e)
        else:
            print("Failed getting recent malware csv from MalwareBazaar.")
    with open(Output_File, "a+") as OF:  # Open the output file
        OF.write("Scanning Results\n")  # Create scan result section
        Results_List = []
        print("")
        print("Starting scan")  # Let the user know scanning has begun
        print("")
        with open(
            scan_list, newline=""
        ) as csvfile:  # Open the known malware csv for reading
            Hash_Data_Reader = csv.reader(csvfile, delimiter=",")
            rowNum = 0
            for (
                row
            ) in (
                Hash_Data_Reader
            ):  # Read through each row. If the row has multiple entries, it checks the provided hash list against the proper entries.
                rowNum += 1
                try:
                    # If matches are found, write the hash matched and the name of the known malware to a list of lists
                    for entry in row:
                        for hash in File_Hash_List:
                            try:
                                if hash[0] in entry:
                                    Results_List.append([hash[0], hash[1], rowNum])
                            except:
                                continue
                except IndexError:  # If the row only has one entry, go to the next row
                    next(Hash_Data_Reader, None)
            if (
                len(Results_List) == 0
            ):  # If no matches are found, write that to the output file
                OF.write("\tNo matches\n")
            else:  # If matches are found, write them to the output file
                OF.write("\tMatches Found:\n")
                for entry in Results_List:
                    OF.write(f"\t\t{entry[1]} hash {entry[0]} on row number {entry[2]} in {scan_list}\n")

        print("Finished scan")  # Let the user know that scanning is done.


# String Searching
def String_Searching(File_To_Scan, Output_File, addtnlKeywords = []):
    """This function searches the input file for strings that match regular expressions from the regex txt file provided by the program.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
    """
    with open(Output_File, "a+") as OF:  # Open the output file
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
        with open(File_To_Scan, "r") as IF:
            # Open the input file and read it into a variable
            text_lines = IF.readlines()
            for entry in Regex_Patterns:
                if entry[0][0] == "#":
                    continue
                found = False
                pattern = entry[0].strip()
                OF.write(f"Pattern: {entry[1]}; {pattern}\n")
                for line in text_lines:
                    matches = re.findall(pattern, line)
                    # Go through all of the patterns in the regex list and find matches within the input file text
                    if matches:
                        found = True
                        # If there are matches for a pattern, write them all to the output file
                        for match in matches:
                            OF.write(f"\tMatch: {match} in line:\n\t\t{line.strip()}\n")
                if not found:
                    OF.write(f"\tNo matches found\n")
    print(
        "String Searching done"
    )  # Inform the user that string searching has completed.


# Identify Packing and/or Obfuscation
# Identify Encoding
def Identify_Encoding(File_To_Scan, Output_File):
    """This function detects character encoding using two different methods.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
    """
    print("Detecting Encoding")  # Inform the user the encoding detection has begun
    with open(Output_File, "a+") as OF:
        OF.write("\tDetecting Character Encoding\n")
        with open(File_To_Scan, "rb") as f:
            text = f.read()  # Generate a string of the file to detect with this method
            Detect_Results = chardet.detect(text)
            if Detect_Results["encoding"] is not None:
                # If an encoding method is found, output the encoding scheme and confidence
                OF.write("\t\tUsing Chardet detect:\n")
                OF.write(
                    f"\t\t\tGot {Detect_Results['encoding']} encoding with {Detect_Results['confidence']} confidence\n"
                )
        filetype, encoding = mimetypes.guess_type(File_To_Scan) # Use mimetypes because magic broke
        OF.write("\t\tUsing mimetypes:\n")
        OF.write(f"\t\t\tDetected {encoding} encoding\n")
    print("Finished detecting encoding")  # Inform the user that this process is done


# Identify Packing
def Identify_Packing(File_To_Scan, Output_File):
    """This function uses YARA rules to detect file cryptors and packers.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
    """
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
            for match in cryptor_Matches.patterns.matches:
                OF.write(f"\t\t\t{match.identifier}\n")
        else:
            OF.write("\t\t\tNo Cryptors found\n")
        packer_Matches = packer_Rules.scan(fileText).matching_rules
        OF.write("\t\tFound Packers:\n")
        # If matches are detected, output them. Otherwise, output no results
        if len(packer_Matches) > 0:
            for match in packer_Matches.patterns.matches:
                OF.write(f"\t\t\t{match.identifier}\n")
        else:
            OF.write("\t\t\tNo Packers found\n")
    print(
        "Finished detecting packing"
    )  # Inform the user that this process has finished.


# Identify Obfuscation
def Identify_Obfuscation(File_To_Scan, Output_File, interactive=False):
    """This function calls Identify_Encoding and Identify_Packing.

    Args:
        File_To_Scan (path STR): The path to the input file
        Output_File (path STR): The path to the output file
        interactive (bool): A boolean determining whether to run in interactive mode
    """
    print("")
    print(
        "Detecting Obfuscation"
    )  # Inform the user that obfuscation detection has begun
    print("")
    with open(Output_File, "a+") as OF:
        # Create a section in the output file for obfuscation detection
        OF.write("\nObfuscation Methods\n")
    Identify_Encoding(
        File_To_Scan, Output_File
    )  # Call the function to identify encoding
    if interactive:
        input("Press enter to continue:")
    Identify_Packing(File_To_Scan, Output_File)  # Call the function to identify packing
    if interactive:
        input("Press enter to continue:")
    print("")
    print(
        "Finished detecting obfuscation"
    )  # Inform the user that obfuscation detection has finished


# Dissasembly
def Dissasembly(File_To_Scan, Output_File):
    """This function disassembles the input file, outputting all characters to a seperate file formatted as a .txt file.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
    """
    print("")
    print("Beginning Dissasembly")  # Inform the user that assembly has begun
    print("")
    head, fileName = os.path.split(File_To_Scan)
    trueFileName, ext = os.path.splitext(fileName)
    Dissasembly_File = f"{trueFileName}_{str(datetime.datetime.now())}.txt"  # Make a unique dissasembly file using the current date
    with open(Output_File, "a+") as OF:
        OF.write("\nDissasembly\n")  # Create a dissasembly section in the output file
        with open(Dissasembly_File, "a+") as DestFile:
            with open(File_To_Scan, "r") as InFile:
                for char in InFile.read():
                    # Write each character from the input file to the dissasembly file
                    DestFile.write(char)
        OF.write(
            f"Dissasembly written to {Dissasembly_File}.\nSee that file for an exact reproduction of the contents of {File_To_Scan}.\n"
        )
    print("Dissasembly finished")  # Inform the user that dissasembly has finished.


# Interactive Mode
def Interactive_Mode():
    # This is a function to allow for greater flexibility in this program
    print("Opening Interactive Mode")
    print("""
\tSimple Static Analysis Copyright (C) 2024 Lucas Ramage
This program comes with ABSOLUTELY NO WARRANTY; for details type `show w'.
This is free software, and you are welcome to redistribute it
under certain conditions; type `show c' for details.""") # Display copyright info and allow user to view warranty info.
    while True:
        print("Press enter to continue, 'q' to quit, or type 'show <option>' as above to display license information: ")
        option = input("\t") # Allow user to continue or view copyright and distrobution conditions
        if option != "":
            if option == "show w": # Show warranty information
                print("""  THERE IS NO WARRANTY FOR THE PROGRAM, TO THE EXTENT PERMITTED BY
APPLICABLE LAW.  EXCEPT WHEN OTHERWISE STATED IN WRITING THE COPYRIGHT
HOLDERS AND/OR OTHER PARTIES PROVIDE THE PROGRAM "AS IS" WITHOUT WARRANTY
OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING, BUT NOT LIMITED TO,
THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
PURPOSE.  THE ENTIRE RISK AS TO THE QUALITY AND PERFORMANCE OF THE PROGRAM
IS WITH YOU.  SHOULD THE PROGRAM PROVE DEFECTIVE, YOU ASSUME THE COST OF
ALL NECESSARY SERVICING, REPAIR OR CORRECTION.""")
            elif option == "show c":
                print("See the License sections 4, 5, 6, and 7 for redistribution conditions, located in the LICENSE file.") # Direct user to distrobution conditions
            elif option == 'q':
                print("quitting")
                sys.exit()
            else:
                print("Invalid entry")
        else:
            break

    print("""
    _____ _____  ___    
   /  ___/  ___|/ _ \\   
   \\ `--.\\ `--./ /_\\ \\  
    `--. \\`--. \\  _  |  
   /\\__/ /\\__/ / | | |  
   \\____/\\____/\\_| |_/  
   """)
    print("Welcome to the Simple Static Analysis tool! This is a tool to help analyze suspected malware by automating various tests.")
    print("NOTE: This program does not guarantee malware detection, it merely runs tests and displays the results. Just because there are results does not mean a file is malware.")
    print("      This program may display false positives for malware, and it may not catch unknown malware.")
    while True:
        print()
        print("Enter the path of the file to scan or the path of a directory to scan all files within:")
        inFile_Path = input("\t")
        inFile_List = []
        if not os.path.exists(inFile_Path):
            print("Entered file path does not exist.")
        else:
            if os.path.isfile(inFile_Path):
                inFile_List.append(inFile_Path)
                break
            else:
                for path, dirs, files in os.walk(inFile_Path, topdown=False):
                    for name in files:
                        inFile_List.append(os.path.join(path, name))
                break
    isOutFileChosen = False
    while not isOutFileChosen:
        print()
        print("Enter a name for the output file; NOT A PATH; DO NOT INCLUDE AN EXTENSION:")
        excluded_chars = ["\\","/",":","*","?","\"","<",">","|","~","#","%","&","{","}","(",")","[","]","$","!","'","@","+","`","="," ",",","^",";"]
        outFile_Name = input("\t")
        rejected = False
        for char in excluded_chars:
            if char in outFile_Name:
                if char == " ":
                    print("file name cannot contain a space")
                else:
                    print(f"file name cannot contain character {char}")
                rejected = True
        if rejected:
            continue
        if os.path.exists(outFile_Name + ".txt"):
            chosen = False
            print(f"A file already exists with this name. Continuing with this file name will completely overwrite this file.")
            while not chosen:
                overwrite = input("Continue? (y/n): ")
                if overwrite == "y":
                    print("Continuing with chosen file name")
                    isOutFileChosen = True
                    chosen = True
                    break
                elif overwrite == "n":
                    print("Choose a different name for the output file")
                    chosen = True
                else:
                    print("Please enter 'y' or 'n'")
        else:
            isOutFileChosen = True
    outFile = outFile_Name + ".txt"
    with open(outFile, "w+") as OF:
        with open("OutputHeader.txt", "r") as header:
            # Copy the output header from the OutputHeader file
            FileHeader = header.read()
            OF.write(FileHeader)
        # Write the timestamp of analysis and the name of the analyzed file
        OF.write("Timestamp: " + str(datetime.datetime.now()))
        OF.write("\n")
        OF.write("Analyzed File(s): ")
        tmp = 0
        for item in inFile_List:
            root, fileName = os.path.split(item)
            if tmp > 0:
                OF.write(r", ")
            OF.write(fileName)
        OF.write("\n")
    print()
    print("The file(s) to scan is/are; ")
    for entry in inFile_List:
        print(entry)
    print(f"and the output will be saved to {outFile}.")
    input("Press enter to continue:")
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
    print("Do you want to use the included hash list csv for the scanning process? y/n")
    while True:
        choice = input("\t")
        if choice == "y":
            defaultScan = True
            break
        elif choice == "n":
            # Get path for different csv
            chosen = False
            while not chosen:
                print("Enter the path to the desired csv file, or enter 'default' to use the included hash list: ")
                scanFile_Path = input("\t")
                if scanFile_Path == "default":
                    defaultScan = True
                    break
                if not os.path.exists(scanFile_Path):
                    print("Path entered does not exist. This may be due to spelling errors")
                else:
                    root, extension = os.path.splitext(scanFile_Path)
                    if extension != ".csv":
                        print("Path entered does not lead to a .csv file. Enter a .csv file")
                    else:
                        scanFile = root + extension
                        defaultScan = False
                        chosen = True
            break
        else:
            print("Invalid option")
    print()
    print("Do you wish to add more keywords or regular expressions for this analysis? y/n")
    option = input("\t")
    addtnlKeywords = []
    if option == "n":
        print("Using default string searching")
    elif option == "y" or option == "Y":
        while True:
            print("Enter one or more keyword options to search for, enter a regular expression, or enter 'q' to quit. If entering multiple keywords, seperate them with a space.")
            user_input = input("")
            if user_input == "q":
                break
            for entry in user_input.split(" "):
                addtnlKeywords.append([entry, "User Input"])
    else:
        print("Invalid option, using default string searching.")
    print()
    # Allow more YARA rules from user input
    for inFile in inFile_List:
        Hash_List = Full_Fingerprint(inFile, outFile, HashType)
        if defaultScan:
            Scanning(Hash_List, outFile)
        else:
            Scanning(Hash_List, outFile, scanFile)
        String_Searching(inFile, outFile, addtnlKeywords)
        Identify_Obfuscation(inFile, outFile, True)
        Dissasembly(inFile, outFile)
    input("Press enter to end program")
    sys.exit()


# Help function to display syntax if help is input
def Help():
    print("Syntax for one command: SimpleStaticAnalysis.py <file_to_scan> <name_for_output_file>")
    print(
        "NOTE: This program will generate a header in the file, please ensure the file does not exist or is empty."
    )
    print(
        "<file_to_scan> is either a file in the same folder as this program or a path to a file. The extension doesn't matter, but it needs to be included here."
    )
    print(
        "<name_for_output_file> is just a simple name for the output file. Do not include an extension, as this program automatically adds the .txt extension."
    )
    print("Syntax for interactive mode: SimpleStaticAnalysis.py OR SimpleStaticAnalysis.py interactive")
    sys.exit()


# Main function
def main():
    if len(sys.argv) == 1 or sys.argv[1] == "interactive":
        Interactive_Mode()
    elif sys.argv[1] == "help":
        Help()
    elif len(sys.argv) == 2:
        print("Unrecognized argument")
        Help()
    elif len(sys.argv) > 3:
        print("Too many arguments entered")
        Help()
    else:
        # Save the files for easy use
        inFile = sys.argv[1]
        try:
            with open(inFile, "r") as IF:
                print(f"{inFile} exists")
        except FileNotFoundError:
            print(f"{inFile} does not exist. This may be due to spelling errors or from an incorrect path. Please double check the path.")
            sys.exit()
        outFile = sys.argv[2] + ".txt"
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
        Dissasembly(inFile, outFile)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("Exicing through Keyboard Interrupt")
        sys.exit()