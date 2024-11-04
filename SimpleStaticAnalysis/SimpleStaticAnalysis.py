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
import magic
import charset_normalizer
import yara


# Fingerprinting function
def Full_Fingerprint(File_To_Scan, Output_File):
    """This function generates hashes of the input file using the four most common hash types used in system foresnics.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file

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
        with open(File_To_Scan, "rb") as f:  # Open the input file
            # Calculate the hashes and write them to the output file
            File_MD5 = hashlib.md5(f.read()).hexdigest()
            OF.write(f"\tMD5 Hash: {File_MD5}\n")
            File_SHA1 = hashlib.sha1(f.read()).hexdigest()
            OF.write(f"\tSHA-1 Hash: {File_SHA1}\n")
            File_SHA256 = hashlib.sha256(f.read()).hexdigest()
            OF.write(f"\tSHA-256 Hash: {File_SHA256}\n")
            File_SHA512 = hashlib.sha512(f.read()).hexdigest()
            OF.write(f"\tSHA-512 Hash: {File_SHA512}\n")
            # Put the SHA-256, MD5, and SHA-1 hashes in a list in a specific order and with a specific format for scanning.
            Hash_List.append(f' "{File_SHA256}"')
            Hash_List.append(f' "{File_MD5}"')
            Hash_List.append(f' "{File_SHA1}"')
        OF.write("\n")
        print(
            "Finished Fingerprinting"
        )  # Let the user know fingerprinting has finished.
    return Hash_List  # Return the list with hashes for use in scanning


# Scanning function
def Scanning(File_Hash_List, Output_File):
    """This function scans the hashes from the provided hash list, taken from the fingerprinting function, and compares them to the csv file included with known malware hashes.

    Args:
        File_Hash_List (list): A list of hashes in a specific format
        Output_File (path STR): The destination output file
    """
    with open(Output_File, "a+") as OF:  # Open the output file
        OF.write("Scanning Results\n")  # Create scan result section
        Results_List = []
        print("")
        print("Starting scan")  # Let the user know scanning has begun
        print("")
        with open(
            "full.csv", newline=""
        ) as csvfile:  # Open the known malware csv for reading
            Hash_Data_Reader = csv.reader(csvfile, delimiter=",")
            for (
                row
            ) in (
                Hash_Data_Reader
            ):  # Read through each row. If the row has multiple entries, it checks the provided hash list against the proper entries.
                try:
                    # If matches are found, write the hash matched and the name of the known malware to a list of lists
                    for entry in row:
                        for hash in File_Hash_List:
                            if hash in entry:
                                Results_List.append(["Match found: ", hash])
                except IndexError:  # If the row only has one entry, go to the next row
                    next(Hash_Data_Reader, None)
            if (
                len(Results_List) == 0
            ):  # If no matches are found, write that to the output file
                OF.write("No matches\n")
            else:  # If matches are found, write them to the output file
                OF.write("Matches Found:\n")
                for entry in Results_List:
                    OF.write(f"\t{entry[0]} for hash {entry[1]}\n")

        print("Finished scan")  # Let the user know that scanning is done.


# String Searching
def String_Searching(File_To_Scan, Output_File):
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
        with open("stringRegEx.txt", "r") as regex:
            Regex_Patterns = regex.readlines()
        with open(File_To_Scan, "r") as IF:
            # Open the input file and read it into a variable
            text_lines = IF.readlines()
            for pattern in Regex_Patterns:
                found = False
                pattern = pattern.strip()
                OF.write(f"Pattern: {pattern}\n")
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
    """This function detects character encoding using two different methods, and detects file encoding using a third method.

    Args:
        File_To_Scan (path STR): The input file to read from
        Output_File (path STR): The destination output file
    """
    print("Detecting Encoding")  # Inform the user the encoding detection has begun
    with open(Output_File, "a+") as OF:
        OF.write("\tDetecting Character Encoding\n")
        with open(File_To_Scan, "rb") as f:
            text = f.read()  # Generate a string of the file to detect with this method
            Detect_Results = charset_normalizer.detect(text)
            if Detect_Results["encoding"] is not None:
                # If an encoding method is found, output the encoding scheme and confidence
                OF.write("\t\tUsing Charset Normalizer detect:\n")
                OF.write(
                    f"\t\t\tGot {Detect_Results['encoding']} encoding with {Detect_Results['confidence']} confidence\n"
                )
        Normalizer_Results = charset_normalizer.from_path(
            File_To_Scan
        ).best()  # Use a second method to scan the entire file
        if Normalizer_Results is not None:
            # If an encoding method is found, output the scheme
            OF.write("\t\tUsing Charset Normalizer from file:\n")
            OF.write(f"\t\t\tDetected {Normalizer_Results.encoding} encoding\n")
        with open(File_To_Scan, "rb") as IF:
            # Use a third method to scan for file-level mime encoding like base64.
            text = IF.read()
            detector = magic.Magic(mime_encoding=True)
            encoding = detector.from_buffer(text)
            OF.write("\t\tUsing Magic:\n")
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
    packer_Rules = yara.compile("packer.yar")
    crypto_Rules = yara.compile("crypto_signatures.yar")
    with open(Output_File, "a+") as OF:
        OF.write("\tDetecting Packing and Cryptors\n")
        cryptor_Matches = crypto_Rules.match(File_To_Scan)  # Match cryptor rules
        OF.write("\t\tFound Cryptors:\n")
        # If matches are found, output them. Otherwise, output no results found
        if cryptor_Matches:
            OF.write(f"\t\t\t{cryptor_Matches}\n")
        else:
            OF.write("\t\t\tNo Cryptors found\n")
        packer_Matches = packer_Rules.match(File_To_Scan)  # Match packer rules
        OF.write("\t\tFound Packers:\n")
        # If matches are detected, output them. Otherwise, output no results
        if packer_Matches:
            OF.write(f"\t\t\t{packer_Matches}\n")
        else:
            OF.write("\t\t\tNo Packers found\n")
    print(
        "Finished detecting packing"
    )  # Inform the user that this process has finished.


# Identify Obfuscation
def Identify_Obfuscation(File_To_Scan, Output_File):
    """This function calls Identify_Encoding and Identify_Packing.

    Args:
        File_To_Scan (_type_): _description_
        Output_File (_type_): _description_
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
    Identify_Packing(File_To_Scan, Output_File)  # Call the function to identify packing
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
    Dissasembly_File = f"SSA_Dissasembly_File_{str(datetime.datetime.now())}.txt"  # Make a unique dissasembly file using the current date
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


# Main function
def main():
    if sys.argv[1] == "help" or len(sys.argv) == 1:
        # Help function to display syntax if help is input or if no arguments are provided
        print("Syntax: SimpleStaticAnalysis.py <file_to_scan> <name_for_output_file>")
        print(
            "NOTE: This program will generate a header in the file, please ensure the file does not exist or is empty."
        )
        print(
            "<file_to_scan> is either a file in the same folder as this program or a path to a file. The extension doesn't matter, but it needs to be included here."
        )
        print(
            "<name_for_output_file> is just a simple name for the output file. Do not include an extension, as this program automatically adds the .txt extension."
        )
        sys.exit()
    else:
        # Save the files for easy use
        inFile = sys.argv[1]
        outFile = sys.argv[2] + ".txt"
    with open(outFile, "a+") as OF:
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
    main()