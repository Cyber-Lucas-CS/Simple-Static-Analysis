# Simple Static Analysis Tool
Originally Created by Lucas C. Ramage
Copyright (C) 2024 Lucas Ramage

The Simple Static Analysis Tool is a Python tool to help digital forensic investigators analyze suspected malware without running it.
This tool provides all of the most used static analysis methods in a simple command-line tool. 

## Usage:
This application is intended to be used from the command line. You will need Python installed on your system to run this application, as well as the required modules listed in requirements.txt, and you will need to download the full data dump CSV file from MalwareBazaar at this link (https://bazaar.abuse.ch/export/#csv), unzip it, and move it into the folder with this program. Ensure the CSV file has the name "full.csv", otherwise this program may not work. For more info about this, see the scanning section.
The syntax for this program is:

python SimpleStaticAnalysis.py help
OR
python SimpleStaticAnalysis.py <path_to_input_file> <name_for_output_file>

The output file and dissasembled file will be in the folder with the application.

## Full_Fingerprinting:
This function fingerprints the file.

## Scanning:
This function scans the file's fingerprint against a csv of known malware, provided in 'full.csv'
This csv is downloaded from MalwareBazaar. If you wish to use a different set of fingerprints to scan against, simply download a csv file and put it in the folder that contains this program, and name it 'full.csv', or change the code to reference the new csv file.

## String_Searching:
This function searches the input file for strings matching certain regular expressions provided in the file 'stringRegEx.txt'
It writes any matches found and which pattern they matched to the output file.
If you want to add your own regular expressions or keywords, add them to the stringRegEx.txt file. 

## Packaging and Obfuscation detection:
There are multiple functions in this section.
### Identify_Encoding
This function uses multiple different methods to identify any character or file encoding.
First, it uses the charset_normalizer module detect() function on the text of the file to detect an encoding method with a percentage confidence
Then, it uses the charset_normalizer module from_file().best() to detect encoding, though this should give the same result as the detect()
Finally, it uses the magic module to detect mime encoding, like base64. This is because the other methods don't detect mime encoding.
### Identify_Packing
This function uses YARA rules to detect file packers and cryptors.

## Disassembly:
The disassembly function copies the entire input file to a txt file, character by character.
This is to prevent any accidental execution of commands, though everything using the input file is read-only.
