# Simple Static Analysis Tool
Originally Created by Lucas C. Ramage
Copyright (C) 2024 Lucas Ramage

The Simple Static Analysis Tool is a Python tool to help digital forensic investigators analyze suspected malware without running it.
This tool provides all of the most used static analysis methods in a simple command-line tool. 

## Usage:
This application is intended to be used from the command line. You will need Python installed on your system to run this application, as well as the required modules listed in requirements.txt. Depending on the version of Python you have installed, you may need to swap 'python' in the syntax for 'python3'.
The syntax for this program is:

python SimpleStaticAnalysis.py help 
This outputs a simple help message.

python SimpleStaticAnalysis.py <path_to_input_file> <name_for_output_file>
This runs the program in single command mode, with default settings on everything.

python SimpleStaticAnalysis.py OR python SimpleStaticAnalysis.py interactive
This runs the program in interactive mode, where you use more complex options.

The output file and dissasembled file will be in the folder with the application.

## Full_Fingerprinting:
This function fingerprints the file. When in interactive mode, you can specify the level of fingerprinting you want done from three levels; low, which just uses the four most common hash types; extended, which uses all hash types guaranteed to work; and full, which tries to use all available hash types in the hashlib library.

## Scanning:
This function scans the file's fingerprint against a csv of known malware uploaded in the last 48 hours.
This csv is downloaded from MalwareBazaar. If you wish to use a different set of fingerprints to scan against, use interactive mode to enter the path to your own csv file.

## String_Searching:
This function searches the input file for strings matching certain regular expressions provided in the file 'stringRegEx.csv'
It writes any matches found and which pattern they matched to the output file.
If you want to add your own regular expressions or keywords, add them to the stringRegEx.csv file. 

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
