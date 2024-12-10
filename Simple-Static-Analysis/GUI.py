"""
Simple Static Analysis - A malware analysis tool
Copyright (C) 2024 Lucas Ramage

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.
This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
You should have received a copy of the GNU General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

# Imports
import datetime  # Allow for timestamps
import os  # Allow multi-system compatability with file paths
import requests  # Allow getting files from web pages
import tempfile  # Allow for temporary files that do not get saved each run
import yara_x  # Allow the use of YARA rules

# tkinter imports
from tkinter import *  # General tkinter stuff for GUI
from tkinter import ttk  # Special style options for tkinter
from tkinter import filedialog  # Allow for file dialogs
from tkinter import messagebox  # Allow for warnings with input validation
from tkinter import scrolledtext  # Allow for scrollable text boxes

# Get all of the functions from SimpleStaticAnalysis.py
import SimpleStaticAnalysis as SSA

# Version Number
version = "1.0.0"


# App class for storing info and creating the root window
class App(Tk):
    def __init__(self):
        super().__init__()
        # General window config
        self.title(f"Simple Static Analysis Version {version}")
        self.minsize(600, 375)
        self.maxsize(1600, 1000)
        self.configure(background="#323232")
        self.center_window()

        # Make a container for the other frames
        self.container = Frame(self)
        self.container.pack(
            side="top",
            fill="both",
            expand=True,
        )

        # Store info for access by later frames
        # General project info like date and title
        self.projectInfo = {
            "Title": StringVar(),
            "Analyst": StringVar(),
            "Date": StringVar(),
        }
        # Info relating to fingerprinting and scanning
        self.scanInfo = {
            "inFile": StringVar(),
            "fingerLevel": StringVar(),
            "scanList": StringVar(),
        }
        # Additional keyword list stored as a string seperated at newlines
        self.searchList = StringVar()
        # A list containing all of the YARA rules files
        self.yaraList = Variable()
        # Output information
        self.cacheFolder = StringVar()
        self.outFile = StringVar()
        self.disassembleFile = StringVar()
        os.mkdir("GUI_Cache")
        self.cacheFolder.set("GUI_Cache")
        self.outFile.set(os.path.join(self.cacheFolder.get(), "Output.txt"))

        # Allow for clean-up when the window is closed.
        self.protocol("WM_DELETE_WINDOW", self.button_quit)

        # Create all of the subframes
        self.frames = {}
        for F in (StartPage, ScanPage, KeyPage, YaraPage, ProgressPage, OutPage):
            frame = F(self.container, self)
            self.frames[F] = frame
            frame.configure(relief="sunken")
            frame.grid(
                row=0,
                column=0,
                sticky=NSEW,
            )

        # Ensure the container resizes with the frame
        self.container.grid_rowconfigure(0, weight=1)
        self.container.grid_columnconfigure(0, weight=1)

        # Show the first frame
        self.show_frame(StartPage)

    # A function to show a specific frame
    def show_frame(self, page):
        """Shows the input frame and configures all of the rows and columns

        Args:
            page (Class(Frame)): The name of a frame class to show.
        """
        frame = self.frames[page]
        frame.tkraise()
        for i in range(frame.grid_size()[0]):
            frame.rowconfigure(i, pad=10, weight=1)
        for i in range(frame.grid_size()[1]):
            frame.columnconfigure(i, pad=10, weight=1)

        # Resize the window to fit the current frame's content
        self.update_idletasks()  # Update window geometry after raising the frame
        self.center_window()

    # A function to quit the program cleanly
    def button_quit(self):
        """A function to quit the program with cache cleanup"""
        # Go through all files in the cache folder and delete them
        for path, dir, files in os.walk(self.cacheFolder.get(), topdown=False):
            for name in files:
                os.remove(os.path.join(path, name))
        # Delete the cache folder now that it is empty
        os.rmdir(self.cacheFolder.get())
        # Quit the program
        self.quit()

    # A function to center the window on the screen
    def center_window(self):
        """A function to center the window on the screen regardless of screen size."""
        # Get the screen width and height
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()

        # Get the window dimensions
        window_width = self.winfo_reqwidth()
        window_height = self.winfo_reqheight()

        # Calculate the position to center the window
        position_top = int((screen_height // 2) - (window_height // 1.5))
        position_left = (screen_width // 2) - (window_width // 2)

        # Set the window position using the geometry method
        self.geometry(f"{window_width}x{window_height}+{position_left}+{position_top}")


# The Start Page
class StartPage(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        # Label the page
        pageLabel = Label(
            self,
            text="Enter Project Information",
        )
        pageLabel.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky=EW,
        )
        # Allow access to the controller in functions
        self.controller = controller
        # Set the date part of project info
        self.controller.projectInfo["Date"].set(str(datetime.date.today()))

        # Various labels for different entries
        projectLabel = Label(
            self,
            text="Project Name:",
        )
        nameLabel = Label(
            self,
            text="Analyst Name:",
        )
        dateLabel = Label(
            self,
            text="Project Date:",
        )
        projectLabel.grid(
            row=1,
            column=1,
            sticky=E,
        )
        nameLabel.grid(
            row=2,
            column=1,
            sticky=E,
        )
        dateLabel.grid(
            row=3,
            column=1,
            sticky=E,
        )

        # Entries for project info
        # Title entry
        self.projectEntry = Entry(
            self,
            textvariable=self.controller.projectInfo["Title"],
        )
        # Analyst name entry
        self.nameEntry = Entry(
            self,
            textvariable=self.controller.projectInfo["Analyst"],
        )
        # Project date entry, defaults to current date
        self.dateEntry = Entry(
            self,
            textvariable=self.controller.projectInfo["Date"],
        )
        self.projectEntry.grid(
            row=1,
            column=2,
            sticky=EW,
        )
        self.nameEntry.grid(
            row=2,
            column=2,
            sticky=EW,
        )
        self.dateEntry.grid(
            row=3,
            column=2,
            sticky=EW,
        )

        # Copyright information
        CLabel = Label(
            self,
            text="Simple Static Analysis, (C) 2024 Lucas Ramage",
        )
        CLabel.grid(
            row=4,
            column=1,
            columnspan=2,
            sticky=EW,
        )

        # Quit button, uses App.button_quit
        quitButton = ttk.Button(
            self,
            text="QUIT",
            command=lambda: controller.button_quit(),
        )
        quitButton.grid(
            row=4,
            column=0,
            sticky=NSEW,
        )

        # Button to validate input fields and go to the next page
        nextButton = ttk.Button(
            self,
            text="Next",
            command=lambda: controller.show_frame(ScanPage),
        )
        nextButton.grid(
            row=4,
            column=3,
            sticky=EW,
        )

    # Function to validate input fields and to go to the next page
    def validateInput(self):
        """Validates input fields to prevent errors. If any fields are empty, show a warning. Otherwise, go to the next page."""
        # Check if any fields were left empty. If they are, show a warning. If not, it goes to the scan page.
        if (
            self.controller.projectInfo["Title"].get() == None
            or self.controller.projectInfo["Analyst"].get() == None
        ):
            # Warning telling user to provide entries in the relevant fields
            messagebox.showwarning(
                title="Warning",
                message="Please provide entries in the Title and Analyst sections",
            )
        else:
            self.controller.show_frame(ScanPage)


# The Scan Page
class ScanPage(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)
        # Allow access to the controller within functions
        self.controller = controller

        # A list containing options for the dropdown menu on this page
        self.fingerOptions = [
            "Low",
            "Extended",
            "Full",
        ]

        # Set default values for some scan info
        self.controller.scanInfo["fingerLevel"].set("Low")
        self.controller.scanInfo["scanList"].set("default")

        # The page label
        pageLabel = Label(
            self,
            text="File Scanning Information",
        )
        pageLabel.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky=EW,
        )

        # Label with instructions for choosing the input file
        inFileInst = Label(
            self,
            text="Choose a file to analyze:",
        )
        inFileInst.grid(
            row=1,
            column=1,
            columnspan=2,
            sticky=EW,
        )

        # Label for the input file
        inFilePrompt = Label(
            self,
            text="File to analyze:",
        )
        inFilePrompt.grid(
            row=2,
            column=1,
            sticky=E,
        )

        # Label that displays the name of the input file
        inFileLabel = Label(
            self,
            text="File not chosen",
        )
        inFileLabel.grid(
            row=2,
            column=2,
            sticky=EW,
        )

        # Button to allow user to choose input file
        inFileButton = ttk.Button(
            self,
            text="Choose file",
            command=lambda: self.getInFile(inFileLabel),
        )
        inFileButton.grid(
            row=2,
            column=3,
            sticky=EW,
        )

        # Instructions for choosing fingerprinting level
        fingerInst = Label(
            self,
            text="Choose a fingerprinting level:",
        )
        fingerInst.grid(
            row=3,
            column=1,
            columnspan=2,
            sticky=EW,
            ipady=5,
        )

        # Label for fingerprinting level
        fingerLabel = Label(
            self,
            text="Fingerprinting Level:",
        )
        fingerLabel.grid(
            row=4,
            column=1,
            sticky=E,
            ipady=5,
        )

        # Dropdown menu to choose fingerprinting level
        fingerDrop = OptionMenu(
            self,
            self.controller.scanInfo["fingerLevel"],
            *self.fingerOptions,
        )
        fingerDrop.grid(
            row=4,
            column=2,
            sticky=NSEW,
            ipady=5,
        )

        # Instructions for choosing a csv file to scan against
        scanListInst = Label(
            self,
            text="Choose a CSV file to scan against:",
        )
        scanListInst.grid(
            row=5,
            column=1,
            columnspan=2,
            sticky=EW,
            ipady=5,
        )

        # Label for csv file
        scanListPrompt = Label(
            self,
            text="File to reference:",
        )
        scanListPrompt.grid(
            row=6,
            column=1,
            sticky=E,
            ipady=5,
        )

        # Label to display the name of the csv file
        scanListLabel = Label(
            self,
            text="Included List",
        )
        scanListLabel.grid(
            row=6,
            column=2,
            sticky=EW,
            ipady=5,
        )

        # Button to allow user to choose a csv file
        scanListButton = ttk.Button(
            self,
            text="Choose file",
            command=lambda: self.getScanList(scanListLabel),
        )
        scanListButton.grid(
            row=6,
            column=3,
            sticky=EW,
        )

        # Button to allow the user to reset the csv file to default
        scanListReset = ttk.Button(
            self,
            text="Default",
            command=lambda: self.resetScanList(scanListLabel),
        )
        scanListReset.grid(
            row=6,
            column=4,
            sticky=EW,
        )

        # Button to quit the GUI
        quitButton = ttk.Button(
            self,
            text="QUIT",
            command=lambda: controller.button_quit(),
        )
        quitButton.grid(
            row=7,
            column=0,
            sticky=NSEW,
        )

        # Button to go to the next page
        nextButton = ttk.Button(
            self,
            text="Next",
            command=lambda: self.validateScanList(),
        )
        nextButton.grid(
            row=7,
            column=5,
            sticky=EW,
        )

    # Function to get the input file
    def getInFile(self, label):
        """A function to get the input file

        Args:
            label (Label): The label that displays the input file name
        """
        self.controller.scanInfo["inFile"].set(filedialog.askopenfilename())
        dir, name = os.path.split(self.controller.scanInfo["inFile"].get())
        label.configure(text=name)

    # Function to get the csv file
    def getScanList(self, label):
        """A function to allow the user to choose a csv file

        Args:
            label (Label): The label that displays the name of the csv file
        """
        self.controller.scanInfo["scanList"].set(filedialog.askopenfilename())
        dir, name = os.path.split(self.controller.scanInfo["scanList"].get())
        label.configure(text=name)

    # Function to reset the csv file to default
    def resetScanList(self, label):
        """Resets the csv file to default

        Args:
            label (Label): The label that displays the name of the csv file
        """
        self.controller.scanInfo["scanList"].set("default")
        label.configure(text="Included List")

    # Function to validate that the chosen scanList file is a csv file
    def validateScanList(self):
        """Validates the scanList file being a csv file, and validates that there is a selected input file. If either of these is invalid, it displays a warning. Otherwise, it goes to the next page."""
        inputGood = True
        # Validate the scanList.
        if self.controller.scanInfo["scanList"].get() != "default":
            path, ext = os.path.splitext(self.controller.scanInfo["scanList"].get())
            if ext != ".csv":
                # Alert and ask for re-entry
                inputGood = False
                messagebox.showwarning(
                    title="Warning",
                    message=f"An incorrect file type was entered for the scanning list. You entered a(n) {ext} file, need a .csv file. Please try again.",
                )
        # Validate input file
        if self.controller.scanInfo["inFile"].get() == None:
            inputGood = False
            messagebox.showwarning(
                title="Warning",
                message="Please choose a file to analyze.",
            )
        if inputGood:
            self.controller.show_frame(KeyPage)


# The Keyword Page
class KeyPage(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        # Allow access to the controller in functions
        self.controller = controller

        # The page label/title
        pageTitle = Label(
            self,
            text="String Searching Information",
        )
        pageTitle.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky=EW,
        )

        # Label containing instructions for the page
        pageInst = Label(
            self,
            text="Enter any amount of keywords and/or regular expressions. Separate entries by a newline.",
        )
        pageInst.grid(
            row=1,
            column=1,
            sticky=W,
        )

        # A large scrolled text entry for inputting keywords and regular expressions
        self.keywordEntry = scrolledtext.ScrolledText(
            self,
            wrap=WORD,
            width=32,
            height=20,
        )
        self.keywordEntry.grid(
            row=2,
            column=1,
            sticky=NSEW,
        )

        # Quit button
        quitButton = ttk.Button(
            self,
            text="QUIT",
            command=lambda: controller.button_quit(),
        )
        quitButton.grid(
            row=3,
            column=0,
            sticky=NSEW,
        )

        # Next page button
        nextButton = ttk.Button(
            self,
            text="Next",
            command=lambda: self.submitText(),
        )
        nextButton.grid(
            row=3,
            column=2,
            sticky=EW,
        )

    # Function to submit searchList info to the controller then go to the next page
    def submitText(self):
        """Submit the searchList information to the controller"""
        self.controller.searchList.set(
            self.keywordEntry.get(
                "1.0",
                END,
            )
        )
        self.controller.show_frame(YaraPage)


# The YARA Rules Page
class YaraPage(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        # Allow access to the controller in functions
        self.controller = controller

        # Default 2 YARA rules files
        self.yaraList = [
            "crypto_signatures.txt",
            "packer.txt",
        ]

        # Page label/title
        pageTitle = Label(
            self,
            text="YARA Rules to check",
        )
        pageTitle.grid(
            row=0,
            column=0,
            columnspan=3,
            sticky=EW,
        )

        # Label with instructions for the page
        pageInst = Label(
            self,
            text="Choose more YARA files to check the input file against.\nThese files can be .txt, .yar, .yara, .YAR, or .YARA files.\nIf the file compiles, it is added to the list. If not, it is ignored.",
        )
        pageInst.grid(
            row=1,
            column=1,
            sticky=EW,
        )

        # Label to display all of the YARA rules files selected
        yaraListLabel = Label(
            self,
            text="",
        )
        # Update the label to display the default 2
        self.updateYaraListLabel(yaraListLabel)
        yaraListLabel.grid(
            row=3,
            column=1,
            sticky=EW,
        )

        # A button to allow the user to select a YARA rule file
        addButton = ttk.Button(
            self,
            text="Add File",
            command=lambda: self.appendFromButton(yaraListLabel),
        )
        addButton.grid(
            row=2,
            column=1,
        )

        # Quit button
        quitButton = ttk.Button(
            self,
            text="QUIT",
            command=lambda: controller.button_quit(),
        )
        quitButton.grid(
            row=4,
            column=0,
            sticky=NSEW,
        )

        # Button to go to the next page
        nextButton = ttk.Button(
            self,
            text="Next",
            command=lambda: self.submitYaraList(),
        )
        nextButton.grid(
            row=4,
            column=2,
            sticky=EW,
        )

    # A function to temporarily convert a file to a txt file
    def temp_convert_to_txt(self, path):
        """Temporarily converts a file to a txt file

        Args:
            path (path STR): The file to convert

        Returns:
            temp_file.name: A string representing the temporary txt file
        """
        with open(path, "rb") as rulefile:
            text = rulefile.read()
        with tempfile.NamedTemporaryFile(suffix=".txt", delete=False) as temp_file:
            temp_file.write(text)
            return temp_file.name

    # A function to validate that a selected file compiles correctlu\y
    def validateRules(self, file, label):
        """Attempts to compile a selected file. If it does, it adds the file to the YARA list. If not, show a warning.

        Args:
            file (path STR): Selected file
            label (_type_): The label that displays the YARA rules files
        """
        # Convert the file to a txt temporarily
        tmpTXT = self.temp_convert_to_txt(file)
        try:
            # Try to compile the rules. If it can't compile, it will throw an error.
            with open(tmpTXT, "r") as ruleFile:
                rules = yara_x.compile(ruleFile.read())
            # Add the file to the list and update the label
            self.yaraList.append(file)
            self.updateYaraListLabel(label)
        except Exception as err:
            # Show a warning if the selected file cannot compile
            messagebox.showwarning(
                title=err,
                message=f"Selected file could not compile.\n{err}",
            )

    # Function to update the YARA list label
    def updateYaraListLabel(self, label):
        """Updates the label that displays all of the YARA rules files

        Args:
            label (Label): The label that displays the YARA list
        """
        tmpText = ""
        for file in self.yaraList:
            root, filename = os.path.split(file)
            tmpText += f"{filename},\n"
        label.configure(text=tmpText)

    # Function that allows a user to select a file, then it tries to validate the file.
    def appendFromButton(self, label):
        """Allow the user to select a file, then validate that file

        Args:
            label (Label): The label that displays the YARA rules list
        """
        file = filedialog.askopenfilename()
        self.validateRules(file, label)

    # Function that submits the YARA list to the controller and goes to the next page
    def submitYaraList(self):
        """Submits the YARA list to the controller, then goes to the next page"""
        self.controller.yaraList.set(self.yaraList)
        self.controller.show_frame(ProgressPage)


# The Analysis Page
# This is the page that does all of the work
class ProgressPage(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        # Allow access to the controller in functions
        self.controller = controller

        # Get the output info from the controller for easy access
        self.outFile = self.controller.outFile.get()
        self.outFolder = self.controller.cacheFolder.get()

        # The page lable/title
        pageTitle = Label(
            self,
            text="Running Analysis",
        )
        pageTitle.grid(
            row=0,
            column=0,
            columnspan=4,
            sticky=EW,
        )

        # A button that loads the information from the controller
        loadDetails = ttk.Button(
            self,
            text="Load Details",
            command=lambda: self.updateProjectDetails(),
        )
        loadDetails.grid(
            row=1,
            column=1,
            columnspan=2,
            sticky=EW,
        )

        # Various labels
        # Label for project information
        self.infoLabel = Label(
            self,
            text="<Title>, <Analyst>, <Date>",
        )
        self.infoLabel.grid(
            row=2,
            column=1,
            columnspan=2,
            sticky=EW,
        )

        # Label for the input file
        inFileLabel = Label(
            self,
            text="File to Analyze:",
        )
        inFileLabel.grid(
            row=3,
            column=1,
            sticky=W,
        )

        # Label that displays the name of the input file
        self.inFileDisplay = Label(
            self,
            text="<inFile>",
        )
        self.inFileDisplay.grid(
            row=3,
            column=2,
            sticky=W,
        )

        # Label for the fingerprinting level
        fingerLabel = Label(
            self,
            text="Fingerprinting Level:",
        )
        fingerLabel.grid(
            row=4,
            column=1,
            sticky=W,
        )

        # Label that displays the fingerprinting level
        self.fingerLevelLabel = Label(
            self,
            text="<fingerLevel>",
        )
        self.fingerLevelLabel.grid(
            row=4,
            column=2,
            sticky=W,
        )

        # Label for the scanList csv
        scanListLabel = Label(
            self,
            text="Hash List to Reference:",
        )
        scanListLabel.grid(
            row=5,
            column=1,
            sticky=W,
        )

        # Label that displays the name of the csv
        self.hashListLabel = Label(
            self,
            text="<scanList>",
        )
        self.hashListLabel.grid(
            row=5,
            column=2,
            sticky=W,
        )

        # Button to start the analyses
        # This button is inactive until the details are loaded
        self.StartButton = ttk.Button(
            self,
            text="Start",
            state="disabled",
            command=lambda: self.buttonStart(),
        )
        self.StartButton.grid(
            row=6,
            column=1,
            columnspan=2,
        )

        # A progress/loading bar
        self.progressBar = ttk.Progressbar(
            self,
            mode="indeterminate",
        )
        self.progressBar.grid(
            row=7,
            column=1,
            columnspan=2,
            sticky=NSEW,
            ipadx=5,
            ipady=5,
        )

        # Label for the current runnong process
        processLabel = Label(
            self,
            text="Current Process:",
        )
        processLabel.grid(
            row=8,
            column=1,
            sticky=W,
        )

        # Label that displays the current running process
        self.currentProcess = Label(
            self,
            text="<currentProcess>",
        )
        self.currentProcess.grid(
            row=8,
            column=2,
            sticky=W,
        )

        # Quit button
        quitButton = ttk.Button(
            self,
            text="QUIT",
        )
        quitButton.grid(
            row=9,
            column=0,
            sticky=E,
        )

        # Button to go to next page
        # This button is inactive until all analyses are done
        self.nextButton = ttk.Button(
            self,
            text="Next",
            state="disabled",
            command=lambda: controller.show_frame(OutPage),
        )
        self.nextButton.grid(
            row=9,
            column=9,
            sticky=EW,
        )

    # A function to update all of the details on the page
    def updateProjectDetails(self):
        """Updates and displays all of the information on the page. I had to implement this because it would only display the initial empty values at first and needed to be updated."""
        self.infoLabel.configure(
            text=f"{self.controller.projectInfo["Title"].get()}, {self.controller.projectInfo["Analyst"].get()}, {self.controller.projectInfo["Date"].get()}"
        )
        dir, fileName = os.path.split(self.controller.scanInfo["inFile"].get())
        self.inFileDisplay.configure(
            text=f"{fileName}",
        )
        self.fingerLevelLabel.configure(
            text=f"{self.controller.scanInfo["fingerLevel"].get()}"
        )
        if self.controller.scanInfo["scanList"].get() != "default":
            scanDir, scanFile = os.path.split(
                self.controller.scanInfo["scanList"].get()
            )
            self.hashListLabel.configure(text=f"{scanFile}")
        else:
            self.hashListLabel.configure(
                text="Recent 48hrs from MalwareBazaar",
            )
        # Activates the start button
        self.StartButton.configure(state="normal")

    # Function to run the analyses
    def buttonStart(self):
        """This function runs all of the functions from SimpleStaticAnalysis using the info from the user."""
        # Start the loading bar
        self.progressBar.start()
        # Write the output header and project information to the output file
        with open(self.outFile, "w+") as OF:
            with open("OutputHeader.txt", "r") as header:
                OF.write(header.read())
            OF.write(f"Project: {self.controller.projectInfo["Title"].get()}\n")
            OF.write(f"Analyst: {self.controller.projectInfo["Analyst"].get()}\n")
            OF.write(f"Date: {self.controller.projectInfo["Date"].get()}\n")
            dir, fileName = os.path.split(self.controller.scanInfo["inFile"].get())
            OF.write(f"Analyzed File: {fileName}")

        # Create local variables for all of the information for easy access
        inFile = self.controller.scanInfo["inFile"].get()
        outFile = self.outFile
        outFolder = self.outFolder
        type = self.controller.scanInfo["fingerLevel"].get()
        scanList = self.controller.scanInfo["scanList"].get()
        searchList = []
        for item in self.controller.searchList.get().split("\n"):
            searchList.append([item.strip(), "User Input"])
        yaraList = self.controller.yaraList.get()

        # Fingerprinting
        self.currentProcess.configure(text="Fingerprinting")
        hashList = SSA.Full_Fingerprint(inFile, outFile, type, ConsoleOutput=False)

        # Scanning
        self.currentProcess.configure(text="Scanning")
        # If the scanList is default, get the most recent 48 hours csv from MalwareBazaar
        if scanList == "default":
            scanList = "recent.csv"
            url = "https://bazaar.abuse.ch/export/csv/recent/"
            response = requests.get(url)
            if response.status_code == 200:
                try:
                    # Store the file from MalwareBazaar as a temporary file
                    tmpScanFile = tempfile.NamedTemporaryFile(
                        suffix=".csv", delete=False
                    )
                    # Write a header to the file
                    tmpScanFile.write(
                        b'"first_seen_utc","sha256_hash","md5_hash","sha1_hash","reporter","file_name","file_type_guess","mime_type","signature","clamav","vtpercent","imphash","ssdeep","tlsh"\n'
                    )
                    # Write the content of the requested file to the temp file
                    tmpScanFile.write(response.content)
                    tmpScanFile.close()
                    scanList = tmpScanFile.name
                except Exception as e:
                    # Allow for graceful handling of unexpected errors.
                    print("Something failed")
                    print(e)
        SSA.Scanning(hashList, outFile, scanList, ConsoleOutput=False)

        # String Searching
        self.currentProcess.configure(text="String Searching")
        SSA.String_Searching(inFile, outFile, searchList, ConsoleOutput=False)

        # Identify Obfuscation
        self.currentProcess.configure(text="Identifying Obfuscation")
        # If the YARA list only contains the default 2, just run the function normally.
        # Otherwise, run it with a sublist containing all elements from the YARA list past the default 2.
        if len(yaraList) == 2:
            SSA.Identify_Obfuscation(inFile, outFile, ConsoleOutput=False)
        elif len(yaraList) > 2:
            SSA.Identify_Obfuscation(inFile, outFile, yaraList[2:], ConsoleOutput=False)

        # Disassembly
        self.currentProcess.configure(text="Disassembling")
        # Create the disassembly file in the cache
        dissFile = SSA.Disassembly(inFile, outFile, outFolder, ConsoleOutput=False)
        self.controller.disassembleFile.set(dissFile)

        # Done
        # Set the outfile with the current contents
        self.controller.outFile.set(outFile)
        # Stop the bar
        self.progressBar.stop()
        # Activate the next page button
        self.nextButton.configure(state="normal")


# The page to display and save the output
class OutPage(Frame):
    def __init__(self, parent, controller):
        super().__init__(parent)

        # Allow access to the controller within functions
        self.controller = controller

        # Obtain the output from the controller
        self.outFile = self.controller.outFile
        self.dissFile = self.controller.disassembleFile

        # The page label/title
        pageTitle = Label(
            self,
            text="Preview and save results",
        )
        pageTitle.grid(
            row=0,
            column=0,
            columnspan=5,
            sticky=EW,
        )

        # The label for the general output
        outputLabel = Label(
            self,
            text="Results File",
        )
        outputLabel.grid(
            row=1,
            column=1,
            sticky=EW,
        )

        # The label for the disassembly of the input file
        dissLabel = Label(
            self,
            text="Disassembled File",
        )
        dissLabel.grid(
            row=1,
            column=3,
            sticky=EW,
        )

        # Buttons to allow the user to preview the output
        outFilePreview = ttk.Button(
            self,
            text="Preview",
            command=lambda: self.preview(self.outFile),
        )
        outFilePreview.grid(
            row=2,
            column=1,
            sticky=EW,
        )
        dissFilePreview = ttk.Button(
            self,
            text="Preview",
            command=lambda: self.preview(self.dissFile),
        )
        dissFilePreview.grid(
            row=2,
            column=3,
            sticky=EW,
        )

        # Buttons to save the output to a specific folder using automatic naming conventions
        outputSaveButton = ttk.Button(
            self,
            text="Save",
            command=lambda: self.SaveButton(self.outFile),
        )
        outputSaveButton.grid(
            row=3,
            column=1,
            sticky=EW,
        )
        dissSaveButton = ttk.Button(
            self,
            text="Save",
            command=lambda: self.SaveButton(self.dissFile),
        )
        dissSaveButton.grid(
            row=3,
            column=3,
            sticky=EW,
        )

        # Buttons to save the output to a specific folder using a specific name
        outSaveAs = ttk.Button(
            self,
            text="Save As",
            command=lambda: self.SaveAsButton(self.outFile),
        )
        outSaveAs.grid(
            row=4,
            column=1,
            sticky=EW,
        )
        dissSaveAs = ttk.Button(
            self,
            text="Save As",
            command=lambda: self.SaveAsButton(self.dissFile),
        )
        dissSaveAs.grid(
            row=4,
            column=3,
            sticky=EW,
        )

        # A button to save both output files to a specific folder using automatic naming conventions
        saveAllButton = ttk.Button(
            self,
            text="Save All",
            command=lambda: self.SaveAllButton(),
        )
        saveAllButton.grid(
            row=5,
            column=2,
            sticky=EW,
        )

        # Quit Button
        quitButton = ttk.Button(
            self,
            text="QUIT",
            command=lambda: controller.button_quit(),
        )
        quitButton.grid(
            row=6,
            column=0,
            sticky=EW,
        )

        # A button to finish the program. Prompts the user with a warning that unsaved output will be lost.
        finishButton = ttk.Button(
            self,
            text="Finish",
            command=lambda: self.finishPrompt(),
        )
        finishButton.grid(
            row=6,
            column=4,
            sticky=EW,
        )

    # A function to preview the selected file
    def preview(self, file):
        """Allows the user to preview a selected output file.

        Args:
            file (path StringVar): The StringVar that contains the path to the file
        """
        # Create a new window on top of the current window
        previewWin = Toplevel(self)

        # Set the title of the new window
        previewWin.title("Preview")

        # Set the weights of the rows
        previewWin.rowconfigure(0, pad=10, weight=1)
        previewWin.columnconfigure(0, pad=10, weight=1)

        # Set up a scrolled text widget with empty text
        previewText = scrolledtext.ScrolledText(
            previewWin,
            wrap=WORD,
        )
        previewText.grid(
            row=0,
            column=0,
            sticky=NSEW,
        )
        # Update the scrolled text widget with the text contents of the file
        with open(file.get(), "r") as File:
            previewText.insert(END, File.read())

    # A function to save the selected file to a folder
    def SaveButton(self, file):
        """This function allows the user to select a folder/directory to save the file to. It saves the file using automatic naming.

        Args:
            file (path StringVar): The StringVar containing the path to the file
        """
        # Ask the user for a directory
        destFolder = filedialog.askdirectory()
        # If the user closes the window withour selecting a directory, cancel the save by returning
        if destFolder is None:
            return
        # Get the name of the file seperate from the cache folder
        dir, name = os.path.split(file.get())
        # Combine the name with the project title
        fileName = f"{self.controller.projectInfo["Title"].get()}_{name}"
        # Add the selected folder to the name
        saveName = os.path.join(destFolder, fileName)
        # Copy the contents of the selected file to a new file with the generated name in the selected folder
        with open(saveName, "w+") as destFile:
            with open(file, "r") as target:
                destFile.write(target.read())
        return

    # A function to allow the user to save the file with a custom name
    def SaveAsButton(self, file):
        """Allows the user to save the file to a selected directory with a custom name.

        Args:
            file (path StringVar): The StringVar that contains the path to the file
        """
        # Use the filedialoge asksaveasfile function to do all of the work in creating the new file in the destination folder
        f = filedialog.asksaveasfile(
            mode="w",
            defaultextension=".txt",
        )
        # If the user closes the window, cancel the save and return
        if f is None:
            return
        # Copy the contents of the selected file to the destination file.
        with open(file.get(), "r") as target:
            f.write(target.read())
        f.close()
        return

    # A function to save both output files to a user-selected directory
    def SaveAllButton(self):
        """Allows the user to select a directory to save the output to. Uses automatic naming just like the SaveButton function."""
        # Allow the user to select the folder
        destFolder = filedialog.askdirectory()
        # If the user quits the menu, return from the function and cancel the save operation
        if destFolder is None:
            return
        # Get the file names seperate from the cache folder and add the project title to them.
        outDir, outName = os.path.split(self.outFile.get())
        dissDir, dissName = os.path.split(self.dissFile.get())
        destOutFileName = f"{self.controller.projectInfo["Title"].get()}_{outName}"
        destDissFileName = f"{self.controller.projectInfo["Title"].get()}_{dissName}"
        # Add the selected folder to the path
        destOutFile = os.path.join(destFolder, destOutFileName)
        destDissFile = os.path.join(destFolder, destDissFileName)
        # Copy the files from the cache folder to their respective destination file
        with open(destOutFile, "w") as destFile:
            with open(self.outFile.get(), "r") as target:
                destFile.write(target.read())
        with open(destDissFile, "w") as destFile:
            with open(self.dissFile.get(), "r") as target:
                destFile.write(target.read())
        return

    # A function to inform the user that unsaved results will be lost if they finish without saving.
    def finishPrompt(self):
        """This function informs the user that unsaved results will be lost. It creates a window with the warning text and two buttons. One button to cancel and go back to save the output, another to finish and quit."""
        # Create and format a window on top of the current window
        finishWarningWindow = Toplevel(self)

        # Title the window
        finishWarningWindow.title("Warning")

        # Place the warning text
        warningText = Label(
            finishWarningWindow,
            text="Are you sure you are ready to finish?\nYou will lose any unsaved results.",
        )
        warningText.grid(
            row=0,
            column=1,
            sticky=EW,
            rowspan=2,
        )

        # This button closes this window only
        cancelButton = ttk.Button(
            finishWarningWindow,
            text="CANCEL",
            command=lambda: finishWarningWindow.quit(),
        )
        cancelButton.grid(
            row=3,
            column=0,
            sticky=EW,
        )

        # This button fully quits the GUI
        leaveButton = ttk.Button(
            finishWarningWindow,
            text="FINISH",
            command=lambda: self.controller.button_quit(),
        )
        leaveButton.grid(
            row=3,
            column=2,
            sticky=EW,
        )


# Activate the main loop
if __name__ == "__main__":
    app = App()
    app.mainloop()
