from xml.etree import ElementTree as ET
import os
import re

# New list to merge all findings
MergeList = []

FortifyFileNames = []
BurpFileNames = []
MergedFileNames = []


def merge():
    # Import and parse Fortify XML Findings File
    fortifytree = ET.parse(filename1)
    fortifyroot = fortifytree.getroot()

    # Import and parse Burp XML Findings File
    burptree = ET.parse(filename2)
    burproot = burptree.getroot()

    global burpfindingcount
    global fortifyfindingcount
    burpfindingcount = 0
    fortifyfindingcount = 0

    # for tag == 'FileName' #fortify tag
    # for tag == 'location' #burp tag, start at end of string and work backwards. Keep everything until the first slash and strip out the rest.
    # for tag == 'Category' #fortify vulnerability type
    # for tag == 'name' #burp vulnerability type

    # Add all file names for Fortify findings
    for fortifyissue in fortifyroot.iter(tag="Issue"):
        for fortifyfilename in fortifyissue.iter(tag="FileName"):
            if fortifyfilename != "None":
                fortifyfilename = fortifyfilename.text.strip()
                FortifyFileNames.append(fortifyfilename)

    # Add all file names for Burp findings
    for burpissue in burproot.iter(tag="issue"):
        for burpfilename in burpissue.iter(tag="path"):
            burpfilename = os.path.basename(burpfilename.text.strip())
            burpfilename = re.sub("[\(\[].*?[\)\]]", "", burpfilename)
            BurpFileNames.append(burpfilename)

    MergedFileNames = list(set(FortifyFileNames) & set(BurpFileNames))

    # Check Burp file names against the merged list and add findings if found
    for burpissue in burproot.iter(tag="issue"):
        burpfindingname = os.path.basename(burpissue.find("name").text.strip())
        burpfindingname = re.sub("[\(\[].*?[\)\]]", "", burpfindingname)
        burpseverity = burpissue.find("severity").text
        burpfilename = os.path.basename(burpissue.find("path").text.strip())
        burpfilename = re.sub("[\(\[].*?[\)\]]", "", burpfilename)
        if burpfilename in MergedFileNames:
            MergeList.append("-" * 50)
            MergeList.append("Filename: " + burpfilename)
            MergeList.append("Burp Finding: " + burpfindingname)
            MergeList.append("Burp Severity: " + burpseverity)
            burpfindingcount += 1

    MergeList.append("\n" + "Total Burp Findings: " + str(burpfindingcount) + "\n" + "\n" + "\n")

    # Check Fortify file names against the merged list and add findings if found
    for fortifyissue in fortifyroot.iter(tag="Issue"):
        fortifyfinding = fortifyissue.find("Category").text
        fortifyseverity = fortifyissue.find("Friority").text
        for fortifyfilename in fortifyissue.iter(tag="FileName"):
            if fortifyfilename != "None":
                fortifyfilename = fortifyfilename.text.strip()
                if fortifyfilename in MergedFileNames:
                    MergeList.append("-" * 50)
                    MergeList.append("Filename: " + fortifyfilename)
                    MergeList.append("Fortify Finding: " + fortifyfinding)
                    MergeList.append("Fortify Severity: " + fortifyseverity)
                    fortifyfindingcount += 1

    MergeList.append("\n" + "Total Fortify Findings: " + str(fortifyfindingcount) + "\n" + "\n" + "\n")


# -------------------------------------------------------------------
# OLD VERSION (Did not capture everything)
# -------------------------------------------------------------------
# for burpissue in burproot.iter(tag="issue"):
#	burpfilename = os.path.basename(burpissue.find("location").text.strip())
#	burpfilename = re.sub("[\(\[].*?[\)\]]", "", burpfilename)
#	for fortifyissue in fortifyroot.iter(tag="Issue"):
#		for fortifyfilename in fortifyissue.iter(tag="FileName"):
#			if fortifyfilename != "None":
#				fortifyfilename = fortifyfilename.text.strip()
#				if fortifyfilename == burpfilename:
#					MergeList.append("-" * 50)
#					MergeList.append("Filename: " + fortifyfilename)
#					for burpfinding in burpissue.iter("name"):
#						MergeList.append("Burp Finding: " + burpfinding.text)
#						MergeList.append("Burp Severity: " + burpissue.find("severity").text)
#						burpfindingcount += 1
#					for fortifyfinding in fortifyissue.iter('Category'):
#						MergeList.append("Fortify Finding: " + fortifyfinding.text)
#						MergeList.append("Fortify Severity: " + fortifyissue.find("Friority").text)
#						fortifyfindingcount += 1


if __name__ == '__main__':
    filename1 = input('Enter Fortify File: ') + '.xml'
    filename2 = input('Enter Burp File: ') + '.xml'
    merge()
    mergedfile = open("Merged Findings.xml", "w+")
    for item in MergeList:
        mergedfile.write(item + "\n")
    mergedfile.close()
