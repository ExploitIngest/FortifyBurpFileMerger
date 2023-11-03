# Combining findings from Burp Suite and Fortify scans, and then de-duplicating them in a Python script requires parsing both XML files, extracting relevant data, and implementing logic to identify and remove duplicate findings. 
# Below is a simplified script that demonstrates the process using Python's xml.etree.ElementTree for XML parsing and a set to handle duplicates.
# Assuming you have XML files from both Burp Suite and Fortify, named burp_findings.xml and fortify_findings.xml, respectively, here's a script to merge and de-duplicate the findings:

import xml.etree.ElementTree as ET

# Load Burp Suite XML findings
burp_tree = ET.parse('burp_findings.xml')
burp_root = burp_tree.getroot()

# Load Fortify XML findings
fortify_tree = ET.parse('fortify_findings.xml')
fortify_root = fortify_tree.getroot()

# Define a set to store unique findings
unique_findings = set()

# Merge Burp Suite findings
for burp_finding in burp_root.findall('.//Issue'):
    unique_findings.add(ET.tostring(burp_finding, encoding='unicode'))

# Merge Fortify findings
for fortify_finding in fortify_root.findall('.//Issue'):
    unique_findings.add(ET.tostring(fortify_finding, encoding='unicode'))

# Create a new XML document for de-duplicated findings
merged_root = ET.Element('Findings')

for unique_finding in unique_findings:
    merged_root.append(ET.fromstring(unique_finding))

merged_tree = ET.ElementTree(merged_root)

# Save the merged and de-duplicated findings to a new XML file
merged_tree.write('merged_findings.xml', encoding='utf-8', xml_declaration=True)

print('Merged and de-duplicated findings saved to merged_findings.xml')
