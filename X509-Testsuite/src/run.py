import os
import re

def generate_ids():
    # exhaustively iterate through all subfolders
    def walk_dir(path):
        for root, dirs, files in os.walk(path):
            for dir in dirs:
                walk_dir(root+dir)
            # iterate through all files in the current directory
            for file in files:
                if file.endswith(".py"):
                    continue
                print(file)
                # read file content as string
                with open(os.path.join(root, file), 'r') as f:
                    lines = []
                    for line in f:
                        lines += [line]
                    for i, line in enumerate(lines):
                        if '@AnvilTest(id = "' in line:
                            # replace the id with the random hex string
                            line = re.sub('@AnvilTest\(id = ".*"\)', '@AnvilTest(id = "REPLACE-' + os.urandom(5).hex() + '")', line)
                            # content = content.replace('@AnvilTest(id = "")', )
                        lines[i] = line

                    # join the lines back into a single string
                    content = ''.join(lines)
                    # write the content back to the file
                    with open(os.path.join(root, file), 'w') as f:
                        f.write(content)

    walk_dir(".")

def generate_metadata():

    metadata = map()


    # exhaustively iterate through all subfolders
    def walk_dir(path):
        for root, dirs, files in os.walk(path):
            for dir in dirs:
                walk_dir(root+dir)
            # iterate through all files in the current directory
            for file in files:
                if file.endswith(".py"):
                    continue
                print(file)
                # read file content as string
                with open(os.path.join(root, file), 'r') as f:
                    lines = []
                    for line in f:
                        content = line.split("(")[1]
                        if line.startswith("@Specification("):
                            entries = content.split(",")
                            # parse document from @Specification(document = "RFC 5280", section = "4.1.2.8. Unique Identifiers"
                            rfc_number = strip_entr_to_text(entries[0]).split(" ")[1]
                            rfc_section = strip_entr_to_text(entries[1])
                            description = strip_entr_to_text(entries[2])
                        elif line.startswith("@SeverityLevel("):
                            severity = content.split(")")[0]
                        elif line.startswith("@AnvilTest("):
                            id = strip_entr_to_text(content)
                            tags = None
                            metadata_entry = map()
                            metadata_entry["description"] = description
                            description["severityLevels"] = {"general": severity}
                            description["rfc"] = {"number": rfc_number, "section": rfc_section}
                            description["tags"] = tags
                            metadata[id] = metadata_entry

    walk_dir(".")

def strip_entr_to_text(entry: str):
    return entry.split('"')[1].split('"')[0]