import os
import re

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