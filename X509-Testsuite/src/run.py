import os
import sys

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
                content = f.read()
                if '@AnvilTest(id = "")' in content:
                    # generate 5 byte long random hex string
                    random_hex = os.urandom(5).hex()
                    # replace the id with the random hex string
                    content = content.replace('@AnvilTest(id = "")', '@AnvilTest(id = "REPLACE-' + random_hex + '")')
                    # write the content back to the file
                    with open(os.path.join(root, file), 'w') as f:
                        f.write(content)

walk_dir(".")