import os

def clear_pycache(directory):
    for root, dirs, files in os.walk(directory):
        if '__pycache__' in dirs:
            print(f"Removing: {os.path.join(root, '__pycache__')}")
            os.system(f'rm -rf "{os.path.join(root, "__pycache__")}"')
        for file in files:
            if file.endswith('.pyc'):
                print(f"Removing: {os.path.join(root, file)}")
                os.remove(os.path.join(root, file))

# Use the current directory as the starting point
clear_pycache('.')
print("Finished clearing __pycache__ directories and .pyc files.")