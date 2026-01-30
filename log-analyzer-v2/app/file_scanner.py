import os

def get_log_files(path):
    log_files = []

    for root, _, files in os.walk(os.path):
        for file in files:
            if file.endswith(".log") or file.endswith(".txt"):
                log_files.append(os.path.join(root, file))
            
    return log_files