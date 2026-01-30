import os

def get_directory():
    while True:
        path = input("ENter directory path to scan: ").strip()
        if os.path.isdir(path):
            return path
        print("Invalid directory.")

def get_search_term(prompt):
    while True:
        value = input(prompt).strip()
        if value:
            return value
        print("Input cannot be empty.")