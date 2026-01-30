from app.analyzer import analyze_logs
from app.utils import get_directory, get_search_term

def run_menu():
    while True:
        print("\nSecurity Log Analyzer")
        print("1. keyword scan")
        print("2. Regex scan")
        print("3. Security scan (failed logins, brute force)")
        print("4. Exit")

        choice = input("Select option (1-4): ").strip()
        path = get_directory()

        if choice == "1":
            keyword = get_search_term("Keyword: ")
            analyze_logs(path, keyword)
        
        elif choice == "2":
            regex = get_search_term("Regec: ")
            analyze_logs(path, regex, regex=True)
        
        elif choice == "3":
            analyze_logs(path, "error", security=True)
        
        elif choice == "4":
            break

        else:
            print("Invalid option.")