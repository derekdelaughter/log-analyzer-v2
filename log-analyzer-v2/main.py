import argparse
from app.menu import run_menu
from app.analyzer import analyze_logs

def main():
    parser = argparse.ArgumentParser(
        description="Security-focused Log Analyzer"
    )
    parser.add_argument("--path", help="Directory to scan")
    parser.add_argument("--keyword", help="Keyword to search")
    parser.add_argument("--regex", help="Regex patter to search")
    parser.add_argument("--security", action="store_true",
                        help="Enable security detections")
    
    args = parser.parse_args()

    if args.path and (args.keyword or args.regex):
        analyze_logs(
            path=args.path,
            pattern=args.keyword or args.regex,
            regex=bool(args.regex),
            security=args.security
        )
    else:
        run_menu()

if __name__ == "__main__":
    main()