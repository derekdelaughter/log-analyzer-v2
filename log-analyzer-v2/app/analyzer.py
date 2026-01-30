import re
import json
from datetime import datetime
from collections import defaultdict
from app.file_scanner import get_log_files
from app.detectors import (
    detect_failed_logins,
    extract_ips_and_timestamps,
    detect_bruteforce_time_window
)

REPORT_DIR = "data/reports"

def analyze_logs(path, pattern, regex=False, security=False):
    files = get_log_files(path)
    if not files:
        print(" No log files found.")
        return
    
    results = {}
    total_matches = 0
    failed_login_total = 0
    all_events = []

    for file in files:
        try:

            with open(file, "r", errors="ignore") as f:
                lines = f.readlines()
        except IOError:
            continue

        match_count = scan_lines(lines, pattern, regex)
        if match_count:
            results[file] = match_count
            total_matches += match_count

        if security:
            failed_login_total += detect_failed_logins(lines)
            all_events.extend(extract_ips_and_timestamps(lines))
    
    bruteforce_ips = detect_bruteforce_time_window(all_events)

    print_summary(
        total_matches,
        failed_login_total,
        bruteforce_ips
    )

    save_report(
        pattern,
        results,
        total_matches,
        failed_login_total,
        bruteforce_ips
    )

def scan_lines(lines, pattern, regex):
    count = 0
    for line in lines:
        if regex:
            if re.search(pattern, line):
                count += 1
        else:
            if pattern.lower() in line.lower():
                count +=1
    return count

def print_summary(total, failed, bruteforce):
    print("\n==== Security Summary ====")
    print(f"Total pattern matches: {total}")
    print(f"Failed login attempts: {failed}")

    if bruteforce:
        print("\n ime-Window Brute Force Detected:")
        for ip, data in bruteforce.items():
            print(
                f"{ip} -> {data[ 'attempts']} attemps "
                f"within {data[ 'window_minutes']} minutes"
                )
    else:
        print("\nNo brute-force behavior detected.")
    
    print("============================\n")

def save_report(pattern, results, total, failed, bruteforce):
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report = {
        "pattern": pattern,
        "total_matches": total,
        "failed_logins": failed,
        "time_window_bruteforce": bruteforce,
        "files": results,
        "timestamp": timestamp
    }

    filename = f"{REPORT_DIR}/report_{timestamp}.json"
    with open(filename, "w") as f:
        json.dump(report, f, indent =4)

    print(f"Reprt saved: {filename}")