import re
from collections import defaultdict
from datetime import datetime, timedelta

FAILED_LOGIN_PATTERNS = [
    r"failed password",
    r"authentication failure",
    r"invalid user"
]

IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
TIMESTAMP_REGEX = r"\d{4}-\d{2} \d{2}:\d{2}"

def detect_failed_logins(lines):
    count = 0
    for line in lines:
        for pattern in FAILED_LOGIN_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                count += 1
    return count

def extract_ips_and_timestamps(lines):
    events = []

    for line in lines:
        ip_match = re.search(IP_REGEX, line)
        time_match = re.search(TIMESTAMP_REGEX, line)

        if ip_match and time_match:
            try:
                timestamp = datetime.strptime(
                    time_match.group(), "%Y-%m-%d %H:%M:%S"
                )
                events.append((ip_match.group(), timestamp))
            except ValueError:
                continue

    return events

def detect_bruteforce_time_window(
        events, threshold=5, window_minutes=2
):

    ip_events = defaultdict(list)

    for ip, timestamp in events:
        ip_events[ip].append(timestamp)

    suspicious_ips = {}

    for ip, timestamps in ip_events.items():
        timestamps.sort()

        for i in range(len(timestamps)):
            window_start = timestamps[i]
            window_end = window_start + timedelta(minutes=window_minutes)

            count = sum(
                1 for t in timestamps
                if window_start<= t <= window_end
            )

            if count >= threshold:
                suspicious_ips[ip] = {
                    "attempts": count,
                    "window_minutes": window_minutes
                }
                break

    return suspicious_ips