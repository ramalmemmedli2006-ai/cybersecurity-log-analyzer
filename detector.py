
from collections import Counter


def count_failed_logins(events: list[dict]) -> Counter:
    failed_ips = [
        event["ip"]
        for event in events
        if event["event_type"] == "failed_login"
    ]
    return Counter(failed_ips)


def detect_bruteforce(failed_counts: Counter, threshold: int = 3) -> dict:
    suspicious = {}

    for ip, count in failed_counts.items():
        if count >= threshold:
            suspicious[ip] = count

    return suspicious


def count_user_targets(events: list[dict]) -> Counter:
    usernames = [
        event["username"]
        for event in events
        if event["event_type"] == "failed_login"
    ]
    return Counter(usernames)
