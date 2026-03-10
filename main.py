
from log_parser import parse_log_file
from detector import count_failed_logins, detect_bruteforce, count_user_targets
from report_generator import generate_report, save_report


def main() -> None:
    log_file = "sample_logs.txt"

    events = parse_log_file(log_file)

    failed_events = [event for event in events if event["event_type"] == "failed_login"]
    failed_counts = count_failed_logins(events)
    suspicious_ips = detect_bruteforce(failed_counts, threshold=3)
    targeted_users = count_user_targets(events)

    report = generate_report(
        total_failed=len(failed_events),
        failed_counts=failed_counts,
        suspicious_ips=suspicious_ips,
        targeted_users=targeted_users,
    )

    print(report)
    save_report(report)

    print("\nReport saved as security_report.txt")


if __name__ == "__main__":
    main()
