
def generate_report(
    total_failed: int,
    failed_counts: dict,
    suspicious_ips: dict,
    targeted_users: dict,
) -> str:
    lines = []
    lines.append("=== Cybersecurity Log Analysis Report ===")
    lines.append("")
    lines.append(f"Total failed login attempts: {total_failed}")
    lines.append("")

    lines.append("Failed attempts by IP:")
    if failed_counts:
        for ip, count in failed_counts.items():
            lines.append(f"- {ip} => {count} failed attempts")
    else:
        lines.append("- No failed login attempts found")

    lines.append("")
    lines.append("Potential brute-force activity detected from:")
    if suspicious_ips:
        for ip, count in suspicious_ips.items():
            lines.append(f"- {ip} => {count} failed attempts")
    else:
        lines.append("- No brute-force pattern detected")

    lines.append("")
    lines.append("Most targeted usernames:")
    if targeted_users:
        for username, count in targeted_users.items():
            lines.append(f"- {username} => {count} attempts")
    else:
        lines.append("- No targeted usernames found")

    return "\n".join(lines)


def save_report(report: str, file_path: str = "security_report.txt") -> None:
    with open(file_path, "w", encoding="utf-8") as file:
        file.write(report)
