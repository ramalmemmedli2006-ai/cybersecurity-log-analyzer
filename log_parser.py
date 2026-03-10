
import re


def parse_log_file(file_path: str) -> list[dict]:
    events = []

    failed_pattern = re.compile(
        r"Failed password for (invalid user )?(?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )
    success_pattern = re.compile(
        r"Accepted password for (?P<username>\S+) from (?P<ip>\d+\.\d+\.\d+\.\d+)"
    )

    with open(file_path, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            failed_match = failed_pattern.search(line)
            if failed_match:
                events.append(
                    {
                        "event_type": "failed_login",
                        "username": failed_match.group("username"),
                        "ip": failed_match.group("ip"),
                        "raw": line,
                    }
                )
                continue

            success_match = success_pattern.search(line)
            if success_match:
                events.append(
                    {
                        "event_type": "successful_login",
                        "username": success_match.group("username"),
                        "ip": success_match.group("ip"),
                        "raw": line,
                    }
                )

    return events
