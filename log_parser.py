
import re
from datetime import datetime

import pandas as pd


# expected log format: date, time, severity, service, and message.

LOG_PATTERN = re.compile(
    r"^(\d{4}-\d{2}-\d{2}) "
    r"(\d{2}:\d{2}:\d{2}) "
    r"(INFO|WARN|WARNING|ERROR|DEBUG|CRITICAL) "
    r"(\S+) "
    r"(.+)$"
)


def parse_logs(log_text):
    """
    Read the log file line by line and turn valid entries into a DataFrame.
    Keep track of any lines that don't match the expected format.
    """
    parsed_entries = []
    invalid_lines = []

    # Go through each line while keeping its original line number.
    #here i thought about skipping empty lines as they waste time parsing

    for line_number, line in enumerate(
        log_text.splitlines(), start=1
    ):
        line = line.strip()

        if not line:
            continue

       
        # Save anything that doesn't match so it can be reviewed later.

        match = LOG_PATTERN.match(line)

        if not match:
            invalid_lines.append({
                "line_number": line_number,
                "content": line
            })
            continue

        date, time, level, service, message = match.groups()

        # Convert the date and time into a proper timestamp.
      
        try:
            timestamp = datetime.strptime(
                f"{date} {time}",
                "%Y-%m-%d %H:%M:%S"
            )
        except ValueError:
            invalid_lines.append({
                "line_number": line_number,
                "content": line
            })
            continue

        # Store each valid log entry with its original line number.

        parsed_entries.append({
            "line_number": line_number,
            "timestamp": timestamp,
            "level": level,
            "service": service,
            "message": message
        })

    #column to be used same everywhere

    columns = [
        "line_number",
        "timestamp",
        "level",
        "service",
        "message"
    ]

    dataframe = pd.DataFrame(
        parsed_entries,
        columns=columns
    )


    if not dataframe.empty:
        dataframe = dataframe.sort_values(
            by=["timestamp", "line_number"]
        ).reset_index(drop=True)

    return dataframe, invalid_lines
