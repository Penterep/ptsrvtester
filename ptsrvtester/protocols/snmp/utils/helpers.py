import argparse


def write_to_file(output, message_or_messages: str | list[str]):
    """
    File Output.
    """
    try:
        with open(output, "a") as f:
            if isinstance(message_or_messages, str):
                f.write(message_or_messages + "\n")
            elif isinstance(message_or_messages, list):
                for message in message_or_messages:
                    f.write(message + "\n")
    except FileNotFoundError:
        raise argparse.ArgumentError(None, f"File not found: '{output}'")
    except PermissionError:
        raise argparse.ArgumentError(
            None, f"Cannot write file (permission denied): '{output}'"
        )
    except OSError as e:
        raise argparse.ArgumentError(None, f"Cannot write file '{output}': {e}")

def format_timeticks(value):
    """
    Convert Timeticks to a human-readable string.
    """

    ticks = int(value)
    days, remainder = divmod(ticks, 8640000)  # 1 day = 8640000 timeticks
    hours, remainder = divmod(remainder, 360000)
    minutes, remainder = divmod(remainder, 6000)
    seconds = remainder // 100
    return f"{days} day, {hours}:{minutes:02}:{seconds:02}.{remainder % 100}"