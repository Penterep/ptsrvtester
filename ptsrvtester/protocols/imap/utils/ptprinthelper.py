from . import ptdefs
import re
import os
import shutil


def print_banner(scriptname, version, condition=None, space=1) -> None:
    if not condition:
        print(rf"""
 ____            _                        _____           _
|  _ \ ___ _ __ | |_ ___ _ __ ___ _ __   |_   _|__   ___ | |___
| |_) / _ \ '_ \| __/ _ \ '__/ _ \ '_ \    | |/ _ \ / _ \| / __|
|  __/  __/ | | | ||  __/ | |  __/ |_) |   | | (_) | (_) | \__ \
|_|   \___|_| |_|\__\___|_|  \___| .__/    |_|\___/ \___/|_|___/
                                 |_|{" "*(26-len(scriptname+version)-1)}{scriptname} v{version}
                                       https://www.penterep.com""")
        print("\n"*space)


def help_print(help_object, scriptname, version) -> None:
    print_banner(scriptname, version)
    for help_item in help_object:
        print( out_title(f"{list(help_item.keys())[0].capitalize().replace('_', ' ')}:", show_bullet=False))
        lines = list(help_item.values())[0]
        cols_width = help_calc_column_width(lines)
        for line in lines:
            if isinstance(line, list):
                for index, column in enumerate(line):
                    if not index:
                        print("   ", end="")
                    print(column, end=(cols_width[index]-len(column)+2)*' ')
                print("")
            else:
                print(f"   {line}")
        print("")


def help_calc_column_width(lines: list[list]) -> list[int]:
    if isinstance(lines[0], list):
        max_cols_len =  [0 for x in range(10)]
        for row in lines:
            for index, column in enumerate(row):
                x = len(column)
                if (x > max_cols_len[index]) and not index+1 == len(row):
                    max_cols_len[index] = x
        return max_cols_len


def ptprint(string: str, bullet_type="TEXT", condition=None, end="\n", flush=False, colortext=False, clear_to_eol=False, newline_above=False, filehandle=False, indent=0) -> None:

    if string:
        bullet_type = "" if not isinstance(bullet_type, str) else bullet_type
        bullet_type = bullet_type.upper()
        if condition is None:
            if colortext:
                if isinstance(colortext, str):
                    string = get_colored_text(string, colortext)
                else:
                    string = get_colored_text(string, bullet_type)
            else:
                string = bullet(bullet_type) + string

        elif condition and condition is not None:
            string = out_if(string, bullet_type, condition, colortext, indent=indent)
        else:
            return

        if newline_above:
            string = "\n" + string

        if clear_to_eol:
            if os.name == "posix":
                string = string + (' ' * (terminal_width() - len_string_without_colors(string)))

        print(string, end=end, flush=flush)

        if filehandle:
            string = re.sub(r"\033\[\d+m", "", string)
            filehandle.write(string.lstrip()+end)



def get_colored_text(string: str, color: str) -> str:
    return f"{ptdefs.colors[color]}{string}{ptdefs.colors['TEXT']}"



def out_if(string="", bullet_type="TEXT", condition=True, colortext=False, indent=0) -> str:
    if bullet_type is None:
        bullet_type = ""
    if condition:
        if colortext:
            return f"{' '*indent}{bullet(bullet_type)}{ptdefs.colors[bullet_type]}{string}{ptdefs.colors['TEXT']}"
        else:
            return f"{' '*indent}{bullet(bullet_type)}{string}"
    return ""


def out_title_if(string="", condition=True, show_bullet=True) -> str:
    if condition:
        return out_title(string, show_bullet)
    else:
        return ""


def out_title_ifnot(string="", condition=False, show_bullet=True) -> str:
    if not condition:
        return out_title(string, show_bullet)
    else:
        return ""


def out_title(string, show_bullet=True) -> str:
    if show_bullet:
        return f"{bullet('TITLE')}{ptdefs.colors['TITLE']}{string}{ptdefs.colors['TEXT']}"
    else:
        return f"{ptdefs.colors['TITLE']}{string}{ptdefs.colors['TEXT']}"


def out_ifnot(string="", bullet_type=None, condition=False, colortext=False) -> str:
    if not condition:
        if colortext:
            return f"{bullet(bullet_type)}{ptdefs.colors[bullet_type]}{string}{ptdefs.colors['TEXT']}"
        else:
            return f"{bullet(bullet_type)}{string}"
    else:
        return ""


def bullet(bullet_type=None) -> str:
    if bullet_type and ptdefs.chars.get(bullet_type):
        return f"{ptdefs.colors[bullet_type]}[{ptdefs.chars[bullet_type]}]{ptdefs.colors['TEXT']} "
    else:
        return ""


def ptprint_(string: str, end="\n", flush=False, clear_to_eol=False, filehandle=False) -> None:
    """Legacy solution"""
    if string:
        if clear_to_eol:
            string = string + (' ' * (terminal_width() - len_string_without_colors(string)))
        print(string, end=end, flush=flush)
        if filehandle:
                string = re.sub(r"\033\[\d+m", "", string)
                filehandle.write(string.lstrip()+end)


def add_spaces_to_eon(string: str, minus=0, condition=False) -> str:
    if condition:
        return string
    else:
        prefix_len = 33 # increase about 3 dots
        max_len = terminal_width() - minus
        str_len = len_string_without_colors(string)
        if max_len < str_len:
            prefix = string[:prefix_len - 3]
            suffix_len = max_len - prefix_len
            suffix = string[-suffix_len:] if suffix_len > 0 else ""
            return f"{prefix}...{suffix}"
        return string + (' ' * (terminal_width() - len_string_without_colors(string) - minus))

def terminal_width() -> int:
    return terminal_size()[0]


def len_string_without_colors(string) -> int:
    return len(strip_ANSI_escape_sequences_sub("", string))


def terminal_height() -> int:
    return terminal_size()[1]


def terminal_size() -> tuple[int, int]:
    terminal_size = shutil.get_terminal_size()
    return terminal_size.columns, terminal_size.lines


strip_ANSI_escape_sequences_sub = re.compile(r"""
    \x1b     # literal ESC
    \[       # literal [
    [;\d]*   # zero or more digits or semicolons
    [A-Za-z] # a letter
    """, re.VERBOSE).sub


def clear_line_if(end="\n", condition=True) -> None:
    if condition:
        clear_line(end)


def clear_line_ifnot(end="\n", condition=False) -> None:
    if not condition:
        clear_line(end)


def clear_line(end="\n") -> None:
    if os.name == "posix":
        print(' '*terminal_width(), end=end)