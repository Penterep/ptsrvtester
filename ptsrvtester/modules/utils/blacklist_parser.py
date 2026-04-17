import re, json, httpx
from bs4 import BeautifulSoup
from typing import Callable

from ptlibs.ptprinthelper import get_colored_text, help_calc_column_width


class BlacklistParser:
    def __init__(self, ptdebug: Callable[..., None], use_json=None, verbose_mode=None):
        self.ptdebug = ptdebug
        self.use_json = use_json
        self.verbose_mode = verbose_mode
        self.result = None

    BLACKLIST_TIMEOUT = 15.0
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def _get_auth_keys(self):
        try:
            response = httpx.get(
                "https://mxtoolbox.com/api/v1/user",
                headers={
                    "Accept": "application/json, text/javascript, */*; q=0.01",
                    "User-Agent": self.USER_AGENT,
                    "Referer": "https://mxtoolbox.com/",
                },
                timeout=self.BLACKLIST_TIMEOUT,
            )
            if response.status_code != 200:
                raise ValueError(
                    f"mxtoolbox.com returned HTTP {response.status_code} "
                    f"(API may block automated access - try again later or check network)"
                )
            auth_key = response.json()
        except ValueError:
            raise
        except Exception as e:
            raise ValueError(f"Could not retrieve blacklist data: {type(e).__name__}: {e}") from e
        return auth_key["MxVisitorUid"], auth_key["TempAuthKey"]

    def _parse_response(self, response):
        soup = BeautifulSoup(response["HTML_Value"], "lxml")

        title = re.search(r"Checking([\s\S])*?blacklists\.", soup.text)[0]
        listed_info = re.search(r"Listed \d? times with \d? timeouts", soup.text)[0]
        result = {"title": title, "listed_info": listed_info, "table_result": []}

        table = soup.find("tbody")
        for table_a_href_tag in table.find_all("a"):
            table_a_href_tag.decompose()

        table_rows = table.find_all("tr")
        for table_row in table_rows:
            status = table_row.find("td", {"class": "table-column-Status"})
            blacklist_name = table_row.find("td", {"class": "table-column-Name"})
            reason = table_row.find("td", {"class": "tool-blacklist-reason"})
            ttl = table_row.find("td", {"class": "table-column-TTL"})
            # response_time = table_row.find('td', {'class': 'table-column-ResponseTime'})
            row_result = []
            for index, col in enumerate([status.text, blacklist_name.text, reason.text, ttl.text]):
                col.replace("\xa0", "")
                if col == "":
                    col = "-"
                row_result.append(col)
            row_result = [data.replace("\xa0", "") for data in row_result]
            # input(row_result)
            result["table_result"].append(row_result)

        return result

    def lookup(self, target):
        if self.verbose_mode:
            self.ptdebug("Retrieving auth keys ...", title=True)
        auth_visitor_id, auth_key = self._get_auth_keys()
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Tempauthorization": auth_key,
            "User-Agent": self.USER_AGENT,
            "Referer": "https://mxtoolbox.com/",
        }
        cookie = {"MxVisitorUID": auth_visitor_id}
        client = httpx.Client(http2=True, timeout=self.BLACKLIST_TIMEOUT)
        if self.verbose_mode:
            self.ptdebug("Retrieving server response ...", title=True)
        response = client.get(
            f"https://mxtoolbox.com/api/v1/Lookup?command=blacklist&argument={target}&resultIndex=1&disableRhsbl=true&format=2",
            headers=headers,
            cookies=cookie,
        ).json()
        if self.verbose_mode:
            self.ptdebug("Parsing response ... ", title=True, end="")
        if re.search("<h3>Private IP Address</h3>", response["HTML_Value"]):
            return "Cannot test Private IP Address"  # False
        result = self._parse_response(response)
        if self.verbose_mode:
            self.ptdebug("OK")

        self.result = result

        self._print_result(result)

    def get_response_json(self, result):
        if not result:
            raise ValueError("lookup method must be called first")
        return json.dumps(result)

    def _print_result(self, result):
        max_width = help_calc_column_width(result["table_result"])
        table_heading = f"STATUS{' '*(max_width[0]-6+5)}BLACKLIST{' '*(max_width[1]-9+2)}REASON{' '*(max_width[2]-6+7)}TTL{' '*(max_width[3]-3+2)}"
        sep = "-" * (len(table_heading) + max_width[3] + 1)
        self.ptdebug(sep)
        self.ptdebug(table_heading)
        for table_row in result["table_result"]:
            table_row_before_colors = table_row[0]
            if table_row[0] == "OK":
                status = get_colored_text(table_row[0], color="NOTVULN")
            elif table_row[0] in ["LISTED", "TIMEOUT"]:
                status = get_colored_text(table_row[0], color="VULN")
            else:
                status = table_row[0]
            self.ptdebug(f"{status}", end=" " * (max_width[0] - len(table_row_before_colors) + 5))
            self.ptdebug(f"{table_row[1]}", end=" " * (max_width[1] - len(table_row[1]) + 2), indent_override=0)
            self.ptdebug(f"{table_row[2]}", end=" " * (max_width[2] - len(table_row[2]) + 7), indent_override=0)
            self.ptdebug(f"{table_row[3]}", end=" " * (max_width[3] - len(table_row[3]) + 2), indent_override=0)
            self.ptdebug(" ", indent_override=0)
        self.ptdebug(result["title"])
        self.ptdebug(result["listed_info"])
