#!/usr/bin/env python3

##############################################################
## ODFSearch Console | IPExtractX Standalone Python Script  ##
##############################################################
## Version: 1.2                                             ##
## Release Date: 1/09/2024                                  ##
## Release Author: @Onetrak-Digital-Forensics               ##
## Release License: GNUGPL-V3                               ##
## Release Status: Public                                   ##
## Release Type: Standalone Python Script                   ##
##############################################################



try:

    import os
    import ipaddress
    import re
    
    from rich import panel as rpanel
    from rich import console as rcon
    from rich import print as rprint

    import typer as TypeCLI

    prog_version = '1.2.0'

    cli_main = TypeCLI.Typer(pretty_exceptions_short=True)
    rcon_obj = rcon.Console()

except ImportError as Exception:

    print(f'Python Environment Error: {Exception}')

    raise SystemExit(3)

class IPExtractX:

    """
    IPExtractX - ODFSearch Console
    ====

    Init Parameters
    ====

    `input_path`
    ----
    `File` or `Directory` `Path` Of Data To Be Parsed.

    `outfile`
    ----
    `File Path` Where The Parser Will Save Positive Content Detection Messages To.

    `ws_kwfile`
    ----
    `File Path` Containing A List Format Of Words And/Or False Positive Emails, Seperated By New Lines.

    `ipaddr`
    ----
    `Bool`, Where `True` Enables The Detection Of IPV4/IPV6 Type Addresses.\n
    Default Is `True` if `NoneType` Is Given

    `hn`
    ----
    `Bool`, Where `True` Enables The Detection Of Hostname Type Addresses.
    Please Note: May Throw Duplicates Of EMAIL Hostnames. Should NOT Be \n
    Used In Conjunction With `emlformat`

    `ws`
    ----
    `Bool`, Where `True` Enables The Detection of Keywords, Defined In `ws_kwfile`.\n
    Must Specify `ws_kwfile`, Or This Option Becomes Disabled.\n

    `emlformat`
    ----
    `Bool`, Where `True` Enables The Detection of Email Type Addresses.\n

    `pgpheader`
    ----
    `Bool`, Where `True` Enables The Detection Of Pretty Good Privacy (PGP) Encrypted Email Exports.\n
    Method: `BEGIN PGP MESSAGE`\n

    `WRITEIO`
    ----
    `Bool`, Where `True` Enables The Writing Of Parser Data Positive To `outfile`.\n

    `PRINTIO`
    ----
    `Bool`, Where `True` Enables Parser Output Messages To Print To The Terminal.\n

    `APPENDIO`
    ----
    `Bool`, Where `True` Enables The Appending Of `content` Read From `parser.activefn` to `parser.content_list`.\n
    WARNING: May Cause Python To `Allocate Large Amounts Of Memory` If Large Quantities Of Textual Data Are Supplied.

    Return Object
    ====
    Examples:
    >>> from IPExtractX import IPExtractX as IPX
    >>> mycustomobj = IPX(content_dir, output_file, keywords_file, detect_ipaddr, detect_hostname, detect_wordsearch, detect_emails, detect_pgpheader).execute_parser()
    >>> if mycustomobj.parsed_ipaddr in customiplistobj:

    Return Argument
    ----
    The Parser Returns `set()` Versions Of The Detection Definitions. Example, You Parse IP Addresses, The Parser Will Append Postive Captures to `self.parsed_ipaddr` As A List, Then SET To Remove Duplicates.

    Return Output
    ----
    `outfile` Saves The Detection Log During Execution If `parser.write_output` Is Given `True`
    """

    def __init__(parser, input_path: str, outfile: str, ws_kwfile: str = None, ipaddr: bool = False, hn: bool = False, ws: bool = False, emlformat: bool = False, pgpheader: bool = False, WRITEIO: bool = True, PRINTIO: bool = True, APPENDIO: bool = False):

        parser.dirpath = input_path
        parser.outfile = outfile
        parser.wswordlistfile = ws_kwfile
        parser.detect_ipaddressformat = ipaddr
        parser.detect_hostnameformat = hn
        parser.detect_wordsearchformat = ws
        parser.detect_emailformat = emlformat
        parser.detect_prettygoodprivacyheaders = pgpheader

        parser.pgp_regex_pattern = '(-----BEGIN PGP PUBLIC KEY BLOCK-----)(.*?)(-----END PGP PUBLIC KEY BLOCK-----)'
        parser.ipv4_regex_pattern = r"([0-9]{1,3}\.){3}[0-9]{1,3}"
        parser.ipv6_regex_pattern = r'\b(?:[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*)?::(?:[0-9a-fA-F]{1,4}(:[0-9a-fA-F]{1,4})*)?(?:(?<=::)|(?<=:)(?=\d+\.\d+\.\d+\.\d+)|\b)\b'
        parser.hostname_regex_pattern = r'(?:(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?)'
        parser.email_regex_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'

        parser.verify_dirpath_isdir = os.path.isdir(input_path)
        parser.verify_dirpath_isfile = os.path.isfile(input_path)
        parser.verify_wswordlistfile = os.path.isfile(ws_kwfile) if ws_kwfile else False
        parser.verify_outfile = os.path.isfile(outfile)

        parser.printio = PRINTIO
        parser.appendio = APPENDIO
        parser.writeio = WRITEIO
        parser.statistics = {"PGP": 0, "IPV4": 0, "IPV6": 0, "Hostnames": 0, "Keywords": 0, "Emails": 0, "Errors": 0}
        parser.parsed_ipaddr = []
        parser.parsed_hostnames = []
        parser.parsed_emailids = []
        parser.fileids_with_pgp = []
        parser.content_list = []
        parser.activefn = str

        parser.progbanner = f"""  ___ ____  _____       _                  _  __  __\n |_ _|  _ \| ____|_  _ | |_ _ __ __ _  ___| |_\ \/ /\n  | || |_) |  _| \ \/ /| __| '__/ _` |/ __| __|\  /\n  | ||  __/| |___ >  < | |_| | | (_| | (__| |_ /  \\ \n |___|_|   |_____/_/\_\ \__|_|  \__,_|\___|\__/_/\_\\ \n\n          [GNUGPL_v3] IPExtractX.py - {prog_version}\n        Onetrak Digital Forensics Corporation\n"""

    def execute_parser(parser):

        if parser.printio:

            rprint(f'[red bold]{parser.progbanner}[/red bold]')

        if parser.verify_dirpath_isdir is False and parser.verify_dirpath_isfile is False:

            rprint(f'[red bold] ✘  Input Error: {parser.dirpath} Is a Non-Existent File Path\n')

            return parser

        keywords = parser.load_keywords()

        if keywords == None:

            if parser.printio:

                rprint('[red bold] ✘  Error: Wordlist File Not Loaded: {parser_verify_wswordlistfile} = {False}[/red bold]')
                rprint('[blue bold]    Info: os.path.isfile(parser.wswordlistfile) reports {False}[/blue bold]\n')

        if parser.verify_outfile:

            if parser.writeio:

                if parser.printio:

                    rprint(f'[bold yellow] ✘  Warning: Output File "{parser.outfile}" Exists! Clearing File...[/bold yellow]\n')

                os.remove(parser.outfile)

        with rcon_obj.status(f'[yellow bold] Running Parser... ', spinner="bouncingBar") as statusanim:

            try:

                with open(parser.outfile, mode='w') as outfile:

                    if parser.verify_dirpath_isfile:

                        parser.parse_file(parser.dirpath, outfile, keywords)

                    elif parser.verify_dirpath_isdir:

                        for root, dirs, files in os.walk(parser.dirpath):

                            for file in files:

                                statusanim.update(f'[purple bold] Parsing Text File: {parser.activefn}... ', spinner="hamburger")

                                parser.parse_file(os.path.join(root, file), outfile, keywords)

                    statusanim.stop()

                    if parser.writeio:

                        outfile.write('\n--- STATS ---\n')

                        for key, value in parser.statistics.items():

                            outfile.write(f"{key}: {value}\n")

                    if parser.printio:

                        rprint('\n[green bold] ✔  Success: Parser Execution Complete![/green bold]')
                        
                        if parser.writeio == True:
                            
                            rprint(f'[blue bold]    Output File > {parser.outfile}[/blue bold]\n')

                    if parser.printio:

                        if parser.statistics['Errors'] > 0:

                            rprint(f'[red bold] ✘  Preliminary Warning: {parser.statistics["Errors"]} Error(s) Occured During The Parser Execution!!![/red bold]\n')

                    outfile.close()

                parser.parsed_ipaddr = list(set(parser.parsed_ipaddr))
                parser.parsed_hostnames = list(set(parser.parsed_hostnames))
                parser.parsed_emailids = list(set(parser.parsed_emailids))
                parser.fileids_with_pgp = list(set(parser.fileids_with_pgp))

            except Exception as ERRRESP:

                rprint(f'\n[red bold] ✘  Parser Error: {ERRRESP}\n')

            finally:

                return parser

    def parse_file(parser, input_path, outfile, keywords):

        parser.activefn = input_path

        try:

            with open(input_path, "r") as open_file:

                content = open_file.read()

                if parser.appendio:
                    
                    parser.content_list.append(content)

            if parser.detect_ipaddressformat:

                parser.detect_ip_addresses(content, outfile)

            if parser.detect_hostnameformat:

                parser.detect_hostnames(content, outfile)

            if parser.detect_wordsearchformat:

                parser.detect_keywords(content, outfile, keywords)

            if parser.detect_emailformat:

                parser.detect_emails(content, outfile, keywords)

            if parser.detect_prettygoodprivacyheaders and re.search(parser.pgp_regex_pattern, content, re.DOTALL):

                if parser.writeio:

                    outfile.write(f"PGP message found in {input_path}\n")

                parser.statistics["PGP"] += 1

                parser.fileids_with_pgp.append(parser.activefn)

        except Exception as e:

            outfile.write(f"Cannot read file {input_path}. Error: {str(e)}\n")

            parser.statistics["Errors"] += 1

    def detect_ip_addresses(parser, content, outfile):

        for pattern in [(parser.ipv4_regex_pattern, "IPV4"), (parser.ipv6_regex_pattern, "IPV6")]:

            if pattern[1] == "IPV4" or pattern[1] == "IPV6":

                matches = re.finditer(pattern[0], content)

                for match in matches:

                    ip = match.group()

                    try:

                        ipaddress.ip_address(ip)

                        if parser.writeio:

                            outfile.write(f"{pattern[1]} '{ip}' found in {parser.activefn}\n")

                        parser.statistics[pattern[1]] += 1

                        parser.parsed_ipaddr.append(ip)

                    except ValueError:

                        pass

    def detect_hostnames(parser, content, outfile):

        hostnames = re.findall(parser.hostname_regex_pattern, content, re.IGNORECASE)

        for hostname in hostnames:

            if parser.writeio:

                outfile.write(f"Hostname '{hostname}' found in {parser.activefn}\n")

            parser.statistics["Hostnames"] += 1

            parser.parsed_hostnames.append(hostname)

    def detect_keywords(parser, content, outfile, keywords):

        if keywords:

            for keyword in keywords:

                if keyword.lower() in content.lower():

                    if parser.writeio:

                        outfile.write(f"Keyword '{keyword}' found in {parser.activefn}\n")

                    parser.statistics["Keywords"] += 1

    def detect_emails(parser, content, outfile, no_email):

        emails = re.findall(parser.email_regex_pattern, content)

        for email in emails:

            if parser.detect_wordsearchformat == True and email in no_email:

                pass

            else:

                if parser.writeio:

                    outfile.write(f"Email '{email}' found in {parser.activefn}\n")

                parser.statistics["Emails"] += 1

                parser.parsed_emailids.append(email)

    def load_keywords(parser):

        if parser.verify_wswordlistfile:

            with open(parser.wswordlistfile, mode='r') as wlf:

                load_return = [line.strip() for line in wlf.readlines()]

                wlf.close()

                return load_return

        else:

            return None

@cli_main.command(name='X', help=f'HTML Mail Regular Expression Search Pattern Detection Software Version {prog_version}\n\nThis Script Is Also An Importable Class!, try: >>> from IPExtractX import IPExtractX')
def extract_main(content_dir: str, keywords_file: str = f'{os.getcwd()}/wordlists/words1.list', output_file: str = 'output.txt', detect_ipaddr: bool = True, detect_hostname: bool = False, detect_wordsearch: bool = False, detect_emails: bool = False, detect_pgpheader: bool = False):

    parser_fileop = IPExtractX(content_dir, output_file, keywords_file, detect_ipaddr, detect_hostname, detect_wordsearch, detect_emails, detect_pgpheader).execute_parser()

    ### Custom Code Goes Here ###
    # print(parser_fileop.parsed_ipaddr)
    # print(parser_fileop.parsed_hostnames)

    raise SystemExit(1)



if __name__ == '__main__':

    cli_main()