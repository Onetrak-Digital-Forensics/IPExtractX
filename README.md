```___ ____  _____      _                  _  __  __
 |_ _|  _ \| ____|_  _| |_ _ __ __ _  ___| |_\ \/ /
  | || |_) |  _| \ \/ / __| '__/ _` |/ __| __|\  / 
  | ||  __/| |___ >  <| |_| | | (_| | (__| |_ /  \ 
 |___|_|   |_____/_/\_\\__|_|  \__,_|\___|\__/_/\_\.py
```
# MAJOR UPDATES
As of version 1.2.0, IPExtractX is now an importable class! Create the class initializer and try it out!
```
>>> from IPExtractX import IPExtractX as IPX

>>> mycustomobj = IPX(content_dir,
                  output_file,
                  keywords_file,
                  detect_ipaddr,
                  detect_hostname,
                  detect_wordsearch,
                  detect_emails,
                  detect_pgpheader).execute_parser()

>>> if mycustomobj.parsed_ipaddr in customiplistobj:

>>> DO SOMETHING
```
>This update requires a change in the [requirements.txt](requirements.txt) file.<br> If you have not already, After cloning the repository, re-execute <br> the below commands to fix any ImportErrors you may recieve.


# Script Setup

### Import Required Modules Via Python3-PIP
* Execute: ``pip install -r requirements.txt``

### Import Required Modules Via Command
* Execute: ``pip install rich ipaddress regex typer``

# Script Usage
### Pre-Requisites:
* ***UTF-8*** Textual Data, Contained in **Exported Emails**.
* ***Word List File***, Ex. [wordlist.txt](wordlists/words1.list), this file ***can*** be empty.

>The Shebang Snippet For Python Environment Execution Is Set As The File Header. <br>
To Execute, Make Sure You Authorize Execution Permissions With ``chmod +x IPExtractX.py`` <br>
on ***UNIX*** Type Systems


### The Help Command: <br>
Execute: ``./IPExtractX.py --help``

![IPExtractX Help Image](.github/IPExtractX_HelpImage01.png)

### The WordSearch Function
To Run The Scenario With Word Detection, Please Execute With The `--detect-wordsearch` Argument <br>
Then Specify A `List Format` File During Execution with `--keywords-file`, Default is [wordlists/words1.list](wordlists/words1.list)

>Please Note:
>* WordSearch is Non-Case-Sensitive, May Produce False Posatives.
>* WordSearch Detects The Non-Captilized Type Characters, And Will Encode Words This Way When Searching.
>* WordSearch Obtains It's Search Index From a Wordlist File. Please Ensure Your File is UTF-8 & Is Placed in List Format