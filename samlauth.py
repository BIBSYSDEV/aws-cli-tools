#!/usr/bin/env python3

'''A helper script for AWS login with SAML on the terminal
This helper script performs a web flow SAML login against an external identity provider (IdP), and uses the resulting XML Assertion element to assume a role in a named AWS account.
After a successful login, if the profile is not 'default', then add --profile to your commands, i.e.
   aws sts get-caller-identity --profile my-profile-name
'''

import sys
import boto3
import requests
import getpass
import configparser
import base64
import logging
import xml.etree.ElementTree as ET
import re
import json
import pickle
import argparse
import os
import stat
from botocore.client import Config
from datetime import datetime
from dateutil import tz
from bs4 import BeautifulSoup
from os.path import expanduser
from urllib.parse import urlparse, urlunparse

__version__ = '0.4'

############################
# Prerequisites
#
# pip3 install boto3
# pip3 install bs4
# pip3 install ConfigParser
#
############################

############################
# TODO
#   Implement optional arguments:
#     UseExistingSTSToken
#
#       First, check if token valid: get_caller_identity()
#          load credentials from named profile
#            test: 
#              get_caller_identity with creds
#
############################


##########################################################################
# Variables

# output format: The AWS CLI output format that will be configured in the
# saml profile (affects subsequent CLI calls)
outputformat = 'json'

# awsconfigfile: The file where this script will store the temp
# credentials under the saml profile
awsconfigfile = '/.aws/credentials'

# cookiejarfile: The file where any cached cookies are stored
cookiejarfile = '/.aws/feide-cookies'

# SSL certificate verification: Whether or not strict certificate
# verification is done, False should never be used, always verify
sslverification = True

# idpentryurl: The initial url that starts the authentication process.
idpentrybaseurl = 'https://idp.feide.no/simplesaml/module.php/feide/preselectOrg.php?HomeOrg=unit.no&ReturnTo=https://idp.bibsys.no/simplesaml/saml2/idp/SSOService.php?spentityid=urn:amazon:webservices:'

# Base Url authorized to receive credentials 
# Used to prevend credentials being submitted to the wrong target
idpbaseurl = 'https://idp.feide.no/'

# This script uses an intermediate IdP.
# The IdP above (idpbaseurl) is the main identity provider.
# The response from that IdP is routed through an intermediate IdP which builds the SAMLResponse required by AWS.
# The resulting SAML Assertion is then re-signed by the intermediate IdP before being submitted to AWS.
# This results in the following trust chain: Main Idp (Feide) - Intermediate IdP (Unit) - AWS 
intermediate_idpbaseurl = 'https://idp.bibsys.no'

mfa_registration_message = 'Note: If you haven\'t registered a MFA device already, please perform the registration step in a web browser (https://aws.unit.no), and then re-run this script'

# Do not modify this unless Amazon have changed their SAML endpoint
awssamlsigninurl = 'https://signin.aws.amazon.com/saml'

# Default session timeout 8hr
# Feide session is max 8hrs (=28800s)
# We can request between 15min and 8hrs

##########################################################################

home = expanduser("~")

cookiejarpath = home + cookiejarfile

filename = home + awsconfigfile

##########################################################################

def saml_login(*, 
               region, 
               accountidentity, 
               profilename, 
               assume_role, 
               duration_seconds=28800, 
               force_login=False, 
               use_existing_token=False, 
               no_profile_overwrite=False, 
               no_cookie_store=False, 
               debug=False, 
               debug_boto3=False):

    if debug_boto3:
        # Enable low level debugging in the boto3 library
        logging.basicConfig(level=logging.DEBUG)


    # Initiate session handler
    session = requests.Session()

    # Load cookies (if present)
    if not force_login:
        try:
            with open(cookiejarpath, 'rb') as f:
                session.cookies.update(pickle.load(f))
        except OSError as e:
            if debug:
                print('No cached cookies found')
                print(e.errno)

    # Programmatically get the SAML assertion
    # Opens the initial IdP url and follows all of the HTTP302 redirects, and
    # gets the resulting login page
    # accountidentity -> spendityid

    idpentryurl = idpentrybaseurl + accountidentity

    response = session.get(idpentryurl, verify=sslverification)

    if debug:
        print('response.url 1: '+response.url)

    # Capture the idpauthformsubmiturl, which is the final url after all the 302s
    idpauthformsubmiturl = response.url


    if not response.url.startswith(intermediate_idpbaseurl):

        # Get the federated credentials from the user
        print("Username: ", end = '')
        username = input()
        password = getpass.getpass()
        print('')

        # Parse the response and extract all the necessary values
        # in order to build a dictionary of all of the form values the IdP expects
        page_text = response.text.encode('utf-8').decode('ascii', 'ignore')
        formsoup = BeautifulSoup(page_text, features="html.parser")
        payload = {}

        for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name','')
            value = inputtag.get('value','')
            if "feidename" in name.lower():
                payload[name] = username
            elif "password" in name.lower():
                payload[name] = password
            else:
                #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
                payload[name] = value

        # Debug the parameter payload if needed
        # Use with caution since this will print sensitive output to the screen
        if debug:
            print(payload)

        # Some IdPs don't explicitly set a form action, but if one is set we should
        # build the idpauthformsubmiturl by combining the scheme and hostname 
        # from the entry url with the form action target
        # If the action tag doesn't exist, we just stick with the 
        # idpauthformsubmiturl above
        for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
            action = inputtag.get('action')
            if action:
                action = action.strip()

                if action.startswith('https://'):
                    idpauthformsubmiturl = action
                else:
                    parsedurl = urlparse(idpauthformsubmiturl)
                    idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

        # Assert target url before submitting credentials
        if not idpauthformsubmiturl.startswith(idpbaseurl):
            print('Assertion failed: attempted to submit credentials to unauthorized host: '+idpauthformsubmiturl)
            sys.exit(0)

        # Performs the submission of the IdP login form with the above post data
        response = session.post(
            idpauthformsubmiturl, data=payload, verify=sslverification)

        if debug:
            print('response.url 2: '+response.url)

        ###################################################################

        # Overwrite and delete the credential variables, just for safety
        username = '##############################################'
        password = '##############################################'
        del username
        del password


        ###################################################################
        #
        # Now we have the response from Feide. Submit it to our intermediary IdP
        #
        ###################################################################

        page_text = response.text.encode('utf-8').decode('ascii', 'ignore')
        formsoup = BeautifulSoup(page_text, features="html.parser")
        payload = {}

        for inputtag in formsoup.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name','')
            value = inputtag.get('value','')
            # TODO can duplicate 'name's become a problem here? (i.e. input=list, output=dict)
            payload[name] = value

        # Debug the parameter payload if needed
        # Use with caution since this will print sensitive output to the screen
        if debug:
            print(payload)

        # Capture the idpauthformsubmiturl, which is the final url after all the 302s
        idpauthformsubmiturl = response.url

        # Some IdPs don't explicitly set a form action, but if one is set we should
        # build the idpauthformsubmiturl by combining the scheme and hostname
        # from the entry url with the form action target
        # If the action tag doesn't exist, we just stick with the
        # idpauthformsubmiturl above
        for inputtag in formsoup.find_all(re.compile('(FORM|form)')):
            action = inputtag.get('action')
            if action:
                action = action.strip()

                if action.startswith('https://'):
                    idpauthformsubmiturl = action
                else:
                    parsedurl = urlparse(idpauthformsubmiturl)
                    idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

        # Performs the submission of the IdP login form with the above post data
        response = session.post(
            idpauthformsubmiturl, data=payload, verify=sslverification)

        if debug:
            print('response.url 3: '+response.url)

    if debug:
        print(session.cookies)

    if not no_cookie_store:
        with open(cookiejarpath, 'wb') as f:
            pickle.dump(session.cookies, f)
        set_read_write_user_only_permissions(cookiejarpath, debug)


    ###########################################################################
    #
    # Check if we have the SAML Assertion in response, or if MFA is required
    #
    #
    ###########################################################################


    # Debug the response if needed
    if debug:
        print(response.text)

    response_text = response.text.encode('utf-8').decode('ascii', 'ignore')
    # Decode the response and check for presence of SAML assertion or MFA code input
    soup = BeautifulSoup(response_text, features="html.parser")
    assertion = ''

    saml_response_found = False
    mfa_required = False

    # Look for the SAMLResponse attribute, MFA code input, or indication that MFA registration is required
    for inputtag in soup.find_all(re.compile('(INPUT|input)')):
        if(inputtag.get('name') == 'SAMLResponse'):
            saml_response_found = True
            assertion = inputtag.get('value')
        elif(inputtag.get('name') == 'code'):
            mfa_required = True

    if response.url.startswith(intermediate_idpbaseurl) and response.status_code == 500 and re.search(r'Ingen metadata funnet', response_text):
        print('Login failure: "{0}" is not a valid account identity'.format(accountidentity))
        sys.exit(0)

    if not saml_response_found and not mfa_required:
        print('Assertion failure: Neither SAML assertion nor MFA code prompt in response..')
        sys.exit(0)

    while not saml_response_found and mfa_required:
     
        # Get the federated credentials from the user
        print(mfa_registration_message) 
        print("MFA Code: ", end = '')
        try:
            mfa_code = input()
        except KeyboardInterrupt:
            print('Aborting')
            sys.exit(0)

        print('')

        payload = {}

        for inputtag in soup.find_all(re.compile('(INPUT|input)')):
            name = inputtag.get('name','')
            value = inputtag.get('value','')
            if "code" in name.lower():
                payload[name] = mfa_code
            else:
                #Simply populate the parameter with the existing value (picks up hidden fields in the login form)
                payload[name] = value

        # Debug the parameter payload if needed
        # Use with caution since this will print sensitive output to the screen
        if debug:
            print(payload)

        idpauthformsubmiturl = intermediate_idpbaseurl

        # Some IdPs don't explicitly set a form action, but if one is set we should
        # build the idpauthformsubmiturl by combining the scheme and hostname
        # from the entry url with the form action target
        # If the action tag doesn't exist, we just stick with the
        # idpauthformsubmiturl above
        for inputtag in soup.find_all(re.compile('(FORM|form)')):
            action = inputtag.get('action')
            if action:
                action = action.strip()

                if action.startswith('https://'):
                    idpauthformsubmiturl = action
                else:
                    parsedurl = urlparse(idpauthformsubmiturl)
                    idpauthformsubmiturl = parsedurl.scheme + "://" + parsedurl.netloc + action

        # Assert target url before submitting credentials
        if not idpauthformsubmiturl.startswith(intermediate_idpbaseurl):
            print('Assertion failed: attempted to submit MFA code to unauthorized host: '+idpauthformsubmiturl)
            sys.exit(0)

        # Performs the submission of the IdP login form with the above post data
        response = session.post(
            idpauthformsubmiturl, data=payload, verify=sslverification)

        if debug:
            print('response.url 4: '+response.url)

        # Debug the response if needed
        if debug:
            print(response.text)

        response_text = response.text.encode('utf-8').decode('ascii', 'ignore')
        # Decode the response and extract the SAML assertion
        soup = BeautifulSoup(response_text, features="html.parser")
        assertion = ''

        # Look for the SAMLResponse attribute of the input tag (determined by
        # analyzing the debug print lines above)
        for inputtag in soup.find_all('input'):
            if(inputtag.get('name') == 'SAMLResponse'):
                assertion = inputtag.get('value')
                saml_response_found = True
            elif(inputtag.get('name') == 'code'):
                print('Incorrect MFA code. Please try again..')
                mfa_required = True

    ############################################################################

    if (assertion == ''):
        print('Response did not contain a valid SAML assertion')
        sys.exit(0)


    ############################################################################
    #
    # Now we have the Assertion from our intermediate IdP
    # Parse the response, get the XML, find attributes and send request to STS
    #
    ############################################################################

    assertion_str = base64.b64decode(assertion)

    if debug:
        print(assertion_str)

    # Parse the returned assertion and extract the authorized roles
    awsroles = []
    root = ET.fromstring(assertion_str)
    for saml2attribute in root.iter('{urn:oasis:names:tc:SAML:2.0:assertion}Attribute'):
        if (saml2attribute.get('Name') == 'https://aws.amazon.com/SAML/Attributes/Role'):
            for saml2attributevalue in saml2attribute.iter('{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue'):
                awsroles.append(saml2attributevalue.text)

    # Note the format of the attribute value should be role_arn,principal_arn
    # but lots of blogs list it as principal_arn,role_arn so let's reverse
    # them if needed
    for awsrole in awsroles:
        chunks = awsrole.split(',')
        if 'saml-provider' in chunks[0]:
            newawsrole = chunks[1] + ',' + chunks[0]
            index = awsroles.index(awsrole)
            awsroles.insert(index, newawsrole)
            awsroles.remove(awsrole)

    awsrolenames = []
    for awsrole in awsroles:
        if debug:
            print("Role attr: "+awsrole)
        chunks = awsrole.split(',')
        if re.search('^arn:aws:iam::[0-9]{12}:role\/[a-zA-Z_+=,\.@-]+$', chunks[0]):
            awsrolename = chunks[0].rsplit('/')[1]
            index = awsroles.index(awsrole)
            awsrolenames.insert(index, awsrolename)
            print("Available role: "+awsrolename)
        else:
            print('WARNING: Found possible erroneous role arn: '+chunks[0])

    # If I have more than one role, ask the user which one they want,
    # otherwise just proceed
    print("")

    if assume_role is not None:
        if not assume_role in awsrolenames:
            print('You do not have access the selected role ({0}), or a role with that name does not exist. Please try with a different role name'.format(assume_role))
            sys.exit(0)
        selectedroleindex = awsrolenames.index(assume_role)
        role_arn = awsroles[int(selectedroleindex)].split(',')[0]
        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]

    elif len(awsroles) > 1:
        i = 0
        print("Please choose the role you would like to assume:")
        for awsrole in awsroles:
            print('[', i, ']: ', awsrole.split(',')[0])
            i += 1
        print("Selection: ", end= '')
        selectedroleindex = input()
        print('')

        # Basic sanity check of input
        if int(selectedroleindex) > (len(awsroles) - 1):
            print('You selected an invalid role index, please try again')
            sys.exit(0)

        role_arn = awsroles[int(selectedroleindex)].split(',')[0]
        principal_arn = awsroles[int(selectedroleindex)].split(',')[1]
    else:
        role_arn = awsroles[0].split(',')[0]
        principal_arn = awsroles[0].split(',')[1]

    # Use the assertion to get an AWS STS token using Assume Role with SAML
    conn = boto3.client('sts',
               region_name=region,
               endpoint_url='https://sts.{0}.amazonaws.com'.format(region),
               config=Config(user_agent_extra='samlauth-v'+__version__)
           )
    token = conn.assume_role_with_saml(RoleArn=role_arn, PrincipalArn=principal_arn, SAMLAssertion=assertion, DurationSeconds=duration_seconds)

    if debug:
        print(json.dumps(token, indent=4, default=str))

    # Get localized expiration time
    from_zone = tz.tzutc()
    to_zone = tz.tzlocal()

    token_expiration = token.get('Credentials', {}).get('Expiration')

    # Tell the datetime object that it's in UTC time zone since
    # datetime objects are 'naive' by default
    utc = token_expiration.replace(tzinfo=from_zone)

    # Convert time zone
    localizedexpirationtime = utc.astimezone(to_zone)

    # Write the AWS STS token into the AWS credential file

    # Read in the existing config file
    config = configparser.RawConfigParser()
    config.read(filename)

    # Put the credentials into a specific profile section 
    # If profile name is set, use that instead of clobbering the default credentials
    if not config.has_section(profilename):
        config.add_section(profilename)
    elif no_profile_overwrite:
        print('The profile \'{0}\' already exists, and you specified --no-profile-overwrite. Please try another profile name'.format(profilename))
        sys.exit(0)

    config.set(profilename, 'output', outputformat)
    config.set(profilename, 'region', region)
    config.set(profilename, 'aws_access_key_id', token['Credentials']['AccessKeyId'])
    config.set(profilename, 'aws_secret_access_key', token['Credentials']['SecretAccessKey'])
    config.set(profilename, 'aws_session_token', token['Credentials']['SessionToken'])
    config.set(profilename, '## expires', localizedexpirationtime)

    # Write the updated config file
    with open(filename, 'w+') as configfile:
        config.write(configfile)

    # Give the user some basic info as to what has just happened
    print('\n----------------------------------------------------------------')
    print('Your new access key has been stored in the AWS configuration file {0} under the \'{1}\' profile.'.format(filename, profilename))
    print('Note that it will expire at {0} ({1} UTC).'.format(localizedexpirationtime,token_expiration))
    print('After this time, you may safely rerun this script to refresh your access key.')
    if profilename != 'default':
        print('To use this credential, call the AWS CLI with the --profile option (e.g. aws --profile {0} ec2 describe-instances).'.format(profilename))
    print('----------------------------------------------------------------\n')

    sts_client = boto3.client('sts', 
                     region_name=region,
                     endpoint_url='https://sts.{0}.amazonaws.com'.format(region),
                     aws_access_key_id=token['Credentials']['AccessKeyId'],
                     aws_secret_access_key=token['Credentials']['SecretAccessKey'],
                     aws_session_token=token['Credentials']['SessionToken'])
    caller_identity = sts_client.get_caller_identity()

    #caller_identity_dict = {k: v for k, v in caller_identity.items() if k != 'ResponseMetadata'}
    #print(json.dumps(caller_identity_dict, indent=4, default=str))

    iam_client = boto3.client('iam',
                     aws_access_key_id=token['Credentials']['AccessKeyId'],
                     aws_secret_access_key=token['Credentials']['SecretAccessKey'],
                     aws_session_token=token['Credentials']['SessionToken'])
    account_aliases = iam_client.list_account_aliases()

    alias = ''
    if account_aliases['AccountAliases']:
        alias = " (" + account_aliases['AccountAliases'][0] + ")"

    print("Account: "+caller_identity['Account'] + alias)
    print("UserId: "+caller_identity['UserId'])
    print("Arn: "+caller_identity['Arn'])


def set_read_write_user_only_permissions(path, debug=False):
    """Set user read/write only for this file. 
    Params:
        path:  The path whose permissions to alter.
    """
    REQUESTED_PERMISSIONS = stat.S_IWUSR | stat.S_IRUSR

    current_permissions = stat.S_IMODE(os.lstat(path).st_mode)
    if debug:
        print("Current file permissions: "+oct(current_permissions))

    if current_permissions != REQUESTED_PERMISSIONS:
        os.chmod(path, REQUESTED_PERMISSIONS)

    if debug:
        new_permissions = stat.S_IMODE(os.lstat(path).st_mode)
        print("New file permissions: "+oct(new_permissions))


def main(arguments):

    usage = (
        '\n'
        'Basic:                  samlauth.py\n'
        'Specify AWS account:    samlauth.py -a EntitydataDevelopment\n'
        'Specify Target profile: samlauth.py -a EntitydataDevelopment -p entitydata-dev\n'
        'Force new IdP login:    samlauth.py -f'
    )

    parser = argparse.ArgumentParser(
        description='A SAML Login helper that performs a (web) login and uses the resulting SAML Assertion to fetch temporary credentials from AWS STS. Web cookies are cached by default, and are automatically reused on subsequent invocations of this script',
        usage=usage,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    standard = parser.add_argument_group('Standard')
    advanced = parser.add_argument_group('Advanced / Debugging')

    standard.add_argument('-a', '--account-identity',
                         metavar='IDENTITY', 
                         default='TEST', 
                         help='The AWS account identity (A local alias stored in the IdP)')
    standard.add_argument('-p', '--profile',
                         metavar='PROFILE', 
                         default='default',
                         help='The profile to create in ~/.aws/credentials. If the profile section already exists, it will be replaced. Set this to \'default\' to avoid having to use --profilename [name] for every command')
    standard.add_argument('-r', '--role',
                         default=None,
                         help='The name of the IAM role to assume. Only relevant if you can assume more than one role, and you would like to auto-select the role')
    standard.add_argument('-f', '--force-login', 
                         action='store_true',
                         default=False, 
                         help='Force full login? (Ignores cached cookies). Use this if you want renew the timeout')
    advanced.add_argument('-n', '--no-cookie-store',
                         action='store_true',
                         default=False,
                         help='Do not save cookies for this session. Any existing cookies are left untouched')
    advanced.add_argument('--no-profile-overwrite',
                         action='store_true',
                         default=False,
                         help='Do not overwrite the profile if it already exists')
    advanced.add_argument('-u', '--use-existing-token',
                         action='store_true',
                         default=False, 
                         help='Do not create a new STS token if the existing token is valid')
    advanced.add_argument('--region', 
                         default='eu-west-1', 
                         help='The default \'region\' for the created profile. Also used for STS API calls (relevant only for latency)')
    advanced.add_argument('-d', '--duration-seconds',
                         metavar='SECONDS',
                         type=int,
                         default=28800,
                         help='Token duration in seconds. Use this if you want to limit token validity')
    advanced.add_argument('--debug',
                         action='store_true',
                         default=False,
                         help='Print debug messages (this script)')
    advanced.add_argument('--debug-boto3',
                         action='store_true',
                         default=False,
                         help='Enable verbose logging (boto3)')

    args = parser.parse_args(arguments)

    if args.debug:
        print("Args: " + str(args))

    if args.duration_seconds < 900 or args.duration_seconds > 28800:
        parser.error("--duration-seconds must be between 900 and 28800")

    if args.use_existing_token:
        print("--use-existing-token not implemented (yet)")
        sys.exit(0)

    print("Attempting logon to: " + args.account_identity)
    saml_login(region=args.region, 
               profilename=args.profile, 
               accountidentity=args.account_identity, 
               assume_role=args.role,
               duration_seconds=args.duration_seconds, 
               force_login=args.force_login,
               no_profile_overwrite=args.no_profile_overwrite,
               use_existing_token=args.use_existing_token,
               no_cookie_store=args.no_cookie_store,
               debug=args.debug,
               debug_boto3=args.debug_boto3)

if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))

