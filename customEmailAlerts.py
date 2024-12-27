#!/usr/bin/python3
##### customEmailAlerts
# Author: Juan C. Tello
# Modifier: Leonit Shabani
# Version: 2024.12.27
# Description:
# 
# This integration allows the user to send fully customizable email alerts
#  this is a simple implementation for which the message is customized in
#  the generate_msg() function. A full html body is accepted if necessary.
#
# Configuration example:
#
#  <integration>
#      <name>customEmailAlerts.py</name>
#      <hook_url>decryptionKey</hook_url>
#      <level>15</level>
#      <alert_format>json</alert_format>
#  </integration>
##########################################################################################################################

import json
import sys
import time
import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from cryptography.fernet import Fernet
from cryptography.fernet import InvalidToken



#################################################### Global Variables ####################################################

######### General

debugEnabled = True
pwd = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
jsonAlert = {}
now = time.strftime("%a %b %d %H:%M:%S %Z %Y")

# Set paths
logPath = '{0}/logs/'.format(pwd)
logFile = '{0}/integrations.log'.format(logPath)

######### Email Related 

emailFrom = "alert@yourMail.com"
configFolder = '{0}/integration/EmailScriptConfigFiles'.format(pwd)
ruleFilePath = '{0}/rules.json'.format(configFolder)
recipientsFilePath = '{0}/recipients.txt'.format(configFolder)

smtp = 'yourSMTP'
port = 0

################################################### General Functions ####################################################

# General Function to keep logs of what is happening
def debug(msg):
    """
    Function to generate debug logs
    """
    if debugEnabled:
        msg = "{0}: {1}\n".format(now, msg)
        print(msg)
        f = open(logFile, "a")
        f.write(msg)
        f.close()

# Function to test path errors that might occur.
def checkPathErrors():
    # Test Case 1
    logPathExists = True
    if not os.path.exists(logPath):
        logPathExists = False
        try:
            os.makedirs(logPath)
        except Exception as e:
            print(f"# Error: {logPath} Log Folder doesn't exist. While trying to create it the script ran into the following error: {e}")

    # Test Case 2
    if not os.path.exists(logFile):
        try:
            os.makedirs(logFile)
            if not logPathExists:
                debug(f"Warning: Log Folder was missing. Created Log Folder at {logPath}.")
            debug(f"Warning: Log File was missing. Created Log File at {logFile}.")
        except Exception as e:
            print(f"# Error: {logPath} Log File doesn't exist. While trying to create it the script ran into the following error: {e}")
    
    # Test Case 3
    if not os.path.exists(configFolder):
        debug(f"# Error: Config Folder at {configFolder} is missing. Terminating process...")
        sys.exit(1)

    # Test Case 4
    if not os.path.exists(recipientsFilePath):
        debug(f"# Error: Recipients File at {recipientsFilePath} is missing. Terminating process...")
        sys.exit(1)

    # Test Case 5
    if not os.path.exists(ruleFilePath):
        debug(f"Error: Rules File at {ruleFilePath} is missing. Terminating process...")
        sys.exit(1)
    
    if os.path.getsize(ruleFilePath) == 0:
        debug(f"Error: Rules File exists but it is empty. Terminating process...")
        sys.exit(1)

    with open(ruleFilePath) as f:
        data = json.load(f)
        ruleFileKeys = data.keys()
        if len(ruleFileKeys) != 1 or "rules" not in ruleFileKeys:
            debug(f"Error: Bad Rules File Format. 'Rules' section not found. Terminating process...")
            sys.exit(1)
        if not data['rules'].keys():
            debug(f"Error: Bad Rules File Format. 'Rules' section can't be empty. Terminating process...")
            sys.exit(1)
    
    debug("# Success: No Path Errors found. ")

def checkGeneralErrors(args):
    checkPathErrors()
    if len(args) < 4:
        debug("# Error: Bad arguments (< 4). Terminating process...")
        sys.exit(1)

    if not os.path.exists(args[1]):
        debug("# Error: Alert File not found (arg[1]). Terminating process...")
        sys.exit(1)

    if os.path.getsize(args[1]) == 0:
        debug("# Error: Alert file exists but is empty. Terminating process...")
        sys.exit(1)
    
    # Load alert. Parse JSON object.
    with open(args[1]) as alert_file:
        try:
            # Trying to read the alert content into the global jsonAlert varibale.
            global jsonAlert
            jsonAlert = json.load(alert_file)
        except Exception as e:
            debug(f"# Error: While trying to dump the Alert json content into a dictionary the script ran into the following error: {e}")
            sys.exit(1)

    if not isinstance(args[3], str):
        debug("# Error: Key must be a string (arg[3]). Terminating process...")
        sys.exit(1)

    alertKeys = jsonAlert.keys()
    if "rule" not in alertKeys:
        debug("# Error: Alert content doesn't contain the Rule section, invalid log. Terminating process...")
        sys.exit(1)
    
    if "agent" not in alertKeys:
        debug("# Error: Alert content doesn't contain the Agent section, invalid log. Terminating process...")
        sys.exit(1)

    if "timestamp" not in alertKeys:
        debug("# Error: Alert content doesn't contain the timestamp, invalid log. Terminating process...")
        sys.exit(1)

    rulesKeys = jsonAlert['rule'].keys()
    if "groups" not in rulesKeys:
        debug("# Error: Alert content doesn't contain the groups inside the Rule section, invalid log. Terminating process...")
        sys.exit(1)
    
    if "description" not in rulesKeys:
        debug("# Error: Alert content doesn't contain the description inside the Rule section, invalid log. Terminating process...")
        sys.exit(1)

    if "level" not in rulesKeys:
        debug("# Error: Alert content doesn't contain the level inside the Rule section, invalid log. Terminating process...")
        sys.exit(1)

    if "id" not in rulesKeys:
        debug("# Error: Alert content doesn't contain the ID inside the Rule section, invalid log. Terminating process...")
        sys.exit(1)
    
    agentKeys = jsonAlert['agent'].keys()
    if "name" not in agentKeys:
        debug("# Error: Alert content doesn't contain the Agent Name inside the Agent section, invalid log. Terminating process...")
        sys.exit(1)

    debug("# Success: No Argument errors found.")


################################################# Mail Related Functions #################################################

# Function to get recipients in a dynamic way
def SetUpRecipients():
    with open(recipientsFilePath) as recipientsFile:
        lines = recipientsFile.readlines()  
        if(len(lines) != 1):
            debug(f'# Error: Recipients File should contain only 1 line with recipient emails being seperated with a comma. Right now it contains len(lines) lines.')
            sys.exit(1)
        recipients = lines[0].split(',')
        debug(f'# Recipients List: {recipients}')
        return recipients

# Function to create a html row to add to the overall template
def createHTMLRow(field:str, value:str):
    toBeReturned = f'''
                        <tr style="height: 32px;">
                            <td style="width: 25%; text-align: center; border-right: 1px solid #ccc; padding: 8px;">{field}</td>
                            <td style="width: 75%; text-align: left; padding: 8px;">{value}</td>
                        </tr>
                    '''
    return toBeReturned

# Function that returns the HTML Template to send in a email
def createHTML(level, timestamp, id, description, extraRows):
    html = f'''Your Html Template - I recommend using pure HTML with inline CSS because of the restrictions of email clients.
    '''
    return html

# Function to parse specific fields based on what group the log belongs to
def getSpecificFields(alert:dict):
    extraRows = ''
    with open(ruleFilePath) as f:
        data = json.load(f)
        rule_names = data['rules'].keys()
        for name in rule_names:
            if name in alert['rule']['groups']:
                debug(f'# Log belongs to {name} group. Parsing extra fields...')
                for field in data['rules'][name]:
                    valueList = data['rules'][name][field].split(',')
                    debug(f'# Value List: {valueList}. Starting loop.')
                    try:
                        actualValue = alert[valueList[0]]
                        for i in range(1, len(valueList)):
                            actualValue = actualValue[valueList[i]]
                        extraRows += createHTMLRow(field, actualValue)
                        debug(f'# Extra Rows retrieved: {field} - {actualValue}')
                    except:
                        debug(f'# Failed to retrieve the "{field}" field despite the log belonging to the {name} group.')
    return extraRows

# Function that will generate the email content
def generate_msg(alert:dict):
    """
    Function that will provide the custom subject and body for the email.
    It takes as input a dictionary object generated from the json alert
    """
    description = alert['rule']['description']
    level = alert['rule']['level']
    id = alert['rule']['id']
    agentname = alert['agent']['name']
    t = time.strptime(alert['timestamp'].split('.')[0],'%Y-%m-%dT%H:%M:%S')
    timestamp = time.strftime('%c',t)

    otherRows = getSpecificFields(alert)

    clusterRow = ''
    try:
        clusterName = alert['cluster']['name']
        clusterNode =  alert['cluster']['node']
        value = f'Name: {clusterName} | Node: {clusterNode}'
        clusterRow = createHTMLRow("Cluster", value)
    except:
        clusterRow = ''

    extraRows = otherRows + clusterRow

    subject = 'Hebbx Alert: {0}, {1}'.format(description, agentname)

    message = createHTML(level, timestamp, id, description, extraRows)

    return subject, message

# Function to send the mail
def send_email(subject:str,body:str,key:str):
    """
    Function to send email using an unautheticated email server.
    """
    msg = MIMEMultipart(
        "alternative", None, [MIMEText(body, 'html')])

    msg['Subject'] = subject
    msg['From'] = emailFrom

    user = b'your encrypted User'
    passwd = b'your encrypted Password'

    try:
        fernet = Fernet(key)
    except InvalidToken:
        debug("# Error: Invalid key format or value. Failed to initialize Fernet. Terminating process...")
        sys.exit(1)

    try:
        user = fernet.decrypt(user).decode()
        passwd = fernet.decrypt(passwd).decode()
    except InvalidToken:
        debug("# Error: Decryption failed. Key may not match the encrypted data. Terminating process...")
        sys.exit(1)

    recipients = SetUpRecipients()

    try:
        with smtplib.SMTP(smtp, port) as server:
            server.login(user, passwd)
            for receiver in recipients:
                msg['To'] = receiver
                server.sendmail(emailFrom, receiver, msg.as_string())
                debug(f"# Mail sent to {receiver}!")
    except Exception as e:
        debug("# Error: Failed to send mail to {} with the following error:".format(receiver))
        debug("# {}".format(e))

# Main Function
def main(args):
    """
    Main function. This will call the functions to prepare the message and send the email 
    """
    debug("# Starting")

    # Read args
    alertFileLocation = args[1]
    key = args[3]

    debug("# File location")
    debug(alertFileLocation)

    debug("# Processing alert")
    # debug(jsonAlert)

    debug("# Generating message")
    subject, msg = generate_msg(jsonAlert)

    debug("# Sending message")
    send_email(subject, msg, key)

if __name__ == "__main__":
    try:
        # Check for general Errors before executing
        checkGeneralErrors(sys.argv)
        
        # Main function
        main(sys.argv)

    except Exception as e:
        debug(str(e))
        raise
