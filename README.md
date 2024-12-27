This Python script uses the integration feature of Wazuh to send customizable email alerts based on a JSON alert file. It processes incoming alerts, and sends detailed email notifications to recipients. Here's a breakdown of the script:

### Key Features:
1. **Configuration Files**:
   - **Rule File**: A dynamic way to change which fields to include in the template based on the rule's group outside the default fields. 
   - **Recipients File**: Lists email recipients for sending alerts.
   - **SMTP Details**: Configures the SMTP server for sending emails.
   - **Encryption Key**: A decryption key is used for retrieving encrypted credentials for the email account.

2. **Alert Processing**:
   - The script reads a JSON file containing alert data (passed as a command-line argument).
   - It validates that the alert file contains the necessary fields (e.g., `rule`, `agent`, `timestamp`).
   - It parses specific fields based on the alert group and appends them to the email message.

3. **Email Message Generation**:
   - The script customizes the subject and body of the email based on the parsed alert data.
   - The message body is generated in HTML format with specific details like the alert's level, description, timestamp, and any additional fields from the rule file.

4. **Email Sending**:
   - The email is sent via an SMTP server using encrypted user credentials, which are decrypted with a provided key.
   - The email is sent to the recipients listed in the `recipients.txt` file.

5. **Logging**:
   - The script logs its operations and any errors to a log file (`integrations.log`), helping track the process and diagnose issues.

### Purpose:
This script allows administrators to automate email notifications for alerts, ensuring that critical information is communicated efficiently to the right recipients in a structured format. The script is particularly useful in systems that need real-time monitoring and alerting (e.g., server or application monitoring systems). 

### Workflow:
1. Validate configuration files and alert data.
2. Parse the alert content and extract relevant information.
3. Generate an HTML email with dynamic content based on the alert data.
4. Send the email to predefined recipients using an SMTP server.
5. Log the process for debugging and auditing.

### Dependencies:
- **Python 3**: For running the script.
- **Cryptography Library**: For decrypting the user credentials.
- **SMTP Server**: For sending emails.

The script expects command-line arguments, including the location of the alert file and a decryption key, to function correctly. This is done automatically by Wazuh. But incase you want to run it manually you must provide them.
