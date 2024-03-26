#!/env/bin/python3.9
import subprocess
import ipaddress
import pandas as pd
import requests
import json
import logging
from pythonjsonlogger import jsonlogger
from datetime import datetime
import time
import yaml


class CustomJsonFormatter(jsonlogger.JsonFormatter):
    def add_fields(self, log_record, record, message_dict):
        super(CustomJsonFormatter, self).add_fields(log_record, record,
                                                    message_dict)


class ddosAlert:
    def __init__(self) -> None:
        with open('notify.yml') as file:
            self.configs = yaml.safe_load(file)
        self.slack_url = self.configs['ddos-configs']['slack_info']['slack_url']
        print(self.slack_url)
        self.today = datetime.today().strftime('%m%d%y')
        self.logger = logging.getLogger()
        self.logger.setLevel(logging.INFO)
        self.fileHandler = logging.FileHandler(f"ddos-logs/slackNotify/ddosalert{self.today}.json")
        self.formatter = CustomJsonFormatter()
        self.fileHandler.setFormatter(self.formatter)
        self.logger.addHandler(self.fileHandler)
        self.ddosLogs = {}
        self.siteName_last_seen = {}
        self.subnets = []
        self.load_subnets('prefix.csv')

    def load_subnets(self, csv_file):
        df = pd.read_csv(csv_file).dropna()
        for _, row in df.iterrows():
            subnet = ipaddress.ip_network(row["Prefix"], strict=False)
            self.subnets.append((subnet, row["Site"]))

    def ipLookup(self, address):
        try:
            ip = ipaddress.ip_address(address)
            for subnet, siteName in self.subnets:
                if ip in subnet:
                    print(f"IP address {address} is in prefix {subnet}")
                    return str(subnet), siteName
            sitePrefix = "Cannot find"
            siteName = "Cannot Find"
        except ValueError:
            print("Invalid IP address")
            log_record = {'message': 'Active DDOS Attack - Invalid IP', 'Invalid IP': address}
            self.logger.info(log_record)
            sitePrefix = None
            siteName = None
        return sitePrefix, siteName

    def liveAlert(self, filename):
        process = subprocess.Popen(['tail', '-f', filename],
                                   stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE
                                   )
        while True:
            line = process.stdout.readline()
            if not line:
                break
            yield line

    def slackNotifyDDoS(self, *args, **kwargs):
        payload = {
            "username": "Sample DDOS",
            "text": "Active DDOS Attack",
            "blocks": [
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Server:* {subprocess.check_output('whoami').strip().decode()}\n *Status*: Live Analysis :white_check_mark:",
                    },
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": ("*Raw Logs:* \n```#target start end pkts " +
                                 f"Gbps Bps signatures votes\n{kwargs.get('line')}```")
                    },
                },
                {
                    "type": "section",
                    "fields": [
                        {
                            "type": "mrkdwn",
                            "text": f"*Event Start*\n {kwargs.get('startTime')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Event End:*\n {kwargs.get('endTime')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Target IP:*\n {kwargs.get('ip')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Target Prefix:*\n {kwargs.get('sitePrefix')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Site Name:*\n {kwargs.get('siteName')}"
                        },
                        {
                            "type": "mrkdwn",
                            "text": f"*Votes:*\n {kwargs.get('votes')}"
                        },
                    ],
                },
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"*Signature*\n {kwargs.get('signature')}"
                    },
                },
                {
                    "type": "divider"
                },
            ],
        }
        headers = {"Content-type": "application/json"}
        try:
            response = requests.request("POST", self.slack_url,
                                        headers=headers,
                                        data=json.dumps(payload))
            print(response)
        except ValueError:
            print(f"Request to slack returned an error {response.status_code},\
                the response is:\n{response.text}")

    def displayAlert(self):
        lineHeader = True
        for line in self.liveAlert(f'ddos-logs/ddosAlert/ddosalert{self.today}.log'):
            if lineHeader:
                lineHeader = False
                continue
            ddosInfo = line.decode().split(" ")
            startTime = datetime.fromtimestamp(int(ddosInfo[1])).strftime(
                                                        "%m-%d-%y | %I:%M %p")
            endTime = datetime.fromtimestamp(int(ddosInfo[2])).strftime(
                                                        "%m-%d-%y | %I:%M %p")
            ip = ddosInfo[0]
            gbps = float(ddosInfo[4])
            votes = float(ddosInfo[-1])
            sitePrefix, siteName = self.ipLookup(ip)
            signatureTotal = ""
            signatureEmail = ""
            signatureParse = ddosInfo[6:len(ddosInfo) - 2]
            for signature in ' '.join(signatureParse).split(';'):
                signatureTotal += signature.strip() + '\n'
                signatureEmail += signature.strip() + '<br>'
            log_record = {'message': f'Active DDOS Attack - {line}'}
            log_record['Time Start'] = startTime
            log_record['Time End'] = endTime
            log_record['Gbps'] = gbps
            log_record['Votes'] = votes
            log_record['Signature'] = signatureEmail
            log_record['sitePrefix'] = sitePrefix
            log_record['siteName'] = siteName
            log_record['targetip'] = ip
            self.logger.info(log_record)
            current_time = time.time()
            # If the siteName is in the dictionary but it's been more than 15 minutes since the last alert
            if siteName in self.siteName_last_seen and (
                    current_time - self.siteName_last_seen[
                        siteName]['timestamp']) > 900:
                # Reset the timestamp and count for the siteName
                self.siteName_last_seen[siteName] = {
                    'timestamp': current_time, 'count': 1
                }
                self.slackNotifyDDoS(ip=ip, startTime=startTime,
                                     endTime=endTime, gbps=gbps,
                                     votes=votes, signature=signatureTotal,
                                     line=line, sitePrefix=sitePrefix,
                                     siteName=siteName
                                     )
            # If it's the first-time alert for this siteName or if the siteName was not in the dictionary
            elif siteName not in self.siteName_last_seen:
                self.siteName_last_seen[siteName] = {
                    'timestamp': current_time, 'count': 1
                }
                self.slackNotifyDDoS(ip=ip, startTime=startTime,
                                     endTime=endTime, gbps=gbps,
                                     votes=votes, signature=signatureTotal,
                                     line=line, sitePrefix=sitePrefix,
                                     siteName=siteName
                                     )
            # If siteName was seen in the last 15 minutes
            elif (current_time - self.siteName_last_seen[siteName]['timestamp']) <= 900:
                self.siteName_last_seen[siteName]['count'] += 1
                # If this is the third alert, send threshold activation notification
                if self.siteName_last_seen[siteName]['count'] == 3:
                    threshold_payload = {
                            "username": "DDOS",
                            "text": f"Threshold Activated for {siteName}",
                            "blocks": [
                                {
                                    "type": "section",
                                    "text": {
                                        "type": "mrkdwn",
                                        "text": f"*Threshold Activated*: {siteName} - 15 minutes :white_check_mark:",
                                    },
                                }]
                            }
                    threshold_headers = {"Content-type": "application/json"}
                    requests.request("POST", self.slack_url,
                                     headers=threshold_headers,
                                     data=json.dumps(threshold_payload))
                # If count exceeds 3, skip sending further notifications
                elif self.siteName_last_seen[siteName]['count'] > 3:
                    pass
                else:
                    self.slackNotifyDDoS(ip=ip, startTime=startTime,
                                         endTime=endTime, gbps=gbps,
                                         votes=votes, signature=signatureTotal,
                                         line=line, sitePrefix=sitePrefix,
                                         siteName=siteName
                                         )


alert = ddosAlert()
alert.displayAlert()

