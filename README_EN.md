# WatchAD2.0 AD Threat Detection System

[![Golang version](https://img.shields.io/badge/Golang-1.17.1-017D9C.svg)](https://github.com/golang/go/releases/tag/go1.17.1) [![Kafka version](https://img.shields.io/badge/Kafka-2.8-252122.svg)](https://kafka.apache.org/quickstart) [![MongoDB version](https://img.shields.io/badge/MongoDB-latest-15EB61.svg)](https://www.mongodb.com/docs/) [![Winlogbeat version](https://img.shields.io/badge/Winlogbeat-7.6.1-F04E98.svg)](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-installation.html)

[中文版本](./README.md) 

## I. Product Overview

WatchAD2.0 is a system for analyzing and monitoring security logs on domain controllers, developed by the 360 Information Security Center. It collects event logs and network traffic from all domain controllers and uses methods such as feature matching, protocol analysis, historical behavior analysis, sensitive operations detection, and honeypot account monitoring to detect various known and unknown threats. It can detect both known and unknown threats and covers most common internal network domain penetration techniques. Compared to WatchAD1.0, it provides the following improvements:

1. Improved Detection Capabilities: This update expands the range of scenarios in which suspicious account activities can be monitored and strengthens detection capabilities for scenarios such as privilege escalation and maintenance. It includes the detection of abnormal accounts and activities, Zerologon privilege escalation, SPN hijacking, shadow tickets, and more.
2. Refactored Analysis Engine using Golang: The Analysis Engine has been refactored in Golang to improve processing efficiency of massive logs and data traffic, ensuring timely and effective alert detection. This was achieved by leveraging Golang's more efficient concurrency capabilities. The previous development language, Python, has been replaced.
3. Integrated and Simplified Architecture: The web platform and detection engine are integrated to streamline the deployment process. Users only need to rely on message queues and storage components for deployment. This enhances system performance and stability, making the system more efficient and user-friendly, providing a better overall experience for users.

## II. Overall Architecture

WatchAD2.0 consists of four components: the Log Collection Agent, Rule Detection and Log Analysis Engine, Cache Database, and Web Control End. The architecture is illustrated in the diagram below.

![image](./images/Architecture_en.png)

> At present, the traffic detection capability is not available as an open source option. To perform threat detection, capture domain controller traffic and upload it to the 360 Zhouhe SaaS PCAP analysis platform at https://zhouhe.360.cn/

## III. Currently Supported Specific Detection Functions

- Abnormal Activity Detection: Certificate service activities, creation of machine account event activities, creation of user accounts similar to DC, reset user account password activities, TGT ticket-related activities.
- Credential Theft: AS-REP abnormal traffic requests, Kerberoasting attack behavior, local Dump Ntds file exploitation.
- Lateral Movement: Directory service replication, abnormal display credential login behavior, remote command execution.
- Privilege Escalation: ACL abnormal modification behavior, abuse of certificate service privilege escalation, rotten potato privilege escalation, MS17-010, added GPO monitoring, NTLM relay detection, resource-based constrained delegation, SPN hijacking, print service attack, ZeroLogon privilege escalation attack.
- Persistence: DCShadow persistence, DSRM password reset, GPO delegation of authority, SamAccountName deception attack, shadow tickets, Sid History persistence, universal key, abnormal permissions for persistence.
- Defense Bypass: System log clearing, disabling system log service.
> Custom Detection Rules: To modify or add rules, navigate to the {project_home}/detect_plugins/event_log/ directory. Please note that changes will only take effect after recompilation.

## IV. Platform Display

![image](./images/Platform_en.png)

## V. Compilation & Deployment & Operation Guide

### Server Deployment Operations:

 **Recommended Docker Deployment:**

WatchAD2.0 relies on components such as Kafka, Zookeeper, and go1.17.1. It can be easily deployed with a single command using Docker. Please follow the steps below:

In the project root directory, create a file named `.env` and modify the Kafka address and domain controller connection information.
```shell
# Modify Kafka configuration to match the current server's IP.
KAFKAHOST=10.10.10.10
KAFKAADV=PLAINTEXT://10.10.10.10:9092
BROKER=10.10.10.10:9092

# Default Username and Password for Mongo Configuration
MONGOUSER=IATP
MONGOPWD=IATP-by-360
  
# The configuration of the domain controller involves using DCUSER, which is the distinguished name of a user within the domain.
DCNAME="demo.com"
DCSERVER=10.10.10.11
DCUSER="CN=IATP, OU=Users, DC=demo, DC=com"
DCPWD="Pass123"

# Web configuration can be set up for any user within the domain or the CN of DCUSER.
WEBUSER="IATP"
```
> Note: If your domain controller does not use SSL, remove the --ssl parameter from the LDAP command in the entrypoint.sh file.

To start the dependencies, detection engine, and web service, run the following commands:
```
docker-compose build
docker-compose up -d
```
Enter the credentials for WEBUSER and successfully log in to port 80 of the server to access the web backend.
> Note: Delete the kafka configuration file before restarting Docker to avoid configuration conflicts: ./data/kafka/logs/meta.properties

**Manual Deployment:**

Prepare the Kafka and MongoDB clusters in advance.
1. Compile the Go program

   To compile the project, use version go1.17.1 and run the following command in
   the project root directory: `go mod vendor && go build -o ./main main.go`.
   Then, copy the compiled main file and the iatp_wbm directory to the server.

2. Initialize Database Information

   `./main init --mongourl mongodb://mongo:password@127.0.0.1:27017`
   This command writes the mongourl configuration to the /etc/iatp.conf file. If reinstalling, delete this file before generating it again with the program.

3. Configure LDAP Authentication

   To configure the LDAP authentication, use the following command:
   `./main init --mongourl mongodb://mongo:password@127.0.0.1:27017 --domainname demo.com --domainserver 10.10.10.11 --username "IATP" --password "Pass123" --ssl`

4. Initialize Indexes for Data Tables
   `./main init --mongourl mongodb://mongo:password@127.0.0.1:27017 --index`

5. Initialize Kafka Consumer Configuration
   Adjust the Brokers, Topic, Group, and other details to correspond with the Kafka cluster:
   `./main init -source --sourcename ITEvent --sourceengine event_log --brokers 10.10.10.10:9092 --topic winlogbeat --group sec-ata --oldest false --kafka true`

6. Web Management Configuration
   `./main web --init --authdomain demo.com --user IATP`
   Set the initial user account for login to match the value in LDAP.

7. Start the Main Detection Engine
   `./main run --engine_start`

8. Start the Web Service
   `./main run --web_start`

To access the web backend, go to port 80 on the server and enter the corresponding credentials for --user. Once entered, login successfully.

**Alert Forwarding:**

In the management backend, go to System Settings > Data Source Output Configuration and configure alert forwarding in the following format (currently only supports Kafka):
```
{
  "Address":

 "10.10.10.10:9092",
  "Topic": "iatp_alarm"
}
```

### Client Deployment Operations:

**Enable Auditing**  
To ensure comprehensive analysis, all event logs from domain controllers must be included. Therefore, it is necessary to enable the security auditing option to record all types of event logs. For example, in Windows Server 2016, navigate to Local Security Policy -> Security Settings -> Local Policies -> Audit Policy, and enable all audit options.

![image](./images/AuditPolicy_en.png)

**Install Winlogbeat**  
To avoid false positives and false negatives, we recommend installing Winlogbeat on all domain controllers.
The latest version of Winlogbeat can be downloaded at https://www.elastic.co/cn/downloads/beats/winlogbeat, corresponding to your version. Please note that the recommended version is 7.6.1, as other versions may have field changes and compatibility issues.
Modify the winlogbeat.yml configuration file as shown in the example below, assuming the IP address of Kafka is 10.10.10.10:

```yaml
winlogbeat.event_logs:
  - name: Security
    ignore_older: 1h
output.kafka:
    hosts: ["10.10.10.10:9092"]
    topic: winlogbeat
```
Follow the [official tutorial](https://www.elastic.co/guide/en/beats/winlogbeat/current/winlogbeat-installation.html) to install the Winlogbeat service.