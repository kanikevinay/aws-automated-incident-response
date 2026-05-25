# ☁️🛡️ Cloud Guard: Automated Event-Driven Incident Response

<div align="center">

![AWS](https://img.shields.io/badge/AWS-Cloud%20Platform-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white)
![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Lambda](https://img.shields.io/badge/AWS-Lambda-FF9900?style=for-the-badge&logo=awslambda&logoColor=white)
![EventBridge](https://img.shields.io/badge/Amazon-EventBridge-FF4F8B?style=for-the-badge&logo=amazonaws&logoColor=white)
![Slack](https://img.shields.io/badge/Slack-Alerts-4A154B?style=for-the-badge&logo=slack&logoColor=white)
![Status](https://img.shields.io/badge/Status-Live%20%26%20Operational-brightgreen?style=for-the-badge)

**A production-grade, fully serverless Security Automation pipeline built on AWS.**  
Detects critical firewall misconfigurations in real time and remediates them automatically — before an attacker can exploit them.

*Zero human intervention. Zero delay. Zero tolerance for open admin ports.*

</div>

---

## 📐 Architecture Overview

> The diagram below illustrates the complete event-driven pipeline — from a misconfigured Security Group rule to automated remediation and Slack alerting, all within seconds.

```
[INSERT ARCHITECTURE DIAGRAM HERE]
(Recommended: A flow diagram showing EC2 Security Group → CloudTrail → EventBridge → Lambda → EC2 Revoke + Slack Alert)
```

---

## 🚨 The Problem: Open Admin Ports Are a Critical Risk

In cloud environments, a single misconfigured firewall rule can expose your entire infrastructure to the internet. The most dangerous offenders:

| Port | Protocol | Service | Risk Level |
|------|----------|---------|------------|
| **22** | TCP | SSH (Secure Shell) | 🔴 **CRITICAL** |
| **3389** | TCP | RDP (Remote Desktop Protocol) | 🔴 **CRITICAL** |

When a developer or admin accidentally (or maliciously) opens either of these ports to `0.0.0.0/0` (the entire internet), the window of exposure begins **immediately**. Automated scanners and botnets probe for open SSH/RDP ports continuously — within minutes of exposure, brute-force attacks begin.

**The traditional response?** Wait for a human analyst to notice the alert, investigate, escalate, and manually remediate. That process can take **hours**.

---

## ✅ The Automated Solution: Cloud Guard

**Cloud Guard** closes that window to **under 10 seconds.**

An event-driven AWS pipeline monitors every API call in the environment in real time. The instant a security group rule opens SSH (Port 22) or RDP (Port 3389) to the public internet, a serverless Lambda function:

1. **Detects** the violation via an EventBridge rule tripwire
2. **Evaluates** whether the new rule exposes a sensitive admin port to `0.0.0.0/0`
3. **Revokes** the offending firewall rule automatically using the AWS SDK
4. **Notifies** the security team with a rich, detailed Slack alert — including the exact rule that was removed, the affected resource, and a timestamp

This is **automated threat response at cloud scale** — the same pattern used in enterprise SOC environments and AWS Security Hub remediations.

---

## 🏗️ AWS Services Used

| Service | Role in Pipeline | Resource Name |
|---------|-----------------|---------------|
| **AWS IAM** | Admin identity & least-privilege Lambda permissions | `devsecops-admin` / `LambdaFirewallAccessPolicy` |
| **AWS CloudTrail** | Real-time audit log of all API management events | `security-environment-trail` |
| **Amazon EventBridge** | Event rule tripwire matching `AuthorizeSecurityGroupIngress` | `DetectPublicFirewallChanges` |
| **AWS Lambda** | Serverless Python remediation engine | `CloudSecurityGuard` |
| **Amazon EC2 API** | Target of detection and remediation (`revoke_security_group_ingress`) | Security Groups |
| **Slack Webhooks** | Real-time incident alerting channel | `#security-alerts` |

---

## 🔧 Step-by-Step Implementation

### Step 1 — CloudTrail: The Audit Foundation

All AWS management events are captured by `security-environment-trail`. This creates a continuous, tamper-resistant audit log of every API call made in the environment — the foundational data source for the entire detection pipeline.

> **Key config:** Management events enabled, read/write events tracked, log file validation ON.

---

### Step 2 — EventBridge: The Tripwire Engine

An EventBridge rule named `DetectPublicFirewallChanges` watches the CloudTrail event stream and fires the moment it sees the `AuthorizeSecurityGroupIngress` API call — the exact AWS SDK call made whenever an inbound rule is added to a Security Group.

**EventBridge Rule Event Pattern:**

```json
{
  "source": ["aws.ec2"],
  "detail-type": ["AWS API Call via CloudTrail"],
  "detail": {
    "eventSource": ["ec2.amazonaws.com"],
    "eventName": ["AuthorizeSecurityGroupIngress"]
  }
}
```

> **[INSERT SCREENSHOT HERE]**  
> *Caption: Amazon EventBridge console showing the `DetectPublicFirewallChanges` rule with **Enabled** status, target Lambda function, and event pattern.*

---

### Step 3 — IAM: Least-Privilege Permissions

The Lambda function's execution role is granted only the minimum permissions required to perform its job — nothing more. This follows the **principle of least privilege**, a cornerstone of cloud security.

**Inline Policy: `LambdaFirewallAccessPolicy`**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "FirewallRemediationPermissions",
      "Effect": "Allow",
      "Action": [
        "ec2:RevokeSecurityGroupIngress",
        "ec2:DescribeSecurityGroups"
      ],
      "Resource": "*"
    },
    {
      "Sid": "CloudWatchLogsPermissions",
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:*"
    }
  ]
}
```

> **Why these two permissions?**  
> - `ec2:DescribeSecurityGroups` — needed to inspect the current rules on a group and confirm a violation  
> - `ec2:RevokeSecurityGroupIngress` — the "close the door" action that removes the offending rule

---

### Step 4 — Lambda: The Remediation Brain

The `CloudSecurityGuard` Lambda function is the heart of the system. Written in **Python 3.12**, it is triggered by EventBridge, parses the CloudTrail event payload, checks for policy violations, and remediates instantly.

> **[INSERT SCREENSHOT HERE]**  
> *Caption: AWS Lambda console showing the `CloudSecurityGuard` function — runtime (Python 3.12), execution role, environment variables (SLACK\_WEBHOOK\_URL), and the inline code editor.*

**Sensitive configuration (the Slack Webhook URL) is stored as a Lambda Environment Variable — never hardcoded in source.**

---

## 🐍 The Python 3 Automation Script

```python
import boto3
import json
import logging
import os
import urllib.request
import urllib.error

# Configure structured logging for CloudWatch
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Sensitive admin ports that must NEVER be exposed to the public internet
SENSITIVE_PORTS = [22, 3389]
PUBLIC_CIDR = "0.0.0.0/0"

def lambda_handler(event, context):
    """
    CloudSecurityGuard — Automated Firewall Remediation Engine
    Triggered by EventBridge when AuthorizeSecurityGroupIngress is called.
    Checks for public exposure of sensitive admin ports and remediates instantly.
    """
    logger.info("CloudSecurityGuard triggered. Analysing event payload...")

    ec2_client = boto3.client("ec2")

    try:
        # Parse the CloudTrail event detail from the EventBridge wrapper
        detail = event.get("detail", {})
        request_params = detail.get("requestParameters", {})
        group_id = request_params.get("groupId")

        if not group_id:
            logger.warning("No groupId found in event. Skipping.")
            return {"statusCode": 200, "body": "No Security Group ID found in event."}

        logger.info(f"Inspecting Security Group: {group_id}")

        # Fetch the current inbound rules for the security group
        response = ec2_client.describe_security_groups(GroupIds=[group_id])
        security_group = response["SecurityGroups"][0]
        sg_name = security_group.get("GroupName", "Unknown")
        inbound_rules = security_group.get("IpPermissions", [])

        violations_found = False

        for rule in inbound_rules:
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            ip_ranges = rule.get("IpRanges", [])
            ip_protocol = rule.get("IpProtocol", "")

            for ip_range in ip_ranges:
                cidr = ip_range.get("CidrIp", "")

                # Check: Is a sensitive port exposed to the entire internet?
                if cidr == PUBLIC_CIDR and from_port in SENSITIVE_PORTS:
                    port = from_port
                    protocol = "SSH" if port == 22 else "RDP"
                    logger.warning(
                        f"VIOLATION DETECTED: Port {port} ({protocol}) open to {PUBLIC_CIDR} "
                        f"on Security Group {group_id} ({sg_name}). Initiating remediation..."
                    )

                    # --- AUTOMATED REMEDIATION ---
                    ec2_client.revoke_security_group_ingress(
                        GroupId=group_id,
                        IpPermissions=[
                            {
                                "IpProtocol": ip_protocol,
                                "FromPort": from_port,
                                "ToPort": to_port,
                                "IpRanges": [{"CidrIp": PUBLIC_CIDR}],
                            }
                        ],
                    )
                    logger.info(
                        f"REMEDIATED: Port {port} ({protocol}) rule successfully "
                        f"revoked from {group_id} ({sg_name})."
                    )
                    violations_found = True

                    # --- SLACK ALERT ---
                    send_slack_alert(group_id, sg_name, port, protocol)

        if not violations_found:
            logger.info(
                f"Security Group {group_id} ({sg_name}) inspected. No violations found."
            )

        return {"statusCode": 200, "body": "CloudSecurityGuard scan complete."}

    except Exception as e:
        logger.error(f"CloudSecurityGuard encountered an error: {str(e)}", exc_info=True)
        raise


def send_slack_alert(group_id: str, sg_name: str, port: int, protocol: str):
    """
    Sends a rich-formatted incident alert to the configured Slack channel
    using a webhook URL stored securely in Lambda environment variables.
    """
    webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        logger.error("SLACK_WEBHOOK_URL environment variable not set. Cannot send alert.")
        return

    port_label = f"Port {port} ({protocol})"
    emoji = "🚨"

    slack_payload = {
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"{emoji} SECURITY INCIDENT: Firewall Violation Auto-Remediated",
                    "emoji": True,
                },
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": [
                    {
                        "type": "mrkdwn",
                        "text": f"*Security Group ID:*\n`{group_id}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Security Group Name:*\n`{sg_name}`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": f"*Offending Rule:*\n`{port_label} → 0.0.0.0/0 (Internet)`",
                    },
                    {
                        "type": "mrkdwn",
                        "text": "*Action Taken:*\n`Rule REVOKED automatically ✅`",
                    },
                ],
            },
            {"type": "divider"},
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": "⚙️ *Cloud Guard* | Automated Incident Response | AWS Lambda `CloudSecurityGuard`",
                    }
                ],
            },
        ]
    }

    payload_bytes = json.dumps(slack_payload).encode("utf-8")

    try:
        req = urllib.request.Request(
            webhook_url,
            data=payload_bytes,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            logger.info(f"Slack alert sent successfully. HTTP Status: {resp.status}")
    except urllib.error.URLError as e:
        logger.error(f"Failed to send Slack alert: {e.reason}")
```

---

## 🔥 Live Fire Testing & Verification

This is where the rubber meets the road. The following test validates the entire pipeline end-to-end.

### Test Procedure

**1. Identify a test Security Group**  
Navigate to EC2 → Security Groups in the AWS Console. Select any non-production security group to use as the test target.

**2. Add the "bad" inbound rule (simulating a misconfiguration)**  
Manually add an inbound rule:

| Type | Protocol | Port Range | Source | Description |
|------|----------|------------|--------|-------------|
| SSH | TCP | 22 | 0.0.0.0/0 | ⚠️ TEST — intentionally bad rule |

> **[INSERT SCREENSHOT HERE]**  
> *Caption: AWS EC2 Security Group console — Inbound Rules tab showing the manually added SSH (Port 22) rule with source `0.0.0.0/0` **immediately after** it was added, before auto-remediation.*

**3. Save the rule and start the clock**  
Click **Save rules**. The moment the `AuthorizeSecurityGroupIngress` API call lands, CloudTrail captures it, EventBridge fires, and Lambda wakes up.

**4. Watch the rule disappear**  
Refresh the Inbound Rules tab. Within **under 10 seconds**, the offending rule will be gone — automatically revoked by `CloudSecurityGuard`.

> **[INSERT SCREENSHOT HERE]**  
> *Caption: The same Security Group Inbound Rules tab after auto-remediation — the SSH rule is completely gone. The group is clean.*

**5. Confirm in Lambda CloudWatch Logs**  
Navigate to Lambda → `CloudSecurityGuard` → Monitor → View CloudWatch Logs. Confirm the execution log shows:

```
[WARNING] VIOLATION DETECTED: Port 22 (SSH) open to 0.0.0.0/0 on Security Group sg-XXXXXXXXX...
[INFO]    REMEDIATED: Port 22 (SSH) rule successfully revoked from sg-XXXXXXXXX...
[INFO]    Slack alert sent successfully. HTTP Status: 200
```

**6. Verify the Slack Alert**  
Check the `#security-alerts` Slack channel. A rich incident card should have arrived in real time:

> **[INSERT SCREENSHOT HERE — THIS IS THE MONEY SHOT]**  
> *Caption: The `#security-alerts` Slack channel showing the Cloud Guard incident alert card — displaying Security Group ID, offending rule (Port 22 → 0.0.0.0/0), and confirmation that the rule was automatically revoked. Timestamp should show within seconds of the test.*

---

## 💼 Professional Competencies Demonstrated

This project is a real-world proof of the skills that matter most in **Cloud Support**, **DevSecOps**, and **SOC** roles:

### 🔐 Security Operations (SOC)
- **Threat Detection:** Designed and implemented a detection rule targeting a specific, high-risk API call (`AuthorizeSecurityGroupIngress`) — equivalent to writing a SIEM alert rule in a real SOC
- **Automated Response:** Built a SOAR-style playbook that requires zero human intervention to contain a threat
- **Incident Notification:** Engineered a structured, actionable alert format for security analysts — following best practices for SOC dashboards and on-call alerting

### ☁️ Cloud Engineering & Support
- **AWS Service Integration:** Demonstrated hands-on proficiency across IAM, CloudTrail, EventBridge, Lambda, and EC2 — the core services of the AWS security stack
- **Serverless Architecture:** Built and deployed a production-grade serverless function with proper error handling, structured logging, and environment variable management
- **Troubleshooting:** Debugged event schemas, IAM permission boundaries, and CloudWatch log traces independently

### 🔒 DevSecOps Principles
- **Least Privilege IAM:** Authored a minimal inline policy granting only the two EC2 permissions required — nothing more
- **Secrets Management:** Stored webhook credentials as Lambda environment variables, never in source code
- **Infrastructure as Code mindset:** Every component is explicitly configured, documented, and reproducible
- **Shift-Left Security:** Automated a security control that traditionally required manual human review — reducing MTTD (Mean Time to Detect) and MTTR (Mean Time to Respond) to under 10 seconds

### 🐍 Software Engineering
- **Python 3.12:** Production-quality script with structured logging, exception handling, typed function signatures, and clean separation of concerns
- **AWS SDK (boto3):** Fluent use of EC2 client methods, response parsing, and API call construction
- **Webhook Integration:** Built a Slack Block Kit payload from scratch using only Python's standard library (`urllib`) — no third-party dependencies

---

## 📁 Repository Structure

```
cloud-guard/
├── README.md                    # This file
├── lambda/
│   └── cloud_security_guard.py  # Main Lambda handler (Python 3.12)
├── iam/
│   └── lambda_firewall_policy.json  # Least-privilege IAM inline policy
├── eventbridge/
│   └── event_pattern.json       # EventBridge rule event pattern
├── docs/
│   ├── architecture-diagram.png # System architecture diagram
│   └── screenshots/             # Console screenshots for README
└── tests/
    └── test_handler.py          # Unit tests for Lambda handler logic
```

---

## 🚀 How to Deploy This Project

> **Prerequisites:** AWS CLI configured, an active AWS account, a Slack Incoming Webhook URL.

**1. Deploy the Lambda function**
```bash
# Zip the function code
zip cloud_security_guard.zip lambda/cloud_security_guard.py

# Create the Lambda function
aws lambda create-function \
  --function-name CloudSecurityGuard \
  --runtime python3.12 \
  --role arn:aws:iam::<YOUR_ACCOUNT_ID>:role/<YOUR_LAMBDA_ROLE> \
  --handler cloud_security_guard.lambda_handler \
  --zip-file fileb://cloud_security_guard.zip
```

**2. Set the Slack Webhook environment variable**
```bash
aws lambda update-function-configuration \
  --function-name CloudSecurityGuard \
  --environment "Variables={SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL}"
```

**3. Enable CloudTrail**
```bash
aws cloudtrail create-trail \
  --name security-environment-trail \
  --s3-bucket-name <YOUR_TRAIL_BUCKET> \
  --is-multi-region-trail

aws cloudtrail start-logging --name security-environment-trail
```

**4. Create the EventBridge Rule**
```bash
aws events put-rule \
  --name DetectPublicFirewallChanges \
  --event-pattern file://eventbridge/event_pattern.json \
  --state ENABLED

aws events put-targets \
  --rule DetectPublicFirewallChanges \
  --targets "Id=CloudSecurityGuardTarget,Arn=arn:aws:lambda:<REGION>:<ACCOUNT_ID>:function:CloudSecurityGuard"
```

---

## 👤 Author

**[Your Name]**  
Final-Year B.Tech Computer Science (Artificial Intelligence)  
Specializing in Cloud Security, DevSecOps & Security Operations

[![LinkedIn](https://img.shields.io/badge/LinkedIn-Connect-0A66C2?style=for-the-badge&logo=linkedin&logoColor=white)](https://linkedin.com/in/YOUR-PROFILE)
[![GitHub](https://img.shields.io/badge/GitHub-Follow-181717?style=for-the-badge&logo=github&logoColor=white)](https://github.com/YOUR-USERNAME)

---

<div align="center">

*Built with ☁️ + 🛡️ + ☕ on Amazon Web Services*  
*"Security is not a product, but a process." — Bruce Schneier*

</div>
