# Cloud Audit Queries Reference

Expanded audit queries for investigating credential abuse across cloud providers. Each section includes query variations, expected output examples, what to look for, common false positives, and retention period notes.

---

## AWS CloudTrail

**Retention period:** 90 days via the free `lookup-events` API. Longer retention requires a trail configured to deliver to S3 or CloudWatch Logs.

### Query Variations

```bash
# 1. All API calls made with a specific access key
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=AccessKeyId,AttributeValue=AKIAIOSFODNN7EXAMPLE \
  --start-time "2026-03-19T00:00:00Z" \
  --end-time "2026-03-26T00:00:00Z" \
  --max-results 50 \
  --query 'Events[].{Time:EventTime,Name:EventName,Source:EventSource,IP:sourceIPAddress}'

# 2. All API calls by a specific IAM user
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=Username,AttributeValue=compromised-user \
  --start-time "2026-03-19T00:00:00Z" \
  --max-results 50

# 3. Check for IAM user creation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateUser \
  --start-time "2026-03-19T00:00:00Z"

# 4. Check for access key creation
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=CreateAccessKey \
  --start-time "2026-03-19T00:00:00Z"

# 5. Check for policy attachments (privilege escalation)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachUserPolicy \
  --start-time "2026-03-19T00:00:00Z"

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AttachRolePolicy \
  --start-time "2026-03-19T00:00:00Z"

# 6. Check for role assumption (lateral movement)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=AssumeRole \
  --start-time "2026-03-19T00:00:00Z" \
  --max-results 50

# 7. Check for S3 data access
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=GetObject \
  --start-time "2026-03-19T00:00:00Z" \
  --max-results 50

# 8. Check for console login attempts
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=ConsoleLogin \
  --start-time "2026-03-19T00:00:00Z"

# 9. Check for EC2 instance launches (cryptomining, C2)
aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=RunInstances \
  --start-time "2026-03-19T00:00:00Z"

# 10. Filter by unusual source IPs
aws cloudtrail lookup-events \
  --start-time "2026-03-19T00:00:00Z" \
  --query 'Events[?sourceIPAddress!=`amazonaws.com`].{Time:EventTime,Name:EventName,IP:sourceIPAddress}' \
  --max-results 100
```

### Expected Output Example

```json
{
    "Events": [
        {
            "EventTime": "2026-03-20T14:32:11Z",
            "EventName": "CreateAccessKey",
            "EventSource": "iam.amazonaws.com",
            "sourceIPAddress": "198.51.100.42",
            "Username": "compromised-user",
            "Resources": [
                {
                    "ResourceType": "AWS::IAM::AccessKey",
                    "ResourceName": "AKIANEWKEYEXAMPLE"
                }
            ]
        }
    ]
}
```

### What to Look For

- API calls from IP addresses outside your known infrastructure ranges
- `CreateAccessKey`, `CreateUser`, `CreateLoginProfile` events (persistence)
- `AttachUserPolicy`, `AttachRolePolicy`, `PutUserPolicy` events (privilege escalation)
- `AssumeRole` calls to roles the compromised identity does not normally use
- `RunInstances`, `CreateFunction` events (resource provisioning)
- `GetObject`, `ListBuckets` calls to sensitive S3 buckets
- `ConsoleLogin` events for service accounts that should not use the console
- Any activity during unusual hours for the compromised identity

### Common False Positives

- AWS service-to-service calls (sourceIPAddress will be an AWS service domain like `iam.amazonaws.com`)
- Automated systems (CI/CD, monitoring) that legitimately use the same credentials
- CloudFormation or Terraform runs that create IAM resources as part of normal operations
- Session token refreshes from EC2 instance metadata

---

## GCP Audit Logs

**Retention period:** Admin Activity audit logs are retained for 400 days. Data Access audit logs are retained for 30 days by default (configurable up to 3650 days with a sink to Cloud Storage or BigQuery).

### Query Variations

```bash
# 1. All activity by a specific service account
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="my-sa@my-project.iam.gserviceaccount.com"' \
  --limit 50 --format json

# 2. Service account key creation
gcloud logging read \
  'protoPayload.methodName="google.iam.admin.v1.CreateServiceAccountKey"' \
  --limit 20 --format json

# 3. IAM policy changes
gcloud logging read \
  'protoPayload.methodName="SetIamPolicy"' \
  --limit 20 --format json

# 4. Service account impersonation
gcloud logging read \
  'protoPayload.methodName="GenerateAccessToken" OR protoPayload.methodName="SignBlob"' \
  --limit 20 --format json

# 5. Compute instance creation (cryptomining, C2)
gcloud logging read \
  'protoPayload.methodName="v1.compute.instances.insert"' \
  --limit 20 --format json

# 6. Cloud Storage access
gcloud logging read \
  'protoPayload.methodName="storage.objects.get" AND protoPayload.authenticationInfo.principalEmail="my-sa@my-project.iam.gserviceaccount.com"' \
  --limit 50 --format json

# 7. Warnings and errors from a specific principal
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="my-sa@my-project.iam.gserviceaccount.com" AND severity>=WARNING' \
  --limit 50 --format json

# 8. Activity within a specific time window
gcloud logging read \
  'protoPayload.authenticationInfo.principalEmail="my-sa@my-project.iam.gserviceaccount.com" AND timestamp>="2026-03-19T00:00:00Z" AND timestamp<="2026-03-26T00:00:00Z"' \
  --limit 100 --format json

# 9. BigQuery data access (exfiltration)
gcloud logging read \
  'protoPayload.methodName="jobservice.jobcompleted" AND protoPayload.authenticationInfo.principalEmail="my-sa@my-project.iam.gserviceaccount.com"' \
  --limit 20 --format json

# 10. Secret Manager access
gcloud logging read \
  'protoPayload.methodName="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion"' \
  --limit 20 --format json
```

### Expected Output Example

```json
{
  "protoPayload": {
    "methodName": "google.iam.admin.v1.CreateServiceAccountKey",
    "authenticationInfo": {
      "principalEmail": "my-sa@my-project.iam.gserviceaccount.com"
    },
    "requestMetadata": {
      "callerIp": "198.51.100.42",
      "callerSuppliedUserAgent": "google-cloud-sdk/400.0.0"
    }
  },
  "timestamp": "2026-03-20T14:32:11Z",
  "severity": "NOTICE"
}
```

### What to Look For

- `CreateServiceAccountKey` events (persistence via new keys)
- `SetIamPolicy` events that grant new roles (privilege escalation)
- `callerIp` values from unexpected networks
- `GenerateAccessToken` or `SignBlob` calls (impersonation)
- Compute instance creation in unusual regions
- Access to Secret Manager, Cloud Storage, or BigQuery from the compromised identity
- Activity from user agents that do not match your tooling

### Common False Positives

- Google-internal service calls (callerIp may show as `private` or a Google IP)
- Terraform or Deployment Manager applying infrastructure changes
- Automated key rotation by legitimate systems
- Monitoring and logging agents accessing metadata

---

## Azure Activity Log

**Retention period:** 90 days in the Azure portal. Longer retention requires routing to a Log Analytics workspace, Storage Account, or Event Hub.

### Query Variations

```bash
# 1. All activity by a specific service principal
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --caller "SERVICE_PRINCIPAL_APP_ID" \
  --query "[].{Time:eventTimestamp,Op:operationName.value,Status:status.value,Caller:caller}"

# 2. Role assignment changes
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --resource-provider "Microsoft.Authorization" \
  --query "[?contains(operationName.value, 'roleAssignments')]"

# 3. Resource group creation
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --resource-provider "Microsoft.Resources" \
  --query "[?contains(operationName.value, 'resourceGroups/write')]"

# 4. VM creation
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --resource-provider "Microsoft.Compute" \
  --query "[?contains(operationName.value, 'virtualMachines/write')]"

# 5. Key Vault access
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --resource-provider "Microsoft.KeyVault" \
  --query "[].{Time:eventTimestamp,Op:operationName.value,Status:status.value}"

# 6. Storage account access
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --resource-provider "Microsoft.Storage" \
  --query "[].{Time:eventTimestamp,Op:operationName.value,Status:status.value}"

# 7. Failed operations (may indicate probing)
az monitor activity-log list \
  --start-time "2026-03-19T00:00:00Z" \
  --query "[?status.value=='Failed'].{Time:eventTimestamp,Op:operationName.value,Caller:caller}"
```

### Expected Output Example

```json
[
  {
    "Time": "2026-03-20T14:32:11Z",
    "Op": "Microsoft.Authorization/roleAssignments/write",
    "Status": "Succeeded",
    "Caller": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
  }
]
```

### What to Look For

- `roleAssignments/write` events (privilege escalation)
- Resource creation in unusual regions or resource groups
- Key Vault secret access from the compromised identity
- VM or container creation (compute resource abuse)
- Failed operations that suggest the attacker was probing permissions
- Activity from unexpected caller IP addresses (check `httpRequest.clientIpAddress` in full log)

### Common False Positives

- Azure Resource Manager internal operations
- Azure Policy remediation tasks
- Automated deployments via Azure DevOps or GitHub Actions
- Diagnostic settings and monitoring agent operations

---

## GitHub Audit Log

**Retention period:** 180 days for GitHub Enterprise. Non-Enterprise organizations have limited API access (approximately 7 days for some event types). The web UI retains events longer than the API for Enterprise accounts.

### Query Variations

```bash
# 1. All activity by a specific actor
gh api "/orgs/ORG/audit-log" --method GET -F phrase="actor:USERNAME" -F per_page=50

# 2. Personal access token events
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:personal_access_token" -F per_page=50

# 3. Deploy key events
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:deploy_key" -F per_page=50

# 4. Repository creation (exfiltration dead drops)
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:repo.create" -F per_page=50

# 5. Repository cloning or forking
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:repo.clone" -F per_page=50
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:repo.fork" -F per_page=50

# 6. Webhook creation (data exfiltration channel)
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:hook.create" -F per_page=50

# 7. Team membership changes
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:team.add_member" -F per_page=50

# 8. Organization member invitations
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:org.invite_member" -F per_page=50

# 9. Branch protection changes
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:protected_branch" -F per_page=50

# 10. Actions secrets changes
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:org.update_actions_secret" -F per_page=50

# 11. OAuth app authorizations
gh api "/orgs/ORG/audit-log" --method GET -F phrase="action:oauth_authorization.create" -F per_page=50

# 12. Filter by date range (ISO 8601)
gh api "/orgs/ORG/audit-log" --method GET -F phrase="created:2026-03-19..2026-03-26" -F per_page=50
```

### Expected Output Example

```json
[
  {
    "@timestamp": 1711123931000,
    "action": "repo.create",
    "actor": "compromised-user",
    "repo": "org/suspicious-new-repo",
    "visibility": "private",
    "created_at": "2026-03-20T14:32:11Z"
  }
]
```

### What to Look For

- New repositories created (could be used as exfiltration destinations)
- New deploy keys or PATs created (persistence)
- Webhook creation pointing to external URLs (data exfiltration)
- Branch protection rules removed or weakened
- Team membership changes or new org members added
- OAuth app authorizations from unknown applications
- Actions secrets modified (could allow further compromise)
- Repository visibility changes (private to public)

### Common False Positives

- Automated bot accounts performing routine operations
- Dependabot or Renovate creating PRs and branches
- GitHub Apps performing authorized actions
- Scheduled GitHub Actions workflows

---

## Kubernetes Audit Logs

**Retention period:** Varies by cluster configuration. Managed services (EKS, GKE, AKS) typically retain audit logs for 90 days in their respective cloud logging systems. Self-managed clusters depend on log rotation configuration.

### Query Variations

```bash
# 1. Check API server logs for service account usage
kubectl logs -n kube-system -l component=kube-apiserver --since=72h | grep "SERVICE_ACCOUNT_NAME"

# 2. Recent cluster role bindings (privilege escalation)
kubectl get clusterrolebindings --sort-by=.metadata.creationTimestamp | tail -20

# 3. Recent role bindings across namespaces
kubectl get rolebindings --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# 4. Recently created secrets
kubectl get secrets --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# 5. Recently created service accounts
kubectl get serviceaccounts --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# 6. Recently created pods (may indicate workload injection)
kubectl get pods --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# 7. Check for privileged pods
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.containers[].securityContext.privileged==true) | {namespace:.metadata.namespace, name:.metadata.name}'

# 8. Check for pods with host network access
kubectl get pods --all-namespaces -o json | \
  jq '.items[] | select(.spec.hostNetwork==true) | {namespace:.metadata.namespace, name:.metadata.name}'

# 9. Check for config maps that may contain credentials
kubectl get configmaps --all-namespaces --sort-by=.metadata.creationTimestamp | tail -20

# 10. For managed Kubernetes, use cloud-specific audit logs
# EKS: Check CloudTrail for EKS API calls
# GKE: Check GCP Audit Logs for GKE
# AKS: Check Azure Activity Log for AKS
```

### Expected Output Example

```
NAMESPACE     NAME                                    AGE
default       suspicious-rolebinding                  2h
kube-system   attacker-cluster-admin-binding          1h
```

### What to Look For

- New `ClusterRoleBinding` or `RoleBinding` resources granting `cluster-admin` or other powerful roles
- New service accounts in unexpected namespaces
- Pods running with `privileged: true` or `hostNetwork: true`
- Secrets created or accessed outside normal deployment patterns
- New namespaces created
- Pods using images from unexpected registries

### Common False Positives

- Helm releases creating role bindings and service accounts
- Cluster autoscaler or node management creating system resources
- Monitoring agents (Prometheus, Datadog) creating service accounts
- Cert-manager creating secrets for TLS certificates
