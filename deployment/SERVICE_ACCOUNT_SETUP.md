# Chronicle SIEM Service Account Setup Guide

## Overview

A dedicated service account has been created for Chronicle SIEM operations with proper permissions for detection rule management.

## Service Account Details

- **Name**: `chronicle-siem-manager`
- **Email**: `chronicle-siem-manager@ops-production-1.iam.gserviceaccount.com`
- **Project**: `ops-production-1` (service account project)
- **Target**: `siem-production-2` (Chronicle instance project)
- **Region**: `northamerica-northeast2` (Canadian Chronicle region)

## Permissions Granted

The service account has been configured with the following Chronicle permissions:

- `roles/chronicle.admin` - Full Chronicle SIEM management access
  - Create, update, delete detection rules
  - Manage rule deployments and configurations
  - Full access to Chronicle APIs
- `roles/chronicle.viewer` - Chronicle data access for reporting
  - Generate reports and analytics
  - Read detection rule status and metadata

## Deployment Steps

### 1. Apply Terraform Configuration

```bash
cd /path/to/ops/iac/terraform/iam/principals/service-accounts/single-use/live

# Apply the service account configuration
terraform plan
terraform apply
```

### 2. Apply Service Account Keys

```bash
cd /path/to/ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys

# Generate the service account key
terraform plan
terraform apply
```

### 3. Verify Service Account Creation

After applying Terraform, verify the service account and key were created:

```bash
# Check if service account exists
gcloud iam service-accounts list --project=ops-production-1 --filter="email:chronicle-siem-manager@ops-production-1.iam.gserviceaccount.com"

# Verify key file was generated
ls -la SECRET_DO_NOT_SHARE.chronicle-siem-manager.json
```

### 4. Test Chronicle Authentication

```bash
cd /path/to/detection-rules/tools/ops_production

# Activate virtual environment
source venv/bin/activate

# Test authentication with new service account
./chronicle_manager.sh status
```

## Configuration Files Created

### Service Account Bindings
**File**: `ops/iac/terraform/iam/principals/service-accounts/single-use/live/config/ops-production-1.chronicle-siem-manager.bindings.yaml`

### Service Account Key Configuration
**File**: `ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/key.ops-production-1.chronicle-siem-manager.bindings.tf`

### Updated Detection Rules Configuration
**File**: `detection-rules/tools/ops_production/config.yaml`
- Updated service account path to use new dedicated account

## Security Considerations

1. **Principle of Least Privilege**: Service account has only Chronicle-specific permissions
2. **Key Security**: Private key stored in gitignored location
3. **Audit Trail**: All Chronicle operations will be attributed to this dedicated account
4. **Isolation**: Separate from other operations (GitHub audit, etc.)

## Troubleshooting

### Permission Issues
If you encounter permission errors:

1. Verify service account was created:
   ```bash
   gcloud iam service-accounts describe chronicle-siem-manager@ops-production-1.iam.gserviceaccount.com
   ```

2. Check Chronicle permissions:
   ```bash
   gcloud projects get-iam-policy siem-production-2 --flatten="bindings[].members" --filter="bindings.members:chronicle-siem-manager@ops-production-1.iam.gserviceaccount.com"
   ```

3. Verify key file exists and is readable:
   ```bash
   ls -la /path/to/ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/SECRET_DO_NOT_SHARE.chronicle-siem-manager.json
   ```

### Chronicle API Issues
If Chronicle API calls fail:

1. Verify Chronicle instance details in config.yaml
2. Check regional endpoint configuration
3. Test with Chronicle web interface to confirm instance is accessible

## Next Steps

Once the service account is deployed and tested:

1. **Deploy Detection Rules**: Use the new service account to deploy your 27 custom rules
2. **Set up Monitoring**: Configure alerts for failed rule deployments
3. **Documentation**: Update team documentation with new service account details
4. **Cleanup**: Consider removing Chronicle permissions from the old `github-audit-writer` account

---

**Status**: Ready for deployment - Terraform configurations created and detection-rules repository updated.
