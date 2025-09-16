# Chronicle Production Manager

A production-ready tool for managing Chronicle SIEM custom detections at scale, migrated from the ops repository for centralized SIEM management.

## 🎯 **Current Status: OPERATIONAL** ✅

- ✅ **Chronicle API**: Connected to Canadian region (northamerica-northeast2)
- ✅ **Authentication**: Using `github-audit-writer` service account 
- ✅ **Configuration**: Production-ready with proper regional endpoints
- ✅ **Migration**: Successfully migrated from ops repository
- ✅ **Custom Rules**: 27 detection rules in organized structure

## Features

- **🔗 Regional Support**: Full Canadian Chronicle region support
- **📋 Bulk Deployment**: Deploy multiple detection rules simultaneously
- **✅ Rule Validation**: Validate YARAL syntax before deployment
- **⚡ State Management**: Enable/disable rules in bulk
- **📊 Comprehensive Reporting**: Generate detailed reports on detection rules
- **🔍 Metadata Parsing**: Extract and manage rule metadata automatically
- **📝 Enterprise Logging**: Comprehensive logging for audit and troubleshooting
- **🔄 Bidirectional Sync**: Download rules from Chronicle or upload local rules

## Directory Structure

```
detection-rules/
├── rules/
│   ├── community/          # Google's community rules (upstream updates)
│   └── custom/             # Your organization-specific rules
│       ├── admin/          # Administrative detection rules
│       └── github/         # GitHub-specific detection rules
├── tools/
│   ├── content_manager/    # Google's official content manager
│   └── ops_production/     # Your production management tools (THIS)
│       ├── bulk_detection_manager.py
│       ├── chronicle_manager.sh
│       ├── config.yaml
│       └── requirements.txt
└── config/
    └── environments/       # Environment-specific configurations
```

## Prerequisites

1. **Chronicle Instance**: Access to Chronicle in northamerica-northeast2 region
2. **Service Account**: `github-audit-writer@ops-production-1.iam.gserviceaccount.com` with Chronicle permissions
3. **Python 3.8+**: Required for running the tool
4. **Dependencies**: Installed via `requirements.txt`

## Quick Start

### Navigate to Production Tools Directory
```bash
cd /path/to/detection-rules/tools/ops_production
```

### Generate Detection Report
```bash
python3 bulk_detection_manager.py \
  --credentials "../../../../ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/ops-production-1.github-audit-writer.json" \
  --region northamerica-northeast2 \
  report
```

### Load and Validate Local Rules
```bash
python3 bulk_detection_manager.py \
  --credentials "../../../../ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/ops-production-1.github-audit-writer.json" \
  --region northamerica-northeast2 \
  --detections-dir "../../rules/custom" \
  load
```

### Deploy Detection Rules
```bash
python3 bulk_detection_manager.py \
  --credentials "../../../../ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/ops-production-1.github-audit-writer.json" \
  --region northamerica-northeast2 \
  --detections-dir "../../rules/custom" \
  deploy
```

## Shell Wrapper Usage

Use `chronicle_manager.sh` for enhanced operations:

```bash
# Test authentication
./chronicle_manager.sh auth test

# Generate report
./chronicle_manager.sh report generate

# Validate all local rules
./chronicle_manager.sh rules verify-all

# Deploy specific rules
./chronicle_manager.sh rules deploy "Admin_elevation"

# Check system status
./chronicle_manager.sh status
```

## Configuration

The system uses `config.yaml` with paths updated for the detection-rules repository structure:

- **Service Account**: References ops repository via relative path
- **Rules Directory**: Points to `../../rules/custom`
- **Regional Configuration**: Canadian Chronicle region
- **API Endpoints**: Production Chronicle endpoints

## Migration Notes

This tool was migrated from the ops repository to centralize all SIEM management in the detection-rules repository. Key changes:

1. **Directory Paths**: Updated all paths to work with detection-rules structure
2. **Rule Discovery**: Enhanced to search subdirectories recursively
3. **Configuration**: Adapted for new repository layout
4. **Git Safety**: Positioned to avoid conflicts with Google's upstream updates

## Authentication

Uses the existing `github-audit-writer` service account with Chronicle permissions:
- `roles/chronicle.admin` - Full Chronicle management access
- `roles/chronicle.viewer` - Chronicle data access

**Service Account Location**: `../../../../ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/ops-production-1.github-audit-writer.json`

## Custom Rules Management

### Rule Organization
- **Admin Rules**: `../../rules/custom/admin/`
- **GitHub Rules**: `../../rules/custom/github/`
- **Future Categories**: Add new subdirectories as needed

### Adding New Rules
1. Create `.yaral` file in appropriate subdirectory under `../../rules/custom/`
2. Follow Google's YARA-L style guide
3. Include required metadata (author, description)
4. Test with `./chronicle_manager.sh rules verify <rule_file>`
5. Deploy with `./chronicle_manager.sh rules deploy`

## Git Workflow Integration

This repository structure supports seamless upstream updates from Google:

```bash
# Add Google as upstream remote (one-time setup)
git remote add upstream https://github.com/chronicle/detection-rules.git

# Pull Google's latest community rules
git fetch upstream
git merge upstream/main  # No conflicts with your custom directories
```

## Troubleshooting

### Common Issues

1. **Path Errors**: Ensure you're running commands from `tools/ops_production/` directory
2. **Authentication**: Verify service account key exists in ops repository
3. **Rule Discovery**: Check that rules are in `../../rules/custom/` subdirectories

### Debug Mode
```bash
python3 bulk_detection_manager.py \
  --credentials "../../../../ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/ops-production-1.github-audit-writer.json" \
  --region northamerica-northeast2 \
  --verbose \
  report
```

## Production Status

### Current Deployment
- **Chronicle Instance**: siem-production-2 (Canadian region)
- **Custom Rules**: 27 detection rules (1 admin + 26 GitHub)
- **Service Account**: github-audit-writer (ops-production-1)
- **Status**: Fully operational and migrated

---

**Engineering Status**: Production-ready Chronicle SIEM detection management system with full Canadian regional support, successfully migrated to detection-rules repository for centralized SIEM operations. ✅

