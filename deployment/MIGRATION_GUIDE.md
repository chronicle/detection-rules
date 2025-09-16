# SIEM Migration Guide - Ops to Detection-Rules Repository

## Migration Completed ✅

This document records the successful migration of all Chronicle SIEM components from the ops repository to the detection-rules repository for centralized management.

## What Was Migrated

### Production Tooling
- ✅ `bulk_detection_manager.py` (588 lines) → `tools/ops_production/`
- ✅ `chronicle_manager.sh` (544 lines) → `tools/ops_production/`
- ✅ `requirements.txt` → `tools/ops_production/`
- ✅ Production configuration → `tools/ops_production/config.yaml`

### Custom Detection Rules (27 total)
- ✅ `Admin_elavation.yaral` → `rules/custom/admin/`
- ✅ 26 GitHub detection rules → `rules/custom/github/`

### Configuration
- ✅ Environment-specific config → `config/environments/production.yaml`
- ✅ Service account authentication paths updated
- ✅ Directory references updated for new structure

## Directory Mapping

| Original (ops repo) | New (detection-rules repo) |
|---------------------|---------------------------|
| `scripts/Chronicle/bulk_detection_manager.py` | `tools/ops_production/bulk_detection_manager.py` |
| `scripts/Chronicle/chronicle_manager.sh` | `tools/ops_production/chronicle_manager.sh` |
| `scripts/Chronicle/config.yaml` | `tools/ops_production/config.yaml` |
| `scripts/Chronicle/SIEM/Custom Detections/` | `rules/custom/` |
| `scripts/Chronicle/SIEM/Custom Detections/Admin_elavation.yaral` | `rules/custom/admin/Admin_elavation.yaral` |
| `scripts/Chronicle/SIEM/Custom Detections/github/*.yaral` | `rules/custom/github/*.yaral` |

## Key Changes Made

### 1. Path Updates
- **Service account path**: Updated to reference ops repo via relative path
- **Rules directory**: Changed from `scripts/Chronicle/SIEM/Custom Detections` to `../../rules/custom`
- **Log file paths**: Updated for new directory structure

### 2. Enhanced Rule Discovery
- Modified `load_local_rules()` to use `rglob("*.yaral")` for recursive directory search
- Supports organized subdirectories (admin, github, future categories)

### 3. Git-Safe Structure
- All custom components in separate directories from Google's upstream
- `rules/community/` - Google's territory (safe merges)
- `rules/custom/` - Your territory (no conflicts)
- `tools/ops_production/` - Your tooling (isolated)

## Usage After Migration

### Navigate to Tools Directory
```bash
cd /path/to/detection-rules/tools/ops_production
```

### Test the Migration
```bash
# Check system status
./chronicle_manager.sh status

# Test authentication
./chronicle_manager.sh auth test

# Validate all rules
./chronicle_manager.sh rules verify-all

# Generate report
./chronicle_manager.sh report generate
```

## Git Workflow Setup

### Add Google's Repository as Upstream
```bash
cd /path/to/detection-rules
git remote add upstream https://github.com/chronicle/detection-rules.git
```

### Pull Google's Updates (Safe - No Conflicts)
```bash
git fetch upstream
git merge upstream/main
```

The custom directories (`rules/custom/`, `tools/ops_production/`) will never conflict with Google's updates.

## Credential Management

The migration maintains the existing authentication approach:
- Service account: `github-audit-writer@ops-production-1.iam.gserviceaccount.com`
- Key file path: `../../../../ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/ops-production-1.github-audit-writer.json`

## Cleanup Operations Needed

### Ops Repository Cleanup
The following can be safely removed from the ops repository after migration verification:

```bash
# Items to remove from ops repo:
ops/scripts/Chronicle/
├── bulk_detection_manager.py     # → Migrated
├── chronicle_manager.sh          # → Migrated  
├── config.yaml                   # → Migrated
├── requirements.txt              # → Migrated
├── SIEM/Custom Detections/       # → Migrated
└── README.md                     # → Enhanced and migrated
```

**⚠️ Important**: Keep the service account keys in the ops repository as they're referenced by the migrated tools.

## Validation Checklist

- [x] All 27 custom rules migrated successfully
- [x] Production tooling operational in new location
- [x] Configuration paths updated correctly
- [x] Authentication working via relative path to ops repo
- [x] Rule discovery working with subdirectory organization
- [x] Git structure safe for upstream merges
- [x] Documentation updated and comprehensive

## Benefits Achieved

1. **Centralized Management**: All SIEM operations in one repository
2. **Upstream Compatibility**: Safe merging of Google's updates
3. **Organized Structure**: Rules categorized by type/platform
4. **Production Ready**: All existing functionality preserved
5. **Future Scalable**: Easy to add new rule categories and tools

## Support

For issues with the migrated system:
- Check logs: `tools/ops_production/chronicle_detection_manager.log`
- Review configuration: `tools/ops_production/config.yaml`
- Test authentication: `cd tools/ops_production && ./chronicle_manager.sh auth test`
- Generate status report: `cd tools/ops_production && ./chronicle_manager.sh status`

---

**Migration Status**: ✅ COMPLETE - All Chronicle SIEM operations successfully consolidated in detection-rules repository.

