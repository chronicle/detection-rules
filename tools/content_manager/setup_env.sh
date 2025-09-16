#!/bin/bash

# Google Chronicle Content Manager Environment Setup
# Engineering Officer's Implementation for Captain Picard

# Activate virtual environment
source venv/bin/activate

# Set required environment variables for Chronicle API
export GOOGLE_APPLICATION_CREDENTIALS="/Users/erikgrunner/Documents/GitHub/ops/iac/terraform/iam/principals/service-accounts/single-use/live/keys/SECRET_DO_NOT_SHARE.chronicle-siem-manager.json"
export GOOGLE_SECOPS_API_BASE_URL="https://northamerica-northeast2-chronicle.googleapis.com/v1alpha"
export GOOGLE_SECOPS_API_UPLOAD_BASE_URL="https://northamerica-northeast2-chronicle.googleapis.com/upload/v1alpha"
export AUTHORIZATION_SCOPES='{"GOOGLE_SECOPS_API":["https://www.googleapis.com/auth/cloud-platform"]}'
export GOOGLE_SECOPS_INSTANCE="projects/siem-production-2/locations/northamerica-northeast2/instances/87bb0359-c967-420b-952c-3956c9bdc3d3"

echo "✅ Google Chronicle Content Manager environment configured"
echo "🎯 Chronicle Instance: Canadian region (northamerica-northeast2)"
echo "🔑 Service Account: chronicle-siem-manager"
echo ""
echo "Available commands:"
echo "  python -m content_manager rules verify-all    # Verify all rules"
echo "  python -m content_manager rules update        # Deploy/update rules" 
echo "  python -m content_manager rules get           # Download rules from Chronicle"
echo "  python -m content_manager rules --help        # See all options"
