#!/bin/bash

# Chronicle Content Manager - Enhanced with Google's best practices
# Engineering Officer's Implementation for Captain Picard
# Compatible with Google's official Content Manager structure

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SCRIPT_DIR}/config.yaml"
PYTHON_SCRIPT="${SCRIPT_DIR}/bulk_detection_manager.py"
LOG_FILE="${SCRIPT_DIR}/chronicle_manager.log"

# Environment variables for compatibility with Google's Content Manager
export LOGGING_LEVEL="INFO"
export GOOGLE_SECOPS_API_BASE_URL="https://northamerica-northeast2-chronicle.googleapis.com/v1alpha"
export GOOGLE_SECOPS_API_UPLOAD_BASE_URL="https://northamerica-northeast2-chronicle.googleapis.com/upload/v1alpha"
export AUTHORIZATION_SCOPES='{"GOOGLE_SECOPS_API":["https://www.googleapis.com/auth/cloud-platform"]}'

# Check if GOOGLE_SECOPS_INSTANCE is set
if [[ -z "${GOOGLE_SECOPS_INSTANCE:-}" ]]; then
    echo -e "${YELLOW}Warning: GOOGLE_SECOPS_INSTANCE not set. Using default format.${NC}"
    echo -e "${BLUE}Set it with: export GOOGLE_SECOPS_INSTANCE='projects/PROJECT_ID/locations/LOCATION/instances/INSTANCE_ID'${NC}"
fi

function print_banner() {
    echo -e "${BLUE}"
    echo "╔═══════════════════════════════════════════════════════════════════════════════╗"
    echo "║                    Chronicle Content Manager - Enhanced                       ║"
    echo "║                    Engineering Officer's Implementation                       ║"
    echo "║                    Compatible with Google's Official Tools                    ║"
    echo "╚═══════════════════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

function usage() {
    print_banner
    cat << EOF
${GREEN}Chronicle Content Manager - Enhanced CLI${NC}

${BLUE}USAGE:${NC}
    $0 <command> [options]

${BLUE}COMMANDS:${NC}

${PURPLE}Rules Management:${NC}
    rules get                     - Download all rules from Chronicle to local files
    rules update                  - Upload/update rules from local files to Chronicle  
    rules verify [rule_file]      - Verify a single rule file
    rules verify-all              - Verify all local rule files
    rules test <rule_file>        - Test a rule without deploying
    rules deploy [rule_names]     - Deploy specific rules (comma-separated)
    rules enable <rule_ids>       - Enable specific rules (comma-separated)
    rules disable <rule_ids>      - Disable specific rules (comma-separated)

${PURPLE}Configuration Management:${NC}
    config export                 - Export current configuration to JSON
    config import <file>          - Import configuration from JSON file
    config validate               - Validate current configuration
    config show                   - Display current configuration

${PURPLE}Reporting & Analysis:${NC}
    report generate               - Generate comprehensive detection report
    report rules                  - Show local vs remote rule comparison
    report deployments            - Show rule deployment status
    report validate               - Validate all local rules

${PURPLE}Maintenance:${NC}
    auth test                     - Test Chronicle API authentication
    auth setup                    - Setup service account authentication
    logs show                     - Show recent log entries
    logs clear                    - Clear log file
    status                        - Show system status

${BLUE}OPTIONS:${NC}
    --region <region>             - Chronicle region (us, europe, asia, northamerica-northeast2)
    --config <file>               - Use custom configuration file
    --force                       - Force operation without confirmation
    --verbose                     - Enable verbose output
    --dry-run                     - Show what would be done without executing
    --help                        - Show this help message

${BLUE}EXAMPLES:${NC}
    # Download all rules from Chronicle
    $0 rules get

    # Upload local rules to Chronicle  
    $0 rules update

    # Verify all local rules
    $0 rules verify-all

    # Test a specific rule
    $0 rules test Admin_elevation.yaral

    # Deploy specific rules
    $0 rules deploy "Admin_elevation,Suspicious_login"

    # Generate comprehensive report
    $0 report generate

    # Test authentication
    $0 auth test

${BLUE}ENVIRONMENT VARIABLES:${NC}
    GOOGLE_SECOPS_INSTANCE        - Chronicle instance path
    GOOGLE_CLOUD_PROJECT          - Google Cloud project ID
    CHRONICLE_INSTANCE_ID         - Chronicle instance ID
    CHRONICLE_REGION              - Chronicle region override

EOF
}

function log() {
    local level=$1
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    case $level in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac
    
    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

function check_prerequisites() {
    log "INFO" "Checking prerequisites..."
    
    # Check Python
    if ! command -v python3 &> /dev/null; then
        log "ERROR" "Python 3 is required but not installed"
        exit 1
    fi
    
    # Check required Python packages
    if ! python3 -c "import requests, yaml, google.auth" 2>/dev/null; then
        log "WARN" "Required Python packages not found. Installing..."
        pip3 install -r "${SCRIPT_DIR}/requirements.txt" || {
            log "ERROR" "Failed to install Python dependencies"
            exit 1
        }
    fi
    
    # Check configuration file
    if [[ ! -f "$CONFIG_FILE" ]]; then
        log "ERROR" "Configuration file not found: $CONFIG_FILE"
        exit 1
    fi
    
    # Check service account file
    local sa_file=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['chronicle']['service_account_file'])" 2>/dev/null || echo "")
    if [[ -n "$sa_file" && ! -f "$sa_file" ]]; then
        log "ERROR" "Service account file not found: $sa_file"
        exit 1
    fi
    
    log "INFO" "Prerequisites check completed"
}

function test_authentication() {
    log "INFO" "Testing Chronicle API authentication..."
    
    python3 "$PYTHON_SCRIPT" --action auth_test \
        --config "$CONFIG_FILE" \
        ${REGION:+--region "$REGION"} \
        ${VERBOSE:+--verbose} || {
        log "ERROR" "Authentication test failed"
        return 1
    }
    
    log "INFO" "Authentication test successful"
}

function rules_get() {
    log "INFO" "Downloading all rules from Chronicle..."
    
    python3 "$PYTHON_SCRIPT" --action rules_get \
        --config "$CONFIG_FILE" \
        ${REGION:+--region "$REGION"} \
        ${VERBOSE:+--verbose} || {
        log "ERROR" "Failed to download rules"
        return 1
    }
    
    log "INFO" "Rules download completed"
}

function rules_update() {
    log "INFO" "Uploading local rules to Chronicle..."
    
    if [[ -z "${FORCE:-}" ]]; then
        echo -e "${YELLOW}This will update rules in Chronicle. Continue? (y/N)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "INFO" "Operation cancelled by user"
            return 0
        fi
    fi
    
    python3 "$PYTHON_SCRIPT" --action rules_update \
        --config "$CONFIG_FILE" \
        ${REGION:+--region "$REGION"} \
        ${VERBOSE:+--verbose} \
        ${FORCE:+--force} || {
        log "ERROR" "Failed to update rules"
        return 1
    }
    
    log "INFO" "Rules update completed"
}

function rules_verify() {
    local rule_file="${1:-}"
    
    if [[ -n "$rule_file" ]]; then
        log "INFO" "Verifying rule: $rule_file"
        
        python3 "$PYTHON_SCRIPT" --action verify_rule \
            --rule-file "$rule_file" \
            --config "$CONFIG_FILE" \
            ${REGION:+--region "$REGION"} \
            ${VERBOSE:+--verbose} || {
            log "ERROR" "Rule verification failed"
            return 1
        }
    else
        log "INFO" "Verifying all local rules..."
        
        python3 "$PYTHON_SCRIPT" \
            --credentials "$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['chronicle']['service_account_file'])")" \
            --region ${REGION:-northamerica-northeast2} \
            --detections-dir "../../rules/custom" \
            load || {
            log "ERROR" "Rule verification failed"
            return 1
        }
    fi
    
    log "INFO" "Rule verification completed"
}

function rules_test() {
    local rule_file="$1"
    
    if [[ -z "$rule_file" ]]; then
        log "ERROR" "Rule file required for testing"
        return 1
    fi
    
    log "INFO" "Testing rule: $rule_file"
    
    python3 "$PYTHON_SCRIPT" --action test_rule \
        --rule-file "$rule_file" \
        --config "$CONFIG_FILE" \
        ${REGION:+--region "$REGION"} \
        ${VERBOSE:+--verbose} || {
        log "ERROR" "Rule test failed"
        return 1
    }
    
    log "INFO" "Rule test completed"
}

function rules_deploy() {
    local rule_names="$1"
    
    log "INFO" "Deploying rules: ${rule_names:-all}"
    
    if [[ -z "${FORCE:-}" ]]; then
        echo -e "${YELLOW}This will deploy rules to Chronicle. Continue? (y/N)${NC}"
        read -r response
        if [[ ! "$response" =~ ^[Yy]$ ]]; then
            log "INFO" "Operation cancelled by user"
            return 0
        fi
    fi
    
    python3 "$PYTHON_SCRIPT" \
        --credentials "$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['chronicle']['service_account_file'])")" \
        --region ${REGION:-northamerica-northeast2} \
        --detections-dir "../../rules/custom" \
        deploy || {
        log "ERROR" "Rule deployment failed"
        return 1
    }
    
    log "INFO" "Rule deployment completed"
}

function rules_enable_disable() {
    local action="$1"
    local rule_ids="$2"
    
    if [[ -z "$rule_ids" ]]; then
        log "ERROR" "Rule IDs required for $action operation"
        return 1
    fi
    
    log "INFO" "${action^}ing rules: $rule_ids"
    
    python3 "$PYTHON_SCRIPT" --action "$action" \
        --rule-ids "$rule_ids" \
        --config "$CONFIG_FILE" \
        ${REGION:+--region "$REGION"} \
        ${VERBOSE:+--verbose} || {
        log "ERROR" "Failed to $action rules"
        return 1
    }
    
    log "INFO" "Rules ${action} completed"
}

function generate_report() {
    local report_type="$1"
    
    log "INFO" "Generating ${report_type:-comprehensive} report..."
    
    python3 "$PYTHON_SCRIPT" --action report \
        ${report_type:+--report-type "$report_type"} \
        --config "$CONFIG_FILE" \
        ${REGION:+--region "$REGION"} \
        ${VERBOSE:+--verbose} || {
        log "ERROR" "Report generation failed"
        return 1
    }
    
    log "INFO" "Report generation completed"
}

function show_status() {
    log "INFO" "Chronicle Content Manager Status"
    echo -e "${BLUE}═══════════════════════════════════════${NC}"
    
    # Configuration info
    if [[ -f "$CONFIG_FILE" ]]; then
        echo -e "${GREEN}✓${NC} Configuration file: $CONFIG_FILE"
    else
        echo -e "${RED}✗${NC} Configuration file: $CONFIG_FILE"
    fi
    
    # Service account info
    local sa_file=$(python3 -c "import yaml; print(yaml.safe_load(open('$CONFIG_FILE'))['chronicle']['service_account_file'])" 2>/dev/null || echo "")
    if [[ -n "$sa_file" && -f "$sa_file" ]]; then
        echo -e "${GREEN}✓${NC} Service account: $sa_file"
    else
        echo -e "${RED}✗${NC} Service account: ${sa_file:-not configured}"
    fi
    
    # Environment variables
    echo -e "${BLUE}Environment:${NC}"
    echo "  Region: ${CHRONICLE_REGION:-northamerica-northeast2}"
    echo "  Instance: ${GOOGLE_SECOPS_INSTANCE:-not set}"
    echo "  Project: ${GOOGLE_CLOUD_PROJECT:-not set}"
    
    # Local rules count
    local rules_dir="${SCRIPT_DIR}/../../rules/custom"
    if [[ -d "$rules_dir" ]]; then
        local rule_count=$(find "$rules_dir" -name "*.yaral" | wc -l)
        echo -e "${GREEN}✓${NC} Local rules: $rule_count"
    else
        echo -e "${YELLOW}!${NC} Local rules directory not found"
    fi
    
    # Authentication test
    echo -e "${BLUE}Testing authentication...${NC}"
    if test_authentication &>/dev/null; then
        echo -e "${GREEN}✓${NC} Chronicle API authentication"
    else
        echo -e "${RED}✗${NC} Chronicle API authentication"
    fi
}

# Parse command line arguments
COMMAND=""
SUBCOMMAND=""
ARG=""
REGION=""
FORCE=""
VERBOSE=""
DRY_RUN=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --region)
            REGION="$2"
            shift 2
            ;;
        --config)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --force)
            FORCE="1"
            shift
            ;;
        --verbose)
            VERBOSE="1"
            shift
            ;;
        --dry-run)
            DRY_RUN="1"
            shift
            ;;
        --help|-h)
            usage
            exit 0
            ;;
        *)
            if [[ -z "$COMMAND" ]]; then
                COMMAND="$1"
            elif [[ -z "$SUBCOMMAND" ]]; then
                SUBCOMMAND="$1"
            else
                ARG="$1"
            fi
            shift
            ;;
    esac
done

# Set region environment variable if provided
if [[ -n "$REGION" ]]; then
    export CHRONICLE_REGION="$REGION"
fi

# Main command handling
case "$COMMAND" in
    "rules")
        check_prerequisites
        case "$SUBCOMMAND" in
            "get")
                rules_get
                ;;
            "update")
                rules_update
                ;;
            "verify")
                rules_verify "$ARG"
                ;;
            "verify-all")
                rules_verify
                ;;
            "test")
                rules_test "$ARG"
                ;;
            "deploy")
                rules_deploy "$ARG"
                ;;
            "enable")
                rules_enable_disable "enable" "$ARG"
                ;;
            "disable")
                rules_enable_disable "disable" "$ARG"
                ;;
            *)
                log "ERROR" "Unknown rules subcommand: $SUBCOMMAND"
                usage
                exit 1
                ;;
        esac
        ;;
    "report")
        check_prerequisites
        case "$SUBCOMMAND" in
            "generate"|"")
                generate_report "comprehensive"
                ;;
            "rules")
                generate_report "rules"
                ;;
            "deployments")
                generate_report "deployments"
                ;;
            "validate")
                generate_report "validation"
                ;;
            *)
                log "ERROR" "Unknown report subcommand: $SUBCOMMAND"
                usage
                exit 1
                ;;
        esac
        ;;
    "auth")
        check_prerequisites
        case "$SUBCOMMAND" in
            "test")
                test_authentication
                ;;
            "setup")
                log "INFO" "Please refer to the setup documentation for service account configuration"
                ;;
            *)
                log "ERROR" "Unknown auth subcommand: $SUBCOMMAND"
                usage
                exit 1
                ;;
        esac
        ;;
    "status")
        show_status
        ;;
    "logs")
        case "$SUBCOMMAND" in
            "show")
                if [[ -f "$LOG_FILE" ]]; then
                    tail -n 50 "$LOG_FILE"
                else
                    log "INFO" "No log file found"
                fi
                ;;
            "clear")
                > "$LOG_FILE"
                log "INFO" "Log file cleared"
                ;;
            *)
                log "ERROR" "Unknown logs subcommand: $SUBCOMMAND"
                usage
                exit 1
                ;;
        esac
        ;;
    "")
        usage
        ;;
    *)
        log "ERROR" "Unknown command: $COMMAND"
        usage
        exit 1
        ;;
esac 