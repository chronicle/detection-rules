#!/usr/bin/env python3
"""
Chronicle Custom Detection Bulk Management Tool

This tool provides comprehensive management capabilities for Chronicle SIEM custom detections.
Author: Engineering Team
"""

import os
import json
import yaml
import argparse
import logging
import time
from typing import List, Dict, Optional, Tuple
from pathlib import Path
import requests
from dataclasses import dataclass
from datetime import datetime
import re
from google.auth.transport.requests import Request
from google.oauth2 import service_account

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('chronicle_detection_manager.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

@dataclass
class DetectionRule:
    """Data class representing a Chronicle detection rule"""
    name: str
    file_path: str
    content: str
    enabled: bool = True
    severity: Optional[str] = None
    author: Optional[str] = None
    description: Optional[str] = None
    rule_id: Optional[str] = None

class ChronicleAPI:
    """Chronicle SIEM API client with enhanced error handling and regional support"""
    
    def __init__(self, credentials_file: str, region: str = "us"):
        self.credentials_file = credentials_file
        self.region = region
        self.credentials = None
        self.session = None
        
        # Regional endpoint mapping based on Google's official implementation
        self.regional_endpoints = {
            "us": "https://us-chronicle.googleapis.com/v1alpha",
            "europe": "https://eu-chronicle.googleapis.com/v1alpha", 
            "asia": "https://asia-southeast1-chronicle.googleapis.com/v1alpha",
            "northamerica-northeast2": "https://northamerica-northeast2-chronicle.googleapis.com/v1alpha"
        }
        
        self.upload_endpoints = {
            "us": "https://us-chronicle.googleapis.com/upload/v1alpha",
            "europe": "https://eu-chronicle.googleapis.com/upload/v1alpha",
            "asia": "https://asia-southeast1-chronicle.googleapis.com/upload/v1alpha", 
            "northamerica-northeast2": "https://northamerica-northeast2-chronicle.googleapis.com/upload/v1alpha"
        }
        
        self.base_url = self.regional_endpoints.get(region, self.regional_endpoints["us"])
        self.upload_url = self.upload_endpoints.get(region, self.upload_endpoints["us"])
        
        # Get instance path from environment or construct it
        self.instance = os.environ.get('GOOGLE_SECOPS_INSTANCE', self._construct_instance_path())
        
        self._authenticate()
    
    def _construct_instance_path(self) -> str:
        """Construct instance path following Google's pattern"""
        project_id = os.environ.get('GOOGLE_CLOUD_PROJECT', 'siem-production-2')
        location = self.region
        instance_id = os.environ.get('CHRONICLE_INSTANCE_ID', '87bb0359-c967-420b-952c-3956c9bdc3d3')
        
        return f"projects/{project_id}/locations/{location}/instances/{instance_id}"
    
    def _authenticate(self):
        """Enhanced authentication with better error handling"""
        try:
            self.credentials = service_account.Credentials.from_service_account_file(
                self.credentials_file,
                scopes=['https://www.googleapis.com/auth/cloud-platform']
            )
            
            # Create authorized session
            self.session = requests.Session()
            self.credentials.refresh(Request())
            
            logger.info(f"Successfully authenticated with Chronicle API (Region: {self.region})")
            
        except Exception as e:
            logger.error(f"Authentication failed: {str(e)}")
            raise
    
    def _make_request(self, method: str, endpoint: str, data: Dict = None, max_retries: int = 3) -> requests.Response:
        """Make HTTP request with retry logic and proper error handling"""
        if not self.credentials.valid:
            self.credentials.refresh(Request())
        
        headers = {
            'Authorization': f'Bearer {self.credentials.token}',
            'Content-Type': 'application/json'
        }
        
        url = f"{self.base_url}/{self.instance}/{endpoint}"
        
        for attempt in range(max_retries + 1):
            try:
                if method.upper() == 'GET':
                    response = self.session.get(url, headers=headers, timeout=30)
                elif method.upper() == 'POST':
                    response = self.session.post(url, headers=headers, json=data, timeout=30)
                elif method.upper() == 'PATCH':
                    response = self.session.patch(url, headers=headers, json=data, timeout=30)
                elif method.upper() == 'DELETE':
                    response = self.session.delete(url, headers=headers, timeout=30)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Handle rate limiting
                if response.status_code == 429:
                    if attempt < max_retries:
                        wait_time = 60 * (attempt + 1)  # Exponential backoff
                        logger.warning(f"Rate limit hit, waiting {wait_time}s... (attempt {attempt + 1})")
                        time.sleep(wait_time)
                        continue
                
                return response
                
            except requests.exceptions.RequestException as e:
                if attempt < max_retries:
                    logger.warning(f"Request failed, retrying... (attempt {attempt + 1}): {str(e)}")
                    time.sleep(5)
                else:
                    raise
        
        return response
    
    def verify_rule(self, rule_text: str) -> Tuple[bool, Dict]:
        """Verify rule using Chronicle's native verification API"""
        try:
            response = self._make_request('POST', 'rules:verify', {'text': rule_text})
            
            if response.status_code == 200:
                result = response.json()
                return result.get("success", False), result
            else:
                logger.error(f"Rule verification failed: {response.text}")
                return False, {"error": response.text}
                
        except Exception as e:
            logger.error(f"Rule verification exception: {str(e)}")
            return False, {"error": str(e)}
    
    def list_detections(self) -> List[Dict]:
        """List all detection rules from Chronicle with enhanced error handling"""
        try:
            response = self._make_request('GET', 'rules')
            
            if response.status_code == 200:
                data = response.json()
                rules = data.get('rules', [])
                logger.info(f"Retrieved {len(rules)} rules from Chronicle")
                return rules
            else:
                logger.error(f"Failed to list detections: {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error listing detections: {str(e)}")
            return []
    
    def get_rule_deployments(self) -> List[Dict]:
        """Get rule deployment states (enabled/disabled status)"""
        try:
            response = self._make_request('GET', 'rules:listDeployments')
            
            if response.status_code == 200:
                data = response.json()
                deployments = data.get('ruleDeployments', [])
                logger.info(f"Retrieved {len(deployments)} rule deployments")
                return deployments
            else:
                logger.error(f"Failed to get deployments: {response.text}")
                return []
                
        except Exception as e:
            logger.error(f"Error getting deployments: {str(e)}")
            return []

    def create_detection(self, rule_content: str, skip_verification: bool = False) -> Dict:
        """Create new detection rule with improved error handling"""
        try:
            # First verify the rule unless skipping verification
            if not skip_verification:
                is_valid, verification_result = self.verify_rule(rule_content)
                if not is_valid:
                    # Check if it's a 404 error (verification endpoint not available)
                    error_msg = str(verification_result.get('error', ''))
                    if '404' in error_msg:
                        logger.warning("Rule verification endpoint not available (404), proceeding without verification")
                    else:
                        raise ValueError(f"Rule verification failed: {verification_result}")
            
            response = self._make_request('POST', 'rules', {'text': rule_content})
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Successfully created rule: {result.get('ruleId')}")
                return result
            else:
                raise Exception(f"Failed to create rule: {response.text}")
                
        except Exception as e:
            logger.error(f"Error creating detection: {str(e)}")
            raise

    def update_rule_deployment(self, resource_name: str, updates: Dict, update_mask: List[str]) -> Dict:
        """Update rule deployment state (enable/disable/archive)"""
        try:
            url = f"{self.base_url}/{resource_name}/deployment"
            
            if not self.credentials.valid:
                self.credentials.refresh(Request())
            
            headers = {
                'Authorization': f'Bearer {self.credentials.token}',
                'Content-Type': 'application/json'
            }
            
            params = {"updateMask": update_mask}
            
            response = self.session.patch(url, headers=headers, params=params, json=updates, timeout=30)
            
            if response.status_code == 200:
                result = response.json()
                logger.info(f"Successfully updated rule deployment: {resource_name}")
                return result
            else:
                raise Exception(f"Failed to update deployment: {response.text}")
                
        except Exception as e:
            logger.error(f"Error updating deployment: {str(e)}")
            raise

class DetectionManager:
    """Main class for managing Chronicle detections"""
    
    def __init__(self, detections_dir: str, credentials_file: str, region: str = "us"):
        """
        Initialize Detection Manager
        
        Args:
            detections_dir: Directory containing detection rule files
            credentials_file: Path to service account JSON file
            region: Chronicle region
        """
        self.detections_dir = Path(detections_dir)
        self.chronicle_api = ChronicleAPI(credentials_file, region)
        self.local_rules: List[DetectionRule] = []
        
    def load_local_rules(self) -> List[DetectionRule]:
        """Load all detection rules from local directory"""
        rules = []
        
        # Search for .yaral files in all subdirectories under the detections_dir
        for file_path in self.detections_dir.rglob("*.yaral"):
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse metadata from rule content
                metadata = self._parse_rule_metadata(content)
                
                rule = DetectionRule(
                    name=file_path.stem,
                    file_path=str(file_path),
                    content=content,
                    severity=metadata.get('severity'),
                    author=metadata.get('author'),
                    description=metadata.get('description')
                )
                
                rules.append(rule)
                
            except Exception as e:
                logger.error(f"Error loading rule from {file_path}: {str(e)}")
        
        self.local_rules = rules
        logger.info(f"Loaded {len(rules)} local detection rules")
        return rules
    
    def _parse_rule_metadata(self, rule_content: str) -> Dict:
        """Parse metadata from YARAL rule content"""
        metadata = {}
        
        # Extract metadata using regex
        patterns = {
            'author': r'author\s*=\s*"([^"]+)"',
            'description': r'description\s*=\s*"([^"]+)"',
            'severity': r'severity\s*=\s*"([^"]+)"',
            'mitre_attack': r'mitre_attack\s*=\s*"([^"]+)"'
        }
        
        for key, pattern in patterns.items():
            match = re.search(pattern, rule_content, re.IGNORECASE)
            if match:
                metadata[key] = match.group(1)
        
        return metadata
    
    def validate_rule_syntax(self, rule_content: str) -> Tuple[bool, str]:
        """Validate YARAL rule syntax"""
        try:
            # Basic syntax validation - allow for copyright headers
            content_lines = [line.strip() for line in rule_content.split('\n') if line.strip()]
            rule_start_found = False
            for line in content_lines:
                if line.startswith('rule '):
                    rule_start_found = True
                    break
                elif not (line.startswith('/*') or line.startswith('*') or line.startswith('*/') or line.startswith('//')):
                    # If it's not a comment and not a rule start, it's invalid
                    if not rule_start_found:
                        return False, "Rule must contain 'rule' keyword (comments allowed before rule)"
            
            if not rule_start_found:
                return False, "Rule must contain 'rule' keyword"
            
            # Check for required sections
            required_sections = ['meta:', 'events:', 'condition:']
            for section in required_sections:
                if section not in rule_content:
                    return False, f"Missing required section: {section}"
            
            # Check for balanced braces
            open_braces = rule_content.count('{')
            close_braces = rule_content.count('}')
            if open_braces != close_braces:
                return False, f"Mismatched braces: {open_braces} open, {close_braces} close"
            
            logger.info("Rule syntax validation passed")
            return True, "Valid"
            
        except Exception as e:
            return False, f"Validation error: {str(e)}"
    
    def deploy_rules(self, rule_names: Optional[List[str]] = None, force: bool = False) -> Dict:
        """Deploy detection rules to Chronicle"""
        results = {"successful": [], "failed": []}
        
        rules_to_deploy = self.local_rules
        if rule_names:
            rules_to_deploy = [r for r in self.local_rules if r.name in rule_names]
        
        for rule in rules_to_deploy:
            try:
                # Validate rule before deployment
                is_valid, validation_msg = self.validate_rule_syntax(rule.content)
                if not is_valid and not force:
                    logger.error(f"Skipping {rule.name}: {validation_msg}")
                    results["failed"].append({"name": rule.name, "error": validation_msg})
                    continue
                
                # Try to create new rule
                try:
                    result = self.chronicle_api.create_detection(rule.content)
                    results["successful"].append({"name": rule.name, "rule_id": result.get("ruleId")})
                except ValueError as ve:
                    # If verification fails due to 404, try again without verification
                    if "Rule verification failed" in str(ve) and "404" in str(ve):
                        logger.warning(f"Retrying {rule.name} without verification due to 404 error")
                        result = self.chronicle_api.create_detection(rule.content, skip_verification=True)
                        results["successful"].append({"name": rule.name, "rule_id": result.get("ruleId")})
                    else:
                        raise ve
                
            except Exception as e:
                error_msg = str(e)
                logger.error(f"Failed to deploy {rule.name}: {error_msg}")
                results["failed"].append({"name": rule.name, "error": error_msg})
        
        return results
    
    def bulk_enable_disable(self, action: str, rule_ids: List[str]) -> Dict:
        """Bulk enable or disable detection rules"""
        results = {"successful": [], "failed": []}
        
        for rule_id in rule_ids:
            try:
                if action.lower() == "enable":
                    success = self.chronicle_api.update_rule_deployment(rule_id, {"state": "ENABLED"}, ["state"])
                elif action.lower() == "disable":
                    success = self.chronicle_api.update_rule_deployment(rule_id, {"state": "DISABLED"}, ["state"])
                else:
                    raise ValueError(f"Invalid action: {action}")
                
                if success:
                    results["successful"].append(rule_id)
                else:
                    results["failed"].append({"rule_id": rule_id, "error": "Operation failed"})
                    
            except Exception as e:
                results["failed"].append({"rule_id": rule_id, "error": str(e)})
        
        return results
    
    def export_configuration(self, output_file: str):
        """Export current detection configuration to JSON"""
        try:
            remote_rules = self.chronicle_api.list_detections()
            
            config = {
                "export_date": datetime.now().isoformat(),
                "local_rules": [
                    {
                        "name": rule.name,
                        "file_path": rule.file_path,
                        "severity": rule.severity,
                        "author": rule.author,
                        "description": rule.description
                    }
                    for rule in self.local_rules
                ],
                "remote_rules": remote_rules
            }
            
            with open(output_file, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"Configuration exported to {output_file}")
            
        except Exception as e:
            logger.error(f"Error exporting configuration: {str(e)}")
    
    def generate_report(self) -> Dict:
        """Generate a comprehensive detection report"""
        try:
            remote_rules = self.chronicle_api.list_detections()
            
            report = {
                "summary": {
                    "local_rules_count": len(self.local_rules),
                    "remote_rules_count": len(remote_rules),
                    "report_date": datetime.now().isoformat()
                },
                "local_rules": [
                    {
                        "name": rule.name,
                        "severity": rule.severity,
                        "author": rule.author,
                        "description": rule.description,
                        "file_size": os.path.getsize(rule.file_path)
                    }
                    for rule in self.local_rules
                ],
                "remote_rules_summary": {
                    "total": len(remote_rules),
                    "enabled": len([r for r in remote_rules if r.get("state") == "ENABLED"]),
                    "disabled": len([r for r in remote_rules if r.get("state") == "DISABLED"])
                }
            }
            
            return report
            
        except Exception as e:
            logger.error(f"Error generating report: {str(e)}")
            return {}

def main():
    """Main CLI interface"""
    parser = argparse.ArgumentParser(description="Chronicle Custom Detection Bulk Manager")
    
    parser.add_argument(
        "--detections-dir",
        default="./Custom Detections",
        help="Directory containing detection rule files"
    )
    
    parser.add_argument(
        "--credentials",
        required=True,
        help="Path to Chronicle service account JSON file"
    )
    
    parser.add_argument(
        "--region",
        default="us",
        choices=["us", "europe", "asia", "northamerica-northeast2"],
        help="Chronicle region"
    )
    
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Load command
    load_parser = subparsers.add_parser("load", help="Load and validate local rules")
    
    # Deploy command
    deploy_parser = subparsers.add_parser("deploy", help="Deploy rules to Chronicle")
    deploy_parser.add_argument("--rules", nargs="*", help="Specific rules to deploy")
    deploy_parser.add_argument("--force", action="store_true", help="Force deployment even if validation fails")
    
    # Enable/Disable commands
    enable_parser = subparsers.add_parser("enable", help="Enable detection rules")
    enable_parser.add_argument("rule_ids", nargs="+", help="Rule IDs to enable")
    
    disable_parser = subparsers.add_parser("disable", help="Disable detection rules")
    disable_parser.add_argument("rule_ids", nargs="+", help="Rule IDs to disable")
    
    # Export command
    export_parser = subparsers.add_parser("export", help="Export configuration")
    export_parser.add_argument("--output", default="chronicle_config.json", help="Output file")
    
    # Report command
    report_parser = subparsers.add_parser("report", help="Generate detection report")
    report_parser.add_argument("--output", default="chronicle_report.json", help="Output file")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    try:
        manager = DetectionManager(args.detections_dir, args.credentials, args.region)
        
        if args.command == "load":
            rules = manager.load_local_rules()
            print(f"Loaded {len(rules)} local detection rules")
            for rule in rules:
                print(f"  - {rule.name} ({rule.severity or 'Unknown severity'})")
        
        elif args.command == "deploy":
            manager.load_local_rules()
            results = manager.deploy_rules(args.rules, args.force)
            
            print(f"Deployment Results:")
            print(f"  Successful: {len(results['successful'])}")
            print(f"  Failed: {len(results['failed'])}")
            
            if results["failed"]:
                print("\nFailed deployments:")
                for failure in results["failed"]:
                    print(f"  - {failure['name']}: {failure['error']}")
        
        elif args.command == "enable":
            results = manager.bulk_enable_disable("enable", args.rule_ids)
            print(f"Enabled {len(results['successful'])} rules")
            if results["failed"]:
                print(f"Failed to enable {len(results['failed'])} rules")
        
        elif args.command == "disable":
            results = manager.bulk_enable_disable("disable", args.rule_ids)
            print(f"Disabled {len(results['successful'])} rules")
            if results["failed"]:
                print(f"Failed to disable {len(results['failed'])} rules")
        
        elif args.command == "export":
            manager.load_local_rules()
            manager.export_configuration(args.output)
            print(f"Configuration exported to {args.output}")
        
        elif args.command == "report":
            manager.load_local_rules()
            report = manager.generate_report()
            
            with open(args.output, 'w') as f:
                json.dump(report, f, indent=2)
            
            print(f"Report generated: {args.output}")
            print(f"Local rules: {report['summary']['local_rules_count']}")
            print(f"Remote rules: {report['summary']['remote_rules_count']}")
    
    except Exception as e:
        logger.error(f"Command failed: {str(e)}")
        exit(1)

if __name__ == "__main__":
    main()