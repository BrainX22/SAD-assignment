import re
from packaging import version
import requests
import json
import os
from pathlib import Path

def parse_requirements(requirements_path):
    """Parse requirements.txt to extract package names and versions"""
    dependencies = {}
    with open(requirements_path, 'r') as file:
        for line in file:
            # Skip empty lines and comments
            if line.strip() and not line.startswith('#'):
                # Split package name and version
                parts = re.split('==|>=|<=|~=|!=', line.strip())
                package_name = parts[0].strip()
                version_num = parts[1].strip() if len(parts) > 1 else None
                dependencies[package_name] = version_num
    return dependencies

def check_cve_vulnerabilities(package_name, package_version):
    """Check NVD database for known vulnerabilities"""
    api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": package_name,
        "keywordExactMatch": True
    }
    
    response = requests.get(api_url, params=params)
    if response.status_code == 200:
        vulnerabilities = []
        data = response.json()
        
        for cve in data.get('vulnerabilities', []):
            cve_data = cve['cve']
            affected_versions = []
            
            # Parse CVE data for affected versions
            if 'configurations' in cve_data:
                for config in cve_data['configurations']:
                    if 'nodes' in config:
                        for node in config['nodes']:
                            if 'cpeMatch' in node:
                                for cpe in node['cpeMatch']:
                                    if package_name.lower() in cpe['criteria'].lower():
                                        affected_versions.append({
                                            'version_range': cpe.get('versionStartIncluding', ''),
                                            'version_end': cpe.get('versionEndIncluding', '')
                                        })
            
            vulnerabilities.append({
                'cve_id': cve_data['id'],
                'description': cve_data.get('descriptions', [{}])[0].get('value', ''),
                'severity': cve_data.get('metrics', {}).get('baseMetricV3', {}).get('cvssV3', {}).get('baseScore', 'N/A'),
                'affected_versions': affected_versions
            })
            
        return vulnerabilities
    return []

def check_dependencies(repo_path, language="python"):
    """Check dependencies for vulnerabilities based on the language"""
    vulnerabilities = []
    
    if language == "python":
        # Look for requirements.txt
        requirements_path = os.path.join(repo_path, "requirements.txt")
        if os.path.exists(requirements_path):
            dependencies = parse_requirements(requirements_path)
            for package, version in dependencies.items():
                package_vulnerabilities = check_cve_vulnerabilities(package, version)
                if package_vulnerabilities:
                    vulnerabilities.append({
                        "package": package,
                        "version": version or "unknown",
                        "vulnerabilities": package_vulnerabilities
                    })
    else:  # JavaScript
        # Look for package.json
        package_json_path = os.path.join(repo_path, "package.json")
        if os.path.exists(package_json_path):
            try:
                with open(package_json_path, 'r') as f:
                    package_data = json.load(f)
                
                # Check dependencies
                dependencies = {}
                if "dependencies" in package_data:
                    dependencies.update(package_data["dependencies"])
                if "devDependencies" in package_data:
                    dependencies.update(package_data["devDependencies"])
                
                for package, version in dependencies.items():
                    # Remove version prefix (^, ~, etc.)
                    clean_version = re.sub(r'^[\^~]', '', version)
                    package_vulnerabilities = check_cve_vulnerabilities(package, clean_version)
                    if package_vulnerabilities:
                        vulnerabilities.append({
                            "package": package,
                            "version": version,
                            "vulnerabilities": package_vulnerabilities
                        })
            except Exception as e:
                print(f"Error parsing package.json: {str(e)}")
    
    return vulnerabilities