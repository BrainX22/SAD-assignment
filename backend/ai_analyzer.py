import os
import time
from dotenv import load_dotenv
import google.generativeai as genai
from pathlib import Path
import re
import concurrent.futures
from functools import partial

# Load environment variables
load_dotenv()

# Configure the Gemini API
genai.configure(api_key=os.getenv('GEMINI_API_KEY'))

def analyze_code(path, language="python"):
    """Analyze code in the given path for security vulnerabilities"""
    try:
        # Initialize Gemini model
        model = genai.GenerativeModel('gemini-1.0-pro')
        results = []

        # Find all files based on language
        if language == "python":
            files = list(Path(path).rglob("*.py"))
        else:  # javascript
            files = list(Path(path).rglob("*.js"))
            
        if not files:
            return [{
                "file": "info",
                "analysis": f"No {language} files found in the repository"
            }]

        # Process files in parallel
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
            analyze_file_partial = partial(analyze_single_file, model=model, language=language)
            future_to_file = {executor.submit(analyze_file_partial, file_path): file_path 
                            for file_path in files}
            
            for future in concurrent.futures.as_completed(future_to_file, timeout=30):
                file_path = future_to_file[future]
                try:
                    result = future.result(timeout=10)  # 10 second timeout per file
                    if result:
                        results.append(result)
                except concurrent.futures.TimeoutError:
                    print(f"Analysis timeout for {file_path}")
                    results.append({
                        "file": str(file_path),
                        "static_analysis": perform_static_analysis("", language),
                        "ai_analysis": "Analysis timed out. Please try again with a smaller codebase or contact support.",
                        "vulnerabilities_found": False
                    })
                except Exception as e:
                    print(f"Error analyzing {file_path}: {str(e)}")
                    results.append({
                        "file": str(file_path),
                        "static_analysis": perform_static_analysis("", language),
                        "ai_analysis": "Analysis failed. Please try again or contact support.",
                        "vulnerabilities_found": False
                    })

        return results if results else [{
            "file": "info",
            "analysis": f"No valid {language} files could be analyzed"
        }]

    except Exception as e:
        print(f"Error in code analysis: {str(e)}")
        return [{
            "file": "error",
            "analysis": f"Analysis failed: {str(e)}"
        }]

def analyze_single_file(file_path, model, language="python"):
    """Analyze a single file for security vulnerabilities"""
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            code = f.read()

        if not code.strip():
            return None

        # First, do a quick static analysis for common vulnerabilities
        static_analysis = perform_static_analysis(code, language)
        
        # Then use AI for deeper analysis
        prompt = f"""
        As a security code auditor, analyze this {language} code for security vulnerabilities and provide a structured response.
        Focus on identifying specific security issues, their severity, and recommended fixes.

        Code from {file_path.name}:
        ```{language}
        {code}
        ```

        Provide your analysis in the following format:
        1. Critical Vulnerabilities (if any)
        2. High Severity Issues (if any)
        3. Medium Severity Issues (if any)
        4. Low Severity Issues (if any)
        5. Best Practice Recommendations

        For each issue found, specify:
        - The line number or code section
        - The vulnerability type
        - Potential impact
        - Recommended fix
        """

        try:
            response = model.generate_content(prompt)
            
            if hasattr(response, 'text'):
                return {
                    "file": str(file_path),
                    "static_analysis": static_analysis,
                    "ai_analysis": response.text,
                    "vulnerabilities_found": bool(static_analysis.get("vulnerabilities", []))
                }
            else:
                recommendations = generate_vulnerability_recommendations(static_analysis, language)
                return {
                    "file": str(file_path),
                    "static_analysis": static_analysis,
                    "ai_analysis": recommendations,
                    "vulnerabilities_found": bool(static_analysis.get("vulnerabilities", []))
                }

        except Exception as analysis_error:
            print(f"Error analyzing {file_path}: {str(analysis_error)}")
            recommendations = generate_vulnerability_recommendations(static_analysis, language)
            return {
                "file": str(file_path),
                "static_analysis": static_analysis,
                "ai_analysis": recommendations,
                "vulnerabilities_found": bool(static_analysis.get("vulnerabilities", []))
            }

    except Exception as file_error:
        print(f"Error reading {file_path}: {str(file_error)}")
        return {
            "file": str(file_path),
            "analysis": f"File reading error: {str(file_error)}",
            "vulnerabilities_found": False
        }

def perform_static_analysis(code, language="python"):
    """Perform static analysis on the code"""
    vulnerabilities = []
    
    if language == "python":
        # Python-specific checks
        dangerous_functions = {
            "eval": "Use of eval() can lead to code injection",
            "exec": "Use of exec() can lead to code injection",
            "os.system": "Use of os.system() can lead to command injection",
            "subprocess.call": "Use of subprocess.call() with shell=True can lead to command injection",
            "pickle.loads": "Use of pickle.loads() can lead to code injection",
            "yaml.load": "Use of yaml.load() can lead to code injection",
            "marshal.loads": "Use of marshal.loads() can lead to code injection"
        }
        
        for func, desc in dangerous_functions.items():
            if func in code:
                line_numbers = [i+1 for i, line in enumerate(code.split('\n')) if func in line]
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": desc,
                    "line_numbers": line_numbers
                })
        
        # Check for hardcoded credentials
        credential_patterns = [
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded password detected"),
            (r'api_key\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded API key detected"),
            (r'secret\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded secret detected")
        ]
        
        for pattern, desc in credential_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": desc,
                    "line_number": line_number
                })
        
        # Check for unsafe file operations
        unsafe_file_patterns = [
            (r'open\([^,]+,\s*[\'"]w[\'"]\)', "Unsafe file write operation"),
            (r'open\([^,]+,\s*[\'"]a[\'"]\)', "Unsafe file append operation")
        ]
        
        for pattern, desc in unsafe_file_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    "severity": "High",
                    "description": desc,
                    "line_number": line_number
                })
    
    else:  # JavaScript
        # JavaScript-specific checks
        dangerous_functions = {
            "eval": "Use of eval() can lead to code injection",
            "Function": "Use of Function constructor can lead to code injection",
            "setTimeout": "Use of setTimeout with string argument can lead to code injection",
            "setInterval": "Use of setInterval with string argument can lead to code injection"
        }
        
        for func, desc in dangerous_functions.items():
            if func in code:
                line_numbers = [i+1 for i, line in enumerate(code.split('\n')) if func in line]
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": desc,
                    "line_numbers": line_numbers
                })
        
        # Check for hardcoded credentials
        credential_patterns = [
            (r'password\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded password detected"),
            (r'apiKey\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded API key detected"),
            (r'secret\s*=\s*[\'"][^\'"]+[\'"]', "Hardcoded secret detected")
        ]
        
        for pattern, desc in credential_patterns:
            matches = re.finditer(pattern, code, re.IGNORECASE)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    "severity": "Critical",
                    "description": desc,
                    "line_number": line_number
                })
        
        # Check for unsafe DOM operations
        unsafe_dom_patterns = [
            (r'document\.write\s*\(', "Unsafe DOM manipulation using document.write"),
            (r'innerHTML\s*=', "Unsafe DOM manipulation using innerHTML"),
            (r'outerHTML\s*=', "Unsafe DOM manipulation using outerHTML")
        ]
        
        for pattern, desc in unsafe_dom_patterns:
            matches = re.finditer(pattern, code)
            for match in matches:
                line_number = code[:match.start()].count('\n') + 1
                vulnerabilities.append({
                    "severity": "High",
                    "description": desc,
                    "line_number": line_number
                })

    return {
        "vulnerabilities": vulnerabilities,
        "total_vulnerabilities": len(vulnerabilities)
    }

def generate_vulnerability_recommendations(static_analysis, language="python"):
    """Generate specific recommendations based on found vulnerabilities"""
    if not static_analysis or not static_analysis.get("vulnerabilities"):
        return ""  # Return empty string if no vulnerabilities found

    recommendations = []
    vulnerabilities = static_analysis["vulnerabilities"]

    for vuln in vulnerabilities:
        severity = vuln.get("severity", "").lower()
        description = vuln.get("description", "")
        
        if language == "python":
            if "eval" in description.lower() or "exec" in description.lower():
                recommendations.append(
                    f"Critical: Code injection vulnerability detected. "
                    f"Replace eval()/exec() with safer alternatives like ast.literal_eval() "
                    f"or implement proper input validation and sanitization."
                )
            
            if "sql" in description.lower() and "injection" in description.lower():
                recommendations.append(
                    f"Critical: SQL injection vulnerability detected. "
                    f"Use parameterized queries or an ORM to prevent SQL injection attacks."
                )
            
            if "file" in description.lower() and "write" in description.lower():
                recommendations.append(
                    f"High: Unsafe file operation detected. "
                    f"Implement proper file path validation and use secure file handling practices."
                )
            
            if "hardcoded" in description.lower() and "credential" in description.lower():
                recommendations.append(
                    f"Critical: Hardcoded credentials detected. "
                    f"Move sensitive information to environment variables or a secure configuration management system."
                )
            
            if "input" in description.lower() and "validation" in description.lower():
                recommendations.append(
                    f"Medium: Input validation issue detected. "
                    f"Implement comprehensive input validation and sanitization for all user inputs."
                )
        else:  # JavaScript
            if "eval" in description.lower() or "function" in description.lower():
                recommendations.append(
                    f"Critical: Code injection vulnerability detected. "
                    f"Avoid using eval() or the Function constructor. Use safer alternatives or implement proper input validation."
                )
            
            if "dom" in description.lower() and "manipulation" in description.lower():
                recommendations.append(
                    f"High: Unsafe DOM manipulation detected. "
                    f"Avoid using innerHTML/outerHTML with untrusted input. Use textContent or DOMPurify for sanitization."
                )
            
            if "hardcoded" in description.lower() and "credential" in description.lower():
                recommendations.append(
                    f"Critical: Hardcoded credentials detected. "
                    f"Move sensitive information to environment variables or a secure configuration management system."
                )
            
            if "xss" in description.lower():
                recommendations.append(
                    f"Critical: Cross-Site Scripting (XSS) vulnerability detected. "
                    f"Implement proper input sanitization and use Content Security Policy (CSP) headers."
                )

    return "\n\n".join(recommendations) if recommendations else ""