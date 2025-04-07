import tempfile
import git
import re
import os
from urllib.parse import urlparse

def clean_github_url(url):
    """Clean and validate GitHub URL"""
    try:
        # Parse the URL
        parsed = urlparse(url)
        
        # Check if it's a GitHub URL
        if 'github.com' not in parsed.netloc:
            raise ValueError("Not a valid GitHub URL")
            
        # Remove /tree/master or /tree/main and everything after
        url = re.sub(r'/tree/[^/]+/.*$', '', url)
        # Remove trailing slash
        url = url.rstrip('/')
        
        # Validate repository format
        if not re.match(r'https://github\.com/[^/]+/[^/]+$', url):
            raise ValueError("Invalid GitHub repository URL format")
            
        return url
    except Exception as e:
        raise ValueError(f"Invalid GitHub URL: {str(e)}")

def clone_repo(repo_url):
    """Clone a GitHub repository to a temporary directory"""
    temp_dir = tempfile.mkdtemp()
    try:
        # Clean and validate the URL before cloning
        clean_url = clean_github_url(repo_url)
        
        # Clone the repository
        repo = git.Repo.clone_from(clean_url, temp_dir)
        
        # Verify repository was cloned successfully
        if not os.path.exists(temp_dir) or not os.listdir(temp_dir):
            raise Exception("Repository clone failed - directory is empty")
            
        return temp_dir
    except git.exc.GitCommandError as e:
        raise Exception(f"Git clone failed: {str(e)}")
    except Exception as e:
        raise Exception(f"Failed to clone repository: {str(e)}")