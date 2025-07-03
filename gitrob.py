import argparse
import re
from github import Github, GithubException

# Common sensitive filename patterns
SENSITIVE_PATTERNS = [
    r'\.env$', r'id_rsa$', r'\.pem$', r'config\.php$', r'credentials\.json$', r'\.aws/credentials',
    r'\.htpasswd$', r'\.htaccess$', r'\.key$', r'wp-config\.php$', r'\.p12$', r'\.crt$', r'passwd$', r'\.dockercfg$'
]

def is_sensitive(filename):
    return any(re.search(pattern, filename, re.IGNORECASE) for pattern in SENSITIVE_PATTERNS)

def scan_repo_files(repo, path=""):
    try:
        contents = repo.get_contents(path)
        while contents:
            file_content = contents.pop(0)
            if file_content.type == "dir":
                contents.extend(repo.get_contents(file_content.path))
            else:
                if is_sensitive(file_content.name):
                    print(f"    [!] Sensitive file found: {file_content.path}")
    except GithubException as e:
        print(f"    [x] Failed to scan {repo.name} - {e.data.get('message')}")

def scan_user_repos(token, target):
    g = Github(token)
    try:
        # Try as user
        user = g.get_user(target)
        print(f"[+] Scanning public repos of user/org: {target}")
    except GithubException as e:
        print(f"[x] Error: Could not find user/org '{target}': {e.data.get('message')}")
        return

    for repo in user.get_repos():
        print(f"  [-] Repo: {repo.full_name}")
        scan_repo_files(repo)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Python version of Gitrob")
    parser.add_argument("target", help="GitHub username or organization")
    parser.add_argument("--token", required=True, help="GitHub personal access token")
    args = parser.parse_args()

    scan_user_repos(args.token, args.target)
