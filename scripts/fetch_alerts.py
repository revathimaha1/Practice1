import requests
from bs4 import BeautifulSoup

from packaging import secrets
# Replace with your actual personal access token
github_token = secrets.environ_get("GITHUB_TOKEN")



# Replace with your desired repository owner and name
repo_owner = "revathimaha1"
repo_name = "Practice1"

# Vulnerability severity threshold
severity_threshold = "High"

# Exploitability likelihood threshold
exploitability_threshold = "High"


def get_code_scanning_alerts(github_token, repo_owner, repo_name):
    """
    Fetches code scanning alerts from GitHub Advanced Security.

    Args:
        github_token (str): Personal access token with read access to security alerts.
        repo_owner (str): Owner of the repository.
        repo_name (str): Name of the repository.

    Returns:
        list: List of dictionaries containing alert information.
    """

    headers = {"Authorization": f"token {github_token}"}
    url = f"https://api.github.com/repos/{repo_owner}/{repo_name}/code-scanning/alerts"

    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        return response.json()
    else:
        print(f"Error fetching alerts: {response.status_code}")
        return []


def get_exploitability(cwe_id):
    """
    Fetches exploitability information from MITRE CWE website.

    Args:
        cwe_id (str): The CWE ID of the vulnerability.

    Returns:
        str: The likelihood of exploitability (if found), otherwise None.
    """

    url = f"https://cwe.mitre.org/data/definitions/{cwe_id}.html"
    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        exploitability_text = soup.find("th", text="Likelihood of Exploitability").find_next_sibling("td").text.strip()
        return exploitability_text
    else:
        print(f"Error fetching exploitability for CWE-{cwe_id}: {response.status_code}")
        return None


def main():
    alerts = get_code_scanning_alerts(github_token, repo_owner, repo_name)

    high_severity_alerts = []

    for alert in alerts:
        if alert["severity"] >= severity_threshold:
            cwe_id = alert["instances"][0]["location"]["snippet"]["lines"][0]["content"].split()[0]
            exploitability = get_exploitability(cwe_id)

            if exploitability is not None and exploitability >= exploitability_threshold:
                high_severity_alerts.append(
                    {
                        "message": alert["message"],
                        "severity": alert["severity"],
                        "cwe_id": cwe_id,
                        "exploitability": exploitability,
                    }
                )

    if high_severity_alerts:
        print("Vulnerabilities with High severity and High exploitability:")
        for alert in high_severity_alerts:
            print(f"\t- {alert['message']}")
            print(f"\t\tSeverity: {alert['severity']}")
            print(f"\t\tCWE ID: {alert['cwe_id']}")
            print(f"\t\tExploitability: {alert['exploitability']}")
    else:
        print("No vulnerabilities found with High severity and High exploitability.")


if __name__ == "__main__":
    main()
