import requests
from bs4 import BeautifulSoup

def scan_website(url):
    vulnerabilities = []
    autofill_data = {
        "title": "Website Vulnerability Report",
        "description": "",
        "priority": "Low",
        "category": "Web Security",
        "incident_type": "Vulnerability",
        "department": "Cybersecurity",
        "impact_level": "Low",
        "actions_taken": "None yet. Scan completed. Nova was here."
    }

    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')

        if "/admin" in response.text or "admin" in url:
            vulnerabilities.append({
                "title": "Open Admin Panel",
                "description": "URL or page contains 'admin', which may indicate exposed admin access.",
                "priority": "High"
            })

        forms = soup.find_all('form')
        for form in forms:
            if not form.find('input', {'name': 'csrf_token'}):
                vulnerabilities.append({
                    "title": "Form Without CSRF Token",
                    "description": "Form detected without CSRF protection.",
                    "priority": "Medium"
                })

        if "<script>" in response.text:
            vulnerabilities.append({
                "title": "Potential XSS",
                "description": "Script tags detected in page content.",
                "priority": "High"
            })

        sql_keywords = ["SELECT", "INSERT", "DELETE", "' OR 1=1", "--"]
        if any(keyword.lower() in response.text.lower() for keyword in sql_keywords):
            vulnerabilities.append({
                "title": "Potential SQL Injection",
                "description": "SQL keywords found in source, may be vulnerable.",
                "priority": "High"
            })

        if vulnerabilities:
            autofill_data["description"] = "; ".join([v["description"] for v in vulnerabilities])
            autofill_data["priority"] = max(v["priority"] for v in vulnerabilities if v["priority"])
            autofill_data["impact_level"] = autofill_data["priority"]

    except Exception as e:
        return {"error": str(e)}

    return {"vulnerabilities": vulnerabilities, "autofill": autofill_data}
