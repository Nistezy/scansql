import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

s = requests.Session()
s.headers["User-Agent"] = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/138.0.0.0 Safari/537.36" 

def get_forms(url):
    soup = BeautifulSoup(s.get(url).content, "html.parser")
    return soup.find_all("form")

def form_details(form):
    details = {}
    action = form.attrs.get("action")
    method = form.attrs.get("method", "get").lower()
    inputs = []

    for input_tag in form.find_all("input"):
        input_type = input_tag.attrs.get("type", "text")
        input_name = input_tag.attrs.get("name")
        input_value = input_tag.attrs.get("value", "")
        if input_name:
            inputs.append({
                "type": input_type,
                "name": input_name,
                "value": input_value,
            })

    details["action"] = action
    details["method"] = method
    details["inputs"] = inputs
    return details

def vulnerable(response):
    errors = {
        "quoted string not properly terminated",
        "unclosed quotation mark after the character string",
        "you have an error in your sql syntax",
        "warning: mysql",
        "unknown column",
    }
    content = response.content.decode(errors="ignore").lower()
    return any(error in content for error in errors)

def sql_injection_scan(url):
    forms = get_forms(url)
    print(f"[+] Detected {len(forms)} forms on {url}.")

    for form in forms:
        details = form_details(form)
        target_url = urljoin(url, details["action"])

        for i in ["'", '"']:
            data = {}
            for input_tag in details["inputs"]:
                if input_tag["type"] == "hidden" or input_tag["value"]:
                    data[input_tag['name']] = input_tag["value"] + i
                elif input_tag["type"] != "submit":
                    data[input_tag['name']] = f"test{i}"

            print(f"\n[+] Submitting form to {target_url} with data: {data}")

            if details["method"] == "post":
                res = s.post(target_url, data=data)
            else:
                res = s.get(target_url, params=data)

            if vulnerable(res):
                print("[!!!] SQL Injection vulnerability detected!")
                print(f"URL: {target_url}")
                break
        else:
            print("[OK] No SQL Injection vulnerabilities found in form.")

if __name__ == "__main__":
    urlToBeChecked = "https://testfire.net/login.jsp"
    sql_injection_scan(urlToBeChecked)
