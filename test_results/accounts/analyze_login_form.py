"""
Analyze login form and attempt authentication with demo credentials.
"""

import requests
from bs4 import BeautifulSoup
import json

BASE_URL = "https://demo-company.zumodra.rhematek-solutions.com"

def analyze_login_form():
    """
    Fetch and analyze the login form to understand its structure.
    """
    print("="*80)
    print("ANALYZING LOGIN FORM")
    print("="*80)

    login_url = f"{BASE_URL}/en-us/accounts/login/"

    session = requests.Session()
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
    })

    # Get login page
    print(f"\n[*] Fetching login page: {login_url}")
    response = session.get(login_url)

    print(f"[+] Status Code: {response.status_code}")
    print(f"[+] Content-Type: {response.headers.get('Content-Type')}")

    # Parse HTML
    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all forms
    forms = soup.find_all('form')
    print(f"\n[*] Found {len(forms)} form(s) on page")

    for idx, form in enumerate(forms, 1):
        print(f"\n--- Form {idx} ---")
        print(f"Action: {form.get('action')}")
        print(f"Method: {form.get('method')}")
        print(f"ID: {form.get('id')}")
        print(f"Class: {form.get('class')}")

        # Find all inputs
        inputs = form.find_all('input')
        print(f"\nInputs ({len(inputs)}):")
        for inp in inputs:
            inp_type = inp.get('type', 'text')
            inp_name = inp.get('name', 'N/A')
            inp_value = inp.get('value', '')
            inp_placeholder = inp.get('placeholder', '')
            inp_required = 'required' if inp.get('required') else ''

            print(f"  - Name: {inp_name:30} Type: {inp_type:15} Value: {inp_value[:20]:20} Placeholder: {inp_placeholder} {inp_required}")

        # Find textareas
        textareas = form.find_all('textarea')
        if textareas:
            print(f"\nTextareas ({len(textareas)}):")
            for ta in textareas:
                print(f"  - Name: {ta.get('name', 'N/A')}")

        # Find select elements
        selects = form.find_all('select')
        if selects:
            print(f"\nSelects ({len(selects)}):")
            for sel in selects:
                print(f"  - Name: {sel.get('name', 'N/A')}")
                options = sel.find_all('option')
                print(f"    Options: {len(options)}")

        # Find buttons
        buttons = form.find_all('button')
        if buttons:
            print(f"\nButtons ({len(buttons)}):")
            for btn in buttons:
                print(f"  - Type: {btn.get('type', 'submit'):10} Text: {btn.get_text(strip=True)}")

    # Check for CSRF token
    csrf_input = soup.find('input', {'name': 'csrfmiddlewaretoken'})
    if csrf_input:
        print(f"\n[+] CSRF Token found: {csrf_input.get('value')[:20]}...")
    else:
        print("\n[-] No CSRF token found in form")

    # Check for session cookie
    if 'csrftoken' in session.cookies:
        print(f"[+] CSRF Cookie found: {session.cookies['csrftoken'][:20]}...")
    else:
        print("[-] No CSRF cookie found")

    # Save HTML for inspection
    output_file = "login_page.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(response.text)
    print(f"\n[+] Login page HTML saved to: {output_file}")

    # Try to identify the correct field names
    print("\n" + "="*80)
    print("RECOMMENDATIONS FOR LOGIN")
    print("="*80)

    # Find email/username field
    email_field = soup.find('input', {'type': 'email'}) or \
                  soup.find('input', {'name': lambda x: x and 'email' in x.lower()}) or \
                  soup.find('input', {'name': 'login'}) or \
                  soup.find('input', {'name': 'username'})

    # Find password field
    password_field = soup.find('input', {'type': 'password'})

    if email_field:
        print(f"[+] Email/Username field: name='{email_field.get('name')}'")
    else:
        print("[-] Could not identify email/username field")

    if password_field:
        print(f"[+] Password field: name='{password_field.get('name')}'")
    else:
        print("[-] Could not identify password field")

    # Check for error messages or user info
    error_divs = soup.find_all(class_=lambda x: x and 'error' in str(x).lower())
    if error_divs:
        print(f"\n[!] Found {len(error_divs)} error elements on page")
        for err in error_divs[:3]:
            print(f"    - {err.get_text(strip=True)[:100]}")

    # Check if there's any user info displayed (might already be logged in)
    user_info = soup.find(text=lambda x: x and '@' in str(x))
    if user_info:
        print(f"\n[!] Possible user info found: {str(user_info)[:100]}")

    return session

def check_existing_users():
    """
    Try to get information about existing users (if accessible).
    """
    print("\n" + "="*80)
    print("CHECKING FOR DEMO USERS")
    print("="*80)

    # Try common demo user endpoints
    endpoints = [
        "/api/v1/accounts/tenant-users/",
        "/api/v1/auth/demo-credentials/",
        "/.well-known/demo-users.json",
    ]

    session = requests.Session()

    for endpoint in endpoints:
        url = f"{BASE_URL}{endpoint}"
        print(f"\n[*] Trying: {url}")
        try:
            response = session.get(url)
            print(f"    Status: {response.status_code}")
            if response.status_code == 200:
                try:
                    data = response.json()
                    print(f"    Response: {json.dumps(data, indent=2)[:200]}")
                except:
                    print(f"    Response (not JSON): {response.text[:200]}")
        except Exception as e:
            print(f"    Error: {str(e)}")

def analyze_signup_form():
    """
    Analyze the signup form as well.
    """
    print("\n" + "="*80)
    print("ANALYZING SIGNUP FORM")
    print("="*80)

    signup_url = f"{BASE_URL}/en-us/accounts/signup/"

    session = requests.Session()
    print(f"\n[*] Fetching signup page: {signup_url}")
    response = session.get(signup_url)

    print(f"[+] Status Code: {response.status_code}")

    soup = BeautifulSoup(response.text, 'html.parser')

    # Find all forms
    forms = soup.find_all('form')
    print(f"\n[*] Found {len(forms)} form(s) on signup page")

    for idx, form in enumerate(forms, 1):
        print(f"\n--- Form {idx} ---")
        print(f"Action: {form.get('action')}")
        print(f"Method: {form.get('method')}")

        # Find all inputs
        inputs = form.find_all('input')
        print(f"\nInputs ({len(inputs)}):")
        for inp in inputs:
            inp_type = inp.get('type', 'text')
            inp_name = inp.get('name', 'N/A')
            inp_placeholder = inp.get('placeholder', '')
            inp_required = 'required' if inp.get('required') else ''

            print(f"  - Name: {inp_name:30} Type: {inp_type:15} Placeholder: {inp_placeholder} {inp_required}")

    # Save HTML for inspection
    output_file = "signup_page.html"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(response.text)
    print(f"\n[+] Signup page HTML saved to: {output_file}")

if __name__ == "__main__":
    analyze_login_form()
    analyze_signup_form()
    check_existing_users()

    print("\n" + "="*80)
    print("ANALYSIS COMPLETE")
    print("="*80)
    print("\nNext steps:")
    print("1. Review login_page.html and signup_page.html")
    print("2. Identify correct field names")
    print("3. Try to create a demo account or find existing credentials")
    print("4. Update test_accounts_module.py with correct credentials")
