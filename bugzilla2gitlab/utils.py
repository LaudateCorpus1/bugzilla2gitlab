from getpass import getpass

import dateutil.parser
from defusedxml import ElementTree
import pytz
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
import os, re

SESSION = None


def _perform_request(
    url,
    method,
    data={},
    params={},
    headers={},
    files={},
    json=True,
    dry_run=False,
    verify=True,
):
    """
    Utility method to perform an HTTP request.
    """
    if dry_run and method != "get":
        msg = "{} {} dry_run".format(url, method)
        print(msg)
        return 0

    global SESSION
    if not SESSION:
        SESSION = requests.Session()
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            method_whitelist=["HEAD", "GET", "OPTIONS", "POST"]
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        SESSION.mount("https://", adapter)
        SESSION.mount("http://", adapter)

    func = getattr(SESSION, method)

    if files:
        result = func(url, files=files, headers=headers, verify=verify)
    else:
        result = func(url, params=params, data=data, headers=headers, verify=verify)

    if result.status_code in [200, 201]:
        if json:
            return result.json()
        return result

    raise Exception(
        "{} failed requests: [{}] Response: [{}] Request data: [{}] Url: [{}] Headers: [{}]".format(
            result.status_code, result.reason, result.content, data, url, headers
        )
    )


def markdown_table_row(key, value):
    """
    Create a row in a markdown table.
    """
    return u"| {} | {} |\n".format(key, value)


def format_datetime(datestr, formatting):
    """
    Apply a dateime format to a string, according to the formatting string.
    """
    parsed_dt = dateutil.parser.parse(datestr)
    return parsed_dt.strftime(formatting)


def format_utc(datestr):
    """
    Convert dateime string to UTC format recognized by gitlab.
    """
    parsed_dt = dateutil.parser.parse(datestr)
    utc_dt = parsed_dt.astimezone(pytz.utc)
    return utc_dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def get_gitlab_issue(gitlab_base_url, gitlab_project_id, bug, headers, verify):
    url = "{}/projects/{}/issues/{}".format(gitlab_base_url, gitlab_project_id, bug)
    try:
        issue = _perform_request(url, "get", headers=headers, verify=verify, json=True)
        print(
            "Issue with ID [{}] in project [{}] already exists, skipping".format(
                issue["id"], issue["project_id"]
            )
        )
        return True
    except Exception as e:
        return False


def get_bugzilla_bug(bugzilla_url, bug_id):
    """
    Read bug XML, return all fields and values in a dictionary.
    """
    bug_xml = _fetch_bug_content(bugzilla_url, bug_id)
    tree = ElementTree.fromstring(bug_xml)

    bug_fields = {
        "long_desc": [],
        "attachment": [],
        "cc": [],
        "dependson": [],
        "blocked": [],
    }
    for bug in tree:
        for field in bug:
            if field.tag in ("long_desc", "attachment"):
                new = {}
                for data in field:
                    new[data.tag] = data.text
                bug_fields[field.tag].append(new)
            elif field.tag == "cc":
                bug_fields[field.tag].append(field.text)
            elif field.tag == "dependson":
                bug_fields[field.tag].append(field.text)
            elif field.tag == "blocked":
                bug_fields[field.tag].append(field.text)
            else:
                bug_fields[field.tag] = field.text

    return bug_fields

def replace_bug_links(comment):
    # This performs some basic transformation and sanitizing of the links and references:
    #  * Removes "in reply to comment #1" as it would reference issue, not comment
    #  * Changes #N and @foo into their non-references counterparts
    #  * Replaces bz links / URLs to issue references
    res = (
        (r'\(In reply to comment #(\d+)\)',r''),
        (r'\(In reply to (.*?) from comment #(\d+)\)',r''),
        (r'^#(\d+)',r'#&#8203;\1'), # Insert "zero width space" character
        (r'^@(\w+)',r'@&#8203;\1'), # Insert "zero width space" character
        (r'^!(\d+)',r'@&#8203;\1'), # Insert "zero width space" character
        (r' #(\d+)',r'#&#8203;\1'), # Insert "zero width space" character
        (r' @(\w+)',r'@&#8203;\1'), # Insert "zero width space" character
        (r' !(\d+)',r'@&#8203;\1'), # Insert "zero width space" character
        (r'(http://|https://)?' + re.escape("bugs.llvm.org/show_bug.cgi?id=") + "(\d+)", r'#\2 '),
        (r'(http://|https://)?(llvm.org/)?PR(\d+)', r'#\3 '),
        (r'duplicate of bug (\d+)', r'duplicate of bug #\1 '),
        (r'Bug (\d+) has been marked', r'Bug #\1 has been marked')
        )
    for pair in res:
        comment = re.sub(pair[0], pair[1], comment)
    return comment

def _fetch_bug_content(url, bug_id):
    if os.path.exists(bug_id):
        with open(bug_id, 'r') as f:
            return f.read()
    else:
        url = "{}/show_bug.cgi?ctype=xml&id={}".format(url, bug_id)
        response = _perform_request(url, "get", json=False)
        return response.content


def bugzilla_login(url, user, password):
    """
    Log in to Bugzilla as user, asking for password for a few times / untill success.
    """
    max_login_attempts = 3
    login_url = "{}/index.cgi".format(url)
    # CSRF protection bypass: GET, then POST
    _perform_request(login_url, "get", json=False)
    for attempt in range(max_login_attempts):
        if password is None:
            bugzilla_password = getpass("Bugzilla password for {}: ".format(user))
        else:
            bugzilla_password = password

        response = _perform_request(
            login_url,
            "post",
            headers={"Referer": login_url},
            data={
                "Bugzilla_login": user,
                "Bugzilla_password": bugzilla_password,
            },
            json=False,
        )
        if response.cookies:
            break
        print("Failed to log in (attempt {})".format(attempt + 1))
    else:
        raise Exception("Failed to log in after {} attempts".format(max_login_attempts))


def validate_list(bug_list):
    """
    Ensure that the user-supplied input is a list of integers, or a list of strings
    that can be parsed as integers.
    """
    if not bug_list:
        raise Exception("No bugs to migrate! Call `migrate` with a list of bug ids.")

    if not isinstance(bug_list, list):
        raise Exception(
            "Expected a list of integers. Instead recieved "
            "a(n) {}".format(type(bug_list))
        )

    for bug in bug_list:
        if os.path.exists(bug):
            continue

        try:
            int(bug)
        except ValueError:
            raise Exception(
                "{} is not able to be parsed as an integer, "
                "and is therefore an invalid bug id.".format(bug)
            ) from ValueError
