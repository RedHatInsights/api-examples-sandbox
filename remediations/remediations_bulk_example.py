import requests
import json
import sys
import re
import time
import os

def log(s):
    print(s, file=sys.stderr)

def url(u):
    return 'https://cloud.redhat.com/api/vulnerability/v1{}'.format(u)

def get_affected_systems(ident):
    r = s.get(url('/cves/{}/affected_systems'.format(ident)))
    r.raise_for_status()
    return r.json()['data']

def get_all_cves():
    limit  = 256
    offset = 0
    lst = []
    while True:
        log('> Getting cve list page{}'.format(offset))
        r = s.get(url('/vulnerabilities/cves?sort=-public_date&affecting=true%2Cfalse&limit={}&offset={}'.format(limit, (offset * limit))))
        if r.status_code == 400:
            break

        data = r.json()['data']
        if len(data) == 0:
            break

        lst.extend(data)
        offset += 1

    return list(map(lambda x: x['id'], lst))

def add_rule_id(payload, cve_id):
    payload['add']['issues'][0]['id'] = 'vulnerabilities:{}'.format(cve_id)
    return payload

def conditionally_add_systems(payload, systems, tag):
    for system in systems:
        if tag == False or system_has_tag(system['id'], tag):
            payload["add"]["issues"][0]["systems"].append(system['id'])

def system_has_tag(system_id, tag):
    tags = False
    if system_id not in systems_tags_map:
        r = s.get('https://cloud.redhat.com/api/inventory/v1/hosts/{}/tags?per_page=100&page=1'.format(system_id))
        r.raise_for_status()
        tags = r.json()['results'][system_id]
        tags = list(map(lambda x: '{}={}/{}'.format(x['namespace'], x['key'], x['value']), tags))
        systems_tags_map[system_id] = tags
    else:
        tags = systems_tags_map[system_id]

    if tag in tags:
        return system_id
    return false

def main(cve_list, tag):
    if not cve_list:
        cve_list = get_all_cves()
        log('> Found {} cves'.format(len(cve_list)))

    remediation_id = False

    for cve_id in cve_list:
        payload = {
            "name": "TestRemediation_{}".format(int(time.time())),
            "add": {
                "issues": [
                    {
                        "resolution": "fix",
                        "systems": []
                    }
                ]
            }
        }

        payload = add_rule_id(payload, cve_id)
        conditionally_add_systems(payload, get_affected_systems(cve_id), tag)

        if not remediation_id:
            r = s.post('https://cloud.redhat.com/api/remediations/v1/remediations', json=payload)
            r.raise_for_status()
            remediation_id = r.json()['id']
            log('> Created remediation {} with {}'.format(remediation_id, cve_id))
        else:
            log('> adding {} to remediation {}'.format(cve_id, remediation_id))
            r = s.patch('https://cloud.redhat.com/api/remediations/v1/remediations/{}'.format(remediation_id), json=payload)
            r.raise_for_status()

    return remediation_id

def get_playbook(remediation_id):
    s.headers.update({'accept': 'text/vnd.yaml'})
    r = s.get('https://cloud.redhat.com/api/remediations/v1/remediations/{}/playbook'.format(remediation_id))
    r.raise_for_status()
    print(r.text)

def parse_cves(input_str):
    lst = input_str.split(',')
    ret = []
    for i in lst:
        i = i.strip()
        if not re.match('^CVE-[0-9]{4}-[0-9]{1,10}$', i):
            print('Invalid input CVE: {}'.format(i))
            sys.exit(1)
        ret.append(i)
    return ret

def parse_tag(input_str):
    if not re.match('^[a-zA-Z-]{4,}=.{4,}?\/.*$', input_str):
        print('Invalid tag filter: {}'.format(input_str))
        sys.exit(1)
    return input_str

def check_user_pass():
    for var in ['INSIGHTS_USER', 'INSIGHTS_PASS']:
        e = os.environ.get(var)
        if not e or e == '':
            print('Error: you must set a username in {}'.format(var))
            print_help()
            sys.exit(1)

def print_help():
    print("""Usage: example.py --tag || example.py --cves

Example:
INSIGHTS_USER=username INSIGHTS_PASS=password example.py --tag "insights-client=foo/bar"
INSIGHTS_USER=username INSIGHTS_PASS=password example.py --cves CVE-2020-25661,CVE-2020-25662

Sorry atm --tag and --cves together is not supported""")

systems_tags_map = {}

s = requests.Session()
s.headers.update({
    'Content-Type': 'application/json',
    'User-Agent': 'Insights API example (remediations_bulk_example.py) / 0.1',
})

s.auth = (os.environ.get('INSIGHTS_USER'), os.environ.get('INSIGHTS_PASS'))

if __name__ == "__main__":
    check_user_pass()

    cves = False
    tag  = False

    if len(sys.argv) >= 2:
        if sys.argv[1] == '--help':
            print_help()
            sys.exit(0)

        if sys.argv[1] == '--tag':
            tag = parse_tag(sys.argv[2])
        if sys.argv[1] == '--cves':
            cves = parse_cves(sys.argv[2])

    get_playbook(main(cves, tag))
