# remediations_bulk_example.py

A script that adds in bulk remediations from the Insights/Vulnerability app.

## Usage

### Setup

```shell
$ cd api-examples-sandbox/remediations
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

### Fix *all* CVEs for all Hosts matching a certain tag

```shell
$ INSIGHTS_USER=foo INSIGHTS_PASS=bar remediations_bulk_example.py --tag 'insights-client/foo=bar'
```


### Fix certain CVEs for *all* Hosts

```shell
$ INSIGHTS_USER=foo INSIGHTS_PASS=bar remediations_bulk_example.py --cves CVE-2020-12352,CVE-2020-10713,CVE-2020-14311,CVE-2020-14310
```
