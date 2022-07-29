

# just a playground for reading/writing potential security doc files
# the rough idea right now is that each repo would have a security doc
# that includes baseline security information. Some would need to be
# manually written, some could be automated, and then the whole file could be
# machine-read to help generate the security score for the repo.
import json


# Initial rough idea of security score - the lower the score, the better, for
# each repo.
# Elements could be Github issue count, automated test coverage, static scan
# score, pen test score, swagger documentation, monitoring link, recent audit,
# open issues, risk rating and owner contact information.
# Some of these don't exist yet. And we may want to add more - for example name
# or link to a security design doc

# initial pass at a security doc might look something like this
DEMO_SEC_INFO = {
    "repo_name": "ows-accounting",
    "github_vulnerabilities": 3,
    "test_coverage": 78,
    "static_scan": 21,
    "pen_test": 0,
    "swagger_docs": "http://swagger.theorchard.io/service/ows-accounting",
    "monitor_link": "https://ows-accounting.theorchard.io/hello",
    "last_audited": "2020-02-26",
    "open_issues": 0,
    "risk_rating": 3,
    "owner_contact": "jgetter@theorchard.com",
    "score": 80,
}

DEFAULT_SEC_INFO = {
    "repo_name": "",
    "github_vulnerabilities": 30,
    "test_coverage": 0,
    "static_scan": 30,
    "pen_test": 30,
    "swagger_docs": "n/a",
    "monitor_link": "n/a",
    "last_audited": "n/a",
    "open_issues": 30,
    "risk_rating": 3,
    "owner_contact": "n/a",
}

# maybe have a method to set each of these, if they aren't set?
# plus methods to read and write this to a standard file name
# I think the idea is - maybe - have a directory name passed in
# on the command line, try to read this file from the directory if
# it exists, update scores where possible, calculate a total score,
# and write the updated file back.
# If the file doesn't exist, then create one with updated scores.

# getting the code coverage report - either we need to be able to access
# jenkins and get the number from it, or Jenkins needs to call out to us
# and report a score somehow.
# It could be an issue getting the security doc updated and checked back
# into the repository, changes committed, but maybe they shouldn't be in the
# same repo that they have the information for? The issue is discoverability.
# In most ways I think it would be preferable to have the sec doc at the root
# of each repo, so it can be easily seen and checked with the repo, and people
# who work on the repo are immediately aware of it.


def calculate_score(sec_data):
    sec_data["score"] = 20
    return sec_data


# for getting the static score results it may be similar to the code
# coverage issue - how to automatically get the numbers, either from
# a sonarqube API call or some other method - sonarqube calling out.
def set_static_scan(sec_data):
    if not(sec_data["staticc_scan"]):
        sec_data["static_scan"] = 30
    return sec_data


# need to see if jenkins has an API or standard way we could get info
# from the code coverage output. If not we may need to find a way for Jenkins
# to send the coverage number somewhere so we can get it.
def set_test_coverage(sec_data):
    if not(sec_data["test_coverage"]):
        sec_data["test_coverage"] = 0
    return sec_data


# here want to reuse some of the github exporter code to pull the latest
# total count of vulnerabilities from github
def set_github_vulnerabilities(sec_data):
    if not(sec_data["github_vulnerabilities"]):
        sec_data["github_vulnerabilities"] = 30
    return sec_data


# here we would want to call an API on the pen test tool to get a score
# but we shouldn't overwrite a score that is there until we have a pen
# test tool in place - since we could add manually for now
def set_pen_test(sec_data):
    if not(sec_data["pen_test"]):
        sec_data["pen_test"] = 30
    return sec_data


def read_doc(filename):
    with open(filename) as json_file:
        sec_data = json.load(json_file)
    return sec_data


def write_doc(filename, sec_data):
    with open(filename, "w") as json_file:
        json.dump(sec_data, json_file, indent=1)


def main():
    write_doc("test_sec_doc.json", DEMO_SEC_INFO)


main()
