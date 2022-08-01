#!/usr/bin/python
import argparse

# import collections
import logging
import os
import requests
import sys

# import time

log = logging.getLogger(__name__)
LOG_FORMAT = "%(asctime)s %(levelname)-5.5s %(message)s"


class VulnerabilityCollector:
    def configure(self, owner, authtoken, include_forked=False):
        self.owner = owner
        self.authtoken = authtoken
        self.include_forked = include_forked
        self.score = {
            "CRITICAL": 11,
            "HIGH": 5,
            "MODERATE": 2,
            "LOW": 1
        }
        self.repos = {}

    def make_vuln_dict(self, vuln, reponame):
        one = {}
        ecosystem = vuln["securityVulnerability"]["package"]["ecosystem"]
        one["dismissedAt"] = vuln["dismissedAt"]
        one["currentVersion"] = vuln["vulnerableRequirements"]
        one["severity"] = vuln["securityVulnerability"]["severity"]
        if (ecosystem != "RUBYGEMS") and (not one["dismissedAt"]) and (not reponame.startswith("frontend")):
            one["used"] = True
            one["score"] = self.score[one["severity"]]
        else:
            one["used"] = False
            one["score"] = 0
        if vuln["securityVulnerability"]["firstPatchedVersion"] is None:
            one["patchedVersion"] = "None"
        else:
            one["patchedVersion"] = vuln["securityVulnerability"][
                "firstPatchedVersion"
            ]["identifier"]
        one["ecosystem"] = ecosystem
        return one

    def collect(self):
        # log.info('Retrieving data from GitHub API')
        has_next = True
        cursor = ""
        while has_next:
            r = self.graphql(
                self.QUERY
                % {
                    "owner": self.owner,
                    "cursor": ', after:"%s"' % cursor if cursor else "",
                    "repo_batch_size": self.REPO_BATCH_SIZE,
                    "vuln_batch_size": self.VULN_BATCH_SIZE,
                }
            )
            # print("GOT A RESULT: Data:")
            data = r["data"]["repositoryOwner"]["repositories"]
            # print(data)
            # print("*****************************")
            page = data["pageInfo"]
            has_next = page["hasNextPage"]
            cursor = page["endCursor"]

            for repo in data["nodes"]:
                # print("GOT A REPO")
                # print(repo)
                # print("++++++++++++++++++++++++++++")
                # reponame = "%s/%s" % (self.owner, repo["name"])
                reponame = repo["name"]
                vuln_info = repo["vulnerabilityAlerts"]
                total_count = vuln_info["totalCount"]
                self.repos[reponame] = {}
                self.repos[reponame]["count"] = total_count
                self.repos[reponame]["isArchived"] = repo["isArchived"]
                # print('Repo %s isArchived is: %s' % (reponame, repo['isArchived']))
                if total_count > 0:
                    for vuln in vuln_info["nodes"]:
                        packagename = vuln["securityVulnerability"]["package"]["name"]
                        if packagename == "count":
                            print("!!! OH NO package named count!!!")
                        newscore = self.score[vuln["securityVulnerability"]["severity"]]
                        if packagename in self.repos[reponame]:
                            if self.repos[reponame][packagename]["used"] and self.repos[reponame][packagename]["score"] < newscore:
                                self.repos[reponame][packagename]["score"] = newscore
                        else:
                            one = self.make_vuln_dict(vuln, reponame)
                            # print('%s: severity: %s  package: %s' % (reponame, one['severity'], one['package']))
                            self.repos[reponame][packagename] = one
                    # print(vulns[reponame])
        # print('FINISHED COLLECTING')
        return

    REPO_BATCH_SIZE = 50
    VULN_BATCH_SIZE = 50
    QUERY = """query {
    repositoryOwner(login:"%(owner)s") {
      repositories(first:%(repo_batch_size)s%(cursor)s) {
        nodes {
          name
          isArchived
          vulnerabilityAlerts(first:%(vuln_batch_size)s) {
            totalCount
            nodes {
              dismissedAt
              vulnerableRequirements
              securityVulnerability {
                severity
                firstPatchedVersion {
                  identifier
                }
                package {
                  name
                  ecosystem
                }
              }
            }
          }
        }

        pageInfo {
          hasNextPage
          endCursor
        }
      }
    }}
    """

    def graphql(self, query):
        #print("Authorization: Bearer %s" % self.authtoken)
        #print("owner %s" % self.owner)
        #exit()
        
        token = "token %s" % self.authtoken
        r = requests.post(
            "https://api.github.com/graphql",
            json={"query": query},
            headers={
                "Authorization" : token,
                "Accept": "application/json",
            },
        )
        r.raise_for_status()
        return r.json()


def print_short(vuln_dict, skip_zeros=True):
    print("Total repos,%s" % len(vuln_dict))
    for entry in vuln_dict:
        # print(entry)
        # print(vuln_dict[entry])
        count = vuln_dict[entry]["count"]
        if (count > 0 or not (skip_zeros)) and (not (vuln_dict[entry]["isArchived"])):
            print("%s,%s" % (entry, vuln_dict[entry]["count"]))
        # print('*****************')


def repo_score(repo):
    score = 0
    for package, info in repo.items():
        if package != "count" and package != "isArchived":
            score += info["score"]
    return score


def severity_count(repo, severity):
    count = 0
    for package, info in repo.items():
        if package != "count" and package != "isArchived":
            if info["used"] and info["severity"] == severity:
                count += 1
    return count


def high_count(repo):
    return severity_count(repo, "HIGH")


def critical_count(repo):
    return severity_count(repo, "CRITICAL")


def moderate_count(repo):
    return severity_count(repo, "MODERATE")


def low_count(repo):
    return severity_count(repo, "LOW")


# this should print a score for each repository, then an overall total score
# and would be nice to have total number of CRITICAL, HIGH, MODERATE, and LOW
def print_report(vuln_dict):
    total_high = 0
    total_critical = 0
    total_moderate = 0
    total_low = 0
    print("Repository,Score")
    for name, repo in vuln_dict.items():
        total_high += high_count(repo)
        total_critical += critical_count(repo)
        total_moderate += moderate_count(repo)
        total_low += low_count(repo)
        count = repo["count"]
        if not (repo["isArchived"]):
            if count > 0:
                total_score = repo_score(repo)
                print("%s,%s" % (name, total_score))
            else:
                print("%s,0" % (name))

            # for package, info in repo.items():
            #    if package != "isArchived" and package != "count":
            #        print("%s,%s,%s" % (name, package, info["score"]))
    print("Critical: %s" % (total_critical))
    print("High: %s" % (total_high))
    print("Moderate: %s" % (total_moderate))
    print("Low: %s" % (total_low))


def print_new(vuln_dict, skip_zeros=True):
    print("Repo,Package,Severity,score,Ecosystem,dismissedAt,Current,Patched")
    for name, repo in vuln_dict.items():
        count = repo["count"]
        if (count > 0) and (not (repo["isArchived"])):
            for package, info in repo.items():
                if package != "isArchived" and package != "count":
                    print(
                        "%s,%s,%s,%s,%s,%s,%s,%s"
                        % (
                            name,
                            package,
                            info["severity"],
                            info["score"],
                            info["ecosystem"],
                            info["dismissedAt"],
                            info["currentVersion"],
                            info["patchedVersion"]
                        )
                    )


def print_full(vuln_dict, skip_zeros=True):
    print("Repo,Severity,Package,Current,Patched,Ecosystem,dismissedAt,FE,Mult,Crit,High,Mod,Low")
    for entry in vuln_dict:
        count = vuln_dict[entry]["count"]
        if (count > 0 or not (skip_zeros)) and (not (vuln_dict[entry]["isArchived"])):
            for info in vuln_dict[entry]["info"]:
                frontend = 1 if info["package"].startswith("frontend") else 0
                multiplier = 1
                if frontend == 1 or info["ecosystem"] == "RUBYGEMS":
                    multiplier = 0
                print(
                    "%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s"
                    % (
                        entry,
                        info["severity"],
                        info["package"],
                        info["currentVersion"],
                        info["patchedVersion"],
                        info["ecosystem"],
                        info["dismissedAt"],
                        frontend,
                        multiplier,
                        '1' if info["severity"] == "CRITICAL" else "0",
                        '1' if info["severity"] == "HIGH" else "0",
                        "1" if info["severity"] == "MODERATE" else "0",
                        "1" if info["severity"] == "LOW" else "0",
                        info["score"] * multiplier
                    )
                )


COLLECTOR = VulnerabilityCollector()


def main():
    parser = argparse.ArgumentParser(description="Export GitHub vulnerability alerts")
    parser.add_argument("--owner", help="GitHub owner name")
     parser.add_argument("--authtoken", help="GitHub owner name")
    options = parser.parse_args()
    if not options.owner:
        options.owner = os.environ.get("GITHUB_OWNER")
    if not options.authtoken:
        options.authtoken = os.environ.get("GITHUB_AUTHTOKEN")

    if not all([options.owner, options.authtoken]):
        parser.print_help()
        raise SystemExit(1)
    logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT)
    print("----------------------------------------", options.authtoken)
    COLLECTOR.configure(options.owner, options.authtoken)
    COLLECTOR.collect()
    if options.short:
        print_report(COLLECTOR.repos)
    else:
        print_new(COLLECTOR.repos)



main()
