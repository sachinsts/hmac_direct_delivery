from datetime import datetime
from datetime import date
import requests

class VulnerabilityCollector:
    #collects high and critical severity
    REPO_BATCH_SIZE = 50
    VULN_BATCH_SIZE = 50
    daysForError = {}
    daysForError["CRITICAL"] = 7
    daysForError["HIGH"] = 14
    daysForError["MODERATE"] = 21
    daysForError["LOW"] = 30
    isVulnerabilityFound = 0 

    def configure(self, owner, authtoken, include_forked=False):
        self.owner = owner
        self.authtoken = authtoken
        self.QUERY = """{
            repository(name: "ows-permissions", owner: "sachinsts") {
                vulnerabilityAlerts(first:50) {
                    totalCount
                    nodes {
                            dismissedAt
                            createdAt
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
                    pageInfo {
                        hasNextPage
                        endCursor
                    }
                }
                
            }
        }
        """

    vulnerablityFound = {"HIGH":[], "CRITICAL":[],"MODERATE":[],"LOW":[]}

    def collect(self):
        has_next = True
        cursor = ""
        response_data = []
        new_data = []

        while has_next:
            r = self.graphql(self.QUERY)
            # print("GOT A RESULT: Data:")
            data = r["data"]["repository"]["vulnerabilityAlerts"]
            page = data["pageInfo"]
            has_next = page["hasNextPage"]
            cursor = page["endCursor"]
        
            for vuln in data["nodes"]:
                packagename = vuln["securityVulnerability"]["package"]["name"]
                typeofVulnerability = vuln["securityVulnerability"]["severity"]
                
                if packagename == "count":
                    print("!!! OH NO package named count!!!")
                if typeofVulnerability == "CRITICAL":
                    self.vulnerablityFound['CRITICAL'].append(vuln)
                if typeofVulnerability == 'HIGH':
                    self.vulnerablityFound['HIGH'].append(vuln)
                if typeofVulnerability == 'MODERATE':
                    self.vulnerablityFound['MODERATE'].append(vuln)
                if typeofVulnerability == 'LOW':
                    self.vulnerablityFound['LOW'].append(vuln)
    
    def graphql(self, data):
        token = "Bearer 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"
        r = requests.post(
            "https://api.github.com/graphql",
            json={"query": data},
            headers={
                "Authorization" : token,
                "Accept": "application/json",
            }
        )
        r.raise_for_status()
        return r.json()

    def logVulnerability(self, key, data):
        flag = 0
        for value in data:
            issue_date_string = datetime.strptime(value['createdAt'], '%Y-%m-%dT%H:%M:%SZ')
            issue_date = str(issue_date_string.date())
            today = datetime.today().strftime('%Y-%m-%d')
            current_date = datetime.strptime(today, '%Y-%m-%d')
            issue_date = datetime.strptime(issue_date, '%Y-%m-%d')
            delta = current_date - issue_date

            if delta.days > self.daysForError[key]:
                self.isVulnerabilityFound = 1
                if flag == 0:
                    print("-----------{} level error is not resolved from last {} days--------".format(key, self.daysForError[key]))
                    flag = 1
                print("{} level error for package '{}' current version {}, required version is {}".format(key, value["securityVulnerability"]["package"]["name"], value["vulnerableRequirements"], value["securityVulnerability"]["firstPatchedVersion"]["identifier"]))
        
    def print_report(self, vuln_dict):
        for key,value in vuln_dict.items():
            self.logVulnerability(key, value)
        if self.isVulnerabilityFound == 1:
            raise Exception("Vulnerability found while scaning repo!!!!")


COLLECTOR = VulnerabilityCollector()

def main():
    # parser = argparse.ArgumentParser(description="Export GitHub vulnerability alerts")
    # parser.add_argument("--owner", help="GitHub owner name")
    # parser.add_argument("--authtoken", help="GitHub API token")
    # parser.add_argument(
    #     "--short",
    #     action="store_true",
    #     help="Short form output, otherwise defaults to long form detailed output",
    # )
    # options = parser.parse_args()
    # if not options.owner:
    #     options.owner = os.environ.get("GITHUB_OWNER")
    # if not options.authtoken:
    #     options.authtoken = os.environ.get("GITHUB_AUTHTOKEN")

    # if not all([options.owner, options.authtoken]):
    #     parser.print_help()
    #     raise SystemExit(1)
    # logging.basicConfig(stream=sys.stdout, level=logging.INFO, format=LOG_FORMAT)
    options = {"owner":"sachinsts", "authtoken":"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"}
    COLLECTOR.configure(options["owner"], options["authtoken"])
    COLLECTOR.collect()
    COLLECTOR.print_report(COLLECTOR.vulnerablityFound)

main()
