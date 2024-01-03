""" Fetches all repos under a git organization
and returns last committer to master and date of commit
Results sorted by commit date
Replace ORG_NAME, USERNAME, and GH_TOKEN variables
GH_TOKEN required for authentication

This will use Rate limit at a rate of 1 per repo """

import os
import json
import time
import requests


# Use env vars or replace these values
GH_ORGNAME = os.environ.get('GH_ORGNAME', 'verbit-ai')
GH_USERNAME = os.environ.get('GH_USERNAME', 'mva-verbit')
GH_TOKEN = os.environ.get('GH_TOKEN')


def get_auth_status():
    """ Checks whether your call is authenticated """
    url = "https://api.github.com/rate_limit"
    response = rest_call(url)
    content = json.loads(response.content)
    my_rate = content["rate"]["limit"]
    rate_remaining = content["rate"]["remaining"]
    if my_rate == 60:
        print('Not Authenticated, you may not get the intended results')
        print(f"Current Rate Limit Remaining: {rate_remaining}")
        print('Ctrl-C to stop processing\n')
        time.sleep(4)
    elif my_rate == 5000:
        print('Successfully Authenticated')
        print(f"Current Rate Limit Remaining: {rate_remaining}")


def rest_call(url):
    """ Putting together the request """
    return requests.get(url, auth=(GH_USERNAME, os.environ.get('GH_TOKEN')))


def last_commit(repo):
    """ Pulling data for last commit date and commit author """
    url = "https://api.github.com/repos/" + GH_ORGNAME + "/" + repo + "/commits"
    response = rest_call(url)
    content = json.loads(response.content)
    try:
        commit_date = content[0]["commit"]["committer"]["date"]
        email = content[0]["commit"]["author"]["email"]
        if "github" in email:
            email = "none"
        author = content[0]["commit"]["author"]["name"]
        print(f'Last commit date: {commit_date} by {email} {author}')
        return (commit_date, email, author)
    except KeyError:
        if "message" in content and content["message"] == "Git Repository is empty.":
            return ("<empty_repo>", "", "")

    raise Exception(content)


def list_repos():
    """ Pulls the data from the base repos URL for each repo """
    repos = []
    url = "https://api.github.com/orgs/" + GH_ORGNAME + "/repos"
    while url is not None:
        response = rest_call(url)
        content = json.loads(response.content)
        if "message" in content and content["message"].startswith("API rate limit exceeded"):
            print(content)
            break
        if "message" in content and content["message"] == "Not Found":
            print(f'Content is not found for {GH_ORGNAME}: {content}')
            break
        print("processing repo list " + url)
        for item in content:
            repo = item["name"]
            print("processing repo " + repo)
            commit_date, email, author = last_commit(repo)
            high, critical = getDependencyAlerts(GH_ORGNAME, repo)
            if high+critical > 0:
                print(high, critical)
            repos.append((repo, commit_date, high, critical, email, author))
        # To handle pagination
        if "next" in response.links:
            url = response.links["next"]["url"]
        else:
            url = None
    return repos


headers = {"Authorization": "token {}".format(GH_TOKEN)}


def run_query(query, variables):
    request = requests.post('https://api.github.com/graphql',
                            json={'query': query, 'variables': variables}, headers=headers)
    if request.status_code == 200:
        return request.json()['data']
    else:
        raise Exception("Query failed to run by returning code of {}. {}".format(
            request.status_code, query))


def getDependencyAlerts(repo_owner, repo_name):
    query = ''' 
            query($repo_owner: String!, $repo_name: String!, $after: String )  { 
                repository(owner: $repo_owner , name: $repo_name ) {
                    vulnerabilityAlerts(first:100, after: $after ) {
                        totalCount
                        nodes {
                            id
                            createdAt
                            dismissReason
                            dismissedAt
                            dismisser{
                                login
                            }
                            fixedAt

                            securityAdvisory{
                            severity
                            }
                        }
                        pageInfo{
                            hasNextPage
                            endCursor
                        }
                    }
                }
    }
    '''
    variables = {
        "repo_owner": repo_owner,
        "repo_name": repo_name,
        "after": None
    }

    totalCount = None
    alerts = []
    while True:
        data = run_query(query, variables)['repository']['vulnerabilityAlerts']
        totalCount = data['totalCount']
        alerts.extend(data['nodes'])
        if data['pageInfo']['hasNextPage']:
            variables["after"] = data['pageInfo']['endCursor']
        else:
            break

    if len(alerts) != totalCount:
        raise Exception('graphql call not functioning properly,')

    critical, high = 0, 0
    for alert in alerts:
        if not alert.get('dismissedAt') and not alert.get('fixedAt') and not alert.get('dismisser'):
            if alert['securityAdvisory']['severity'] == 'CRITICAL':
                critical += 1
            elif alert['securityAdvisory']['severity'] == 'HIGH':
                high += 1
    return (critical, high)


def main():
    get_auth_status()
    repos_data = list_repos()
    repos_sorted = sorted(repos_data, key=lambda r: r[1], reverse=True)
    print(repos_sorted)
    for repo in repos_sorted:
        print(",".join([str(item) for item in repo]))


if __name__ == "__main__":
    main()
