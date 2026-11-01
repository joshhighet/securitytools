#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# generates directory.json details of included submodules
import os
import sys
import json
import logging
import urllib.error
import urllib.request
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
if os.path.basename(os.getcwd()) != 'securitytools':
    logging.critical('must run from the securitytools repo!')
    sys.exit(1)
else:
    if not os.path.isfile('.gitmodules'):
        logging.critical('no .gitmodules file found!')
        sys.exit(1)
try:
    github_token = os.environ['GITHUB_TOKEN']
except KeyError:
    logging.critical('GITHUB_TOKEN not set!')
    sys.exit(1)


def get_repo(api_url):
    '''returns the repo json, or None where the upstream is gone or unreachable'''
    request = urllib.request.Request(api_url, headers={
        'Authorization': 'token ' + github_token,
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'securitytools-directory-gen'})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.load(response)
    except urllib.error.HTTPError as err:
        if err.code in (401, 403, 429):
            logging.critical('api returned {} for {} - token or rate limit issue'.format(err.code, api_url))
            sys.exit(1)
        logging.warning('skipping {} - api returned {}'.format(api_url, err.code))
        return None
    except (urllib.error.URLError, TimeoutError) as err:
        logging.warning('skipping {} - {}'.format(api_url, err))
        return None


gmodules = []
with open('.gitmodules', 'r') as f:
    lines = f.readlines()
    f.close()
for i in range(len(lines)):
    if lines[i].startswith('[submodule'):
        gmodules.append({'path': lines[i].split('"')[1]})
    if lines[i].startswith('\turl'):
        gmodules[-1]['url'] = lines[i].split(' = ')[1].strip()
total_projects = len(gmodules)
directory = []
skipped = []
for counter_projects, module in enumerate(gmodules, start=1):
    project = module['path'].replace('projects/', '')
    logging.info('processing project {}/{}: {}'.format(counter_projects, total_projects, project))
    project_url = module['url'].replace('github.com', 'api.github.com/repos')
    if project_url.endswith('.git'):
        project_url = project_url[:-4]
    project_info = get_repo(project_url)
    if project_info is None:
        skipped.append(module['path'])
        continue
    module['description'] = project_info.get('description') or ''
    module['watchers'] = project_info.get('subscribers_count', 0)
    module['forks'] = project_info.get('network_count', 0)
    module['stars'] = project_info.get('stargazers_count', 0)
    directory.append(module)

with open('docs/directory.json', 'w') as f:
    f.write(json.dumps(directory, indent=4))
    f.close()

logging.info('wrote {} of {} projects to docs/directory.json'.format(len(directory), total_projects))
if skipped:
    logging.warning('{} unreachable submodule(s) left out of the directory:'.format(len(skipped)))
    for path in skipped:
        logging.warning('  {}'.format(path))
