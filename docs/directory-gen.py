#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# generates directory.json details of included submodules
import os
import sys
import json
import logging
import subprocess
import requests
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
if os.path.basename(os.getcwd()) != 'securitytools':
    logging.critical('must run from the securitytools repo!')
    sys.exit(1)
else:
    if not os.path.isfile('.gitmodules'):
        logging.critical('no .gitmodules file found!')
        sys.exit(1)
try:
    github_headers = {'Authorization': 'token ' + os.environ['GITHUB_TOKEN']}
except KeyError:
    logging.critical('GITHUB_TOKEN not set!')
    sys.exit(1)
gmodules = []
with open('.gitmodules', 'r') as f:
    lines = f.readlines()
    f.close()
total_projects = int(len(lines) / 3)
counter_projects = 1
for i in range(len(lines)):
    if lines[i].startswith('[submodule'):
        gmodules.append({'path': lines[i].split('"')[1]})
    if lines[i].startswith('\turl'):
        gmodules[-1]['url'] = lines[i].split(' = ')[1].strip()
for i in gmodules:
    project = i['path'].replace('projects/', '')
    logging.info('processing project {}/{}: {}'.format(counter_projects, total_projects, project))
    project_url = i['url'].replace('github.com', 'api.github.com/repos')
    if project_url.endswith('.git'):
        project_url = project_url[:-4]
    project_get = requests.get(project_url, headers=github_headers)
    if project_get.status_code != 200:
        logging.critical('failed to get project info for {}!'.format(project))
        logging.critical('status code: {}'.format(project_get.status_code) + ' response: {}'.format(project_get.text))
        sys.exit(1)
    project_info = project_get.json()
    try:
        i['description'] = project_info['description']
    except KeyError:
        i['description'] = ''
    i['watchers'] = project_info['subscribers_count']
    i['forks'] = project_info['network_count']
    i['stars'] = project_info['stargazers_count']
    counter_projects += 1

with open('docs/directory.json', 'w') as f:
    f.write(json.dumps(gmodules, indent=4))
    f.close()
