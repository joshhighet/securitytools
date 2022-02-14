#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import os
import logging
import subprocess
import requests

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

if os.path.basename(os.getcwd()) != 'securitytools':
    print('must run from the securitytools repo!')
    exit()

try:
    GHAUTH_API = os.environ['GHAUTH_API']
except KeyError:
    print('GHAUTH_API credential missing from environment!')
    exit()

github_headers = {
    'Authorization': 'token ' + GHAUTH_API,
    'Accept': 'application/vnd.github.v3+json'
    }

homedir = os.getcwd()
with open(homedir + '/README.md', 'w') as f:
    f.write('![](https://avatars0.githubusercontent.com/u/2897191?s=95&v=4)\n')
    f.write('# securitytools\n\n')
    f.write('this repository hosts an array of GitHub projects leveraged across the security community, indexed as submodules.\n\n')
    f.write('```shell\ndocker pull ghcr.io/thetanz/securitytools:latest\n```\n\n')
    f.write('### adding submodules\n\n')
    f.write('git projects can be added to this repository by navigating to an applicable folder and replacing `git clone` with `git submodule add`\n\n')
    f.write('### removing submodules\n\n')
    f.write('_remove submodule entry from .git/config_\n\n')
    f.write('```shell\ngit submodule deinit -f path/to/submodule\n```\n')
    f.write('_remove the submodule directory from .git/modules within the parent repo_\n\n')
    f.write('```shell\nrm -rf .git/modules/path/to/submodule\n```\n')
    f.write('_remove entry in .gitmodules & the submodule directory_\n\n')
    f.write('```shell\ngit rm -f path/to/submodule\n```\n')
    f.write('# projects\n\n')
    f.write('[![report generator](https://github.com/thetanz/securitytools/actions/workflows/reporter.yml/badge.svg)](https://github.com/thetanz/securitytools/actions/workflows/reporter.yml)\n\n')
    f.write('this readme is dynamically generated based upon the contents of the submodules\n\n')
    for folder in os.listdir('.'):
        if os.path.isdir(folder):
            if folder.startswith('.git') or folder == 'securitytools':
                continue
            f.write('## ' + folder + '\n')
            for subfolder in os.listdir(folder):
                if subfolder.startswith('.git') or subfolder == 'securitytools' or subfolder.endswith('.DS_Store'):
                    continue
                directory = homedir + '/' + folder + '/' + subfolder
                logging.debug('processing %s' % directory)
                os.chdir(directory)
                url = subprocess.Popen(['git', 'config', '--get', 'remote.origin.url'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8').strip().replace('.git', '')
                ghapi = requests.get(url.replace('github.com', 'api.github.com/repos'), headers=github_headers)
                if ghapi.status_code != 200:
                    logging.error('could not get description for %s' % ghapi.url)
                    logging.error(str(ghapi.status_code) + ' - ' + ghapi.text)
                    logging.error(ghapi.headers)
                    exit()
                f.write('* [%s](%s)\n' % (folder + '/' +  subfolder, url))
                try:
                    description = str(ghapi.json()['description'])
                except KeyError:
                    logging.error(ghapi.text)
                    description = str()
                if description != 'None':
                    f.write('\t_%s_\n' % description.strip())
                f.write('\n')
        os.chdir(homedir)
f.close()
