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
    f.write('# securitytools\n\n')
    f.write('a collection of GitHub projects used for various security tasks - collected as submodules within this repository.\n\n')
    f.write('# projects\n\n')
    f.write('[![report generator](https://github.com/joshhighet/securitytools/actions/workflows/reporter.yml/badge.svg)](https://github.com/joshhighet/securitytools/actions/workflows/reporter.yml)\n\n')
    f.write('this readme is dynamically generated based upon the github description field for the associated repo\n\n')
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
