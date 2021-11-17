import os
import logging
import subprocess
import requests

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

if os.path.basename(os.getcwd()) != 'securitytools':
    print('must run from the securitytools repo!')
    exit()

if len(os.sys.argv) != 2:
    print('usage: report.py ${github_pat}')
    exit()

github_headers = {
    'Authorization': 'token ' + os.sys.argv[1],
    'Accept': 'application/vnd.github.v3+json'
    }

homedir = os.getcwd()
with open(homedir + '/README.md', 'w') as f:
    f.write('![](https://avatars0.githubusercontent.com/u/2897191?s=95&v=4)\n')
    f.write('# securitytools\n')
    f.write('this repository hosts an array of GitHub projects leveraged across the security community, indexed as submodules.\n')
    f.write('```shell\ndocker pull ghcr.io/thetanz/securitytools:latest\n```\n')
    f.write('\n')
    f.write('### adding submodules\n')
    f.write('git projects can be added to this repository by navigating to an applicable folder and replacing `git clone` with `git submodule add`\n')
    f.write('### removing submodules\n')
    f.write('1. delete the relevant section from `.gitmodules`.\n')
    f.write('2. stage the `.gitmodules` changes with `git add .gitmodules`\n')
    f.write('3. delete the relevant section from `.git/config`\n')
    f.write('4. run `git rm --cached path_to_submodule` (no trailing slash).\n')
    f.write('5. run `rm -rf .git/modules/path_to_submodule` (no trailing slash).\n')
    f.write('6. commit changes `git commit -m "submodule removal"`\n')
    f.write('7. delete submodule files `rm -rf path_to_submodule`\n')
    f.write('# projects\n')
    f.write('[![report generator](https://github.com/thetanz/securitytools/actions/workflows/reporter.yml/badge.svg)](https://github.com/thetanz/securitytools/actions/workflows/reporter.yml)\n')
    f.write('this readme is dynamically generated based upon the contents of the submodules\n')
    for folder in os.listdir('.'):
        if os.path.isdir(folder):
            if folder.startswith('.git') or folder == 'securitytools':
                continue
            f.write('## ' + folder + '\n')
            for subfolder in os.listdir(folder):
                if subfolder.startswith('.git') or subfolder == 'securitytools':
                    continue
                directory = homedir + '/' + folder + '/' + subfolder
                logging.debug('processing %s' % directory)
                os.chdir(directory)
                # get the url of the submodule with git config --get remote.origin.url
                url = subprocess.Popen(['git', 'config', '--get', 'remote.origin.url'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8').strip().replace('.git', '')
                ghapi = requests.get(url.replace('github.com', 'api.github.com/repos'), headers=github_headers)
                if ghapi.status_code != 200:
                    logging.error('could not get description for %s' % ghapi.url)
                    logging.error(ghapi.status_code + ' - ' + ghapi.text)
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
