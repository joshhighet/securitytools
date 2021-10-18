import os
import logging
import subprocess
import requests


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

if os.path.basename(os.getcwd()) != 'securitytools':
    print('must run from the securitytools repo!')
    exit()

homedir = os.getcwd()
with open(homedir + '/REPORT.md', 'w') as f:
    for folder in os.listdir('.'):
        if os.path.isdir(folder):
            if folder.startswith('.git') or folder == 'securitytools':
                continue
            f.write('# ' + folder + '\n')
            for subfolder in os.listdir(folder):
                if subfolder.startswith('.git') or subfolder == 'securitytools':
                    continue
                directory = homedir + '/' + folder + '/' + subfolder
                logging.debug('processing %s' % directory)
                os.chdir(directory)
                # get the url of the submodule with git config --get remote.origin.url
                url = subprocess.Popen(['git', 'config', '--get', 'remote.origin.url'], stdout=subprocess.PIPE).communicate()[0].decode('utf-8').strip().replace('.git', '')
                ghapi = requests.get(url.replace('github.com', 'api.github.com/repos'), headers={'accept': 'application/vnd.github.v3+json'})
                if ghapi.status_code != 200:
                    logging.error('could not get description for %s' % ghapi.url)
                    logging.error(ghapi.status_code + ' - ' + ghapi.text)
                    exit()
                f.write('* [%s](%s)\n' % (folder + '/' +  subfolder, url))
                try:
                    description = str(ghapi.json()['description'])
                except KeyError:
                    logging.error(ghapi.text)
                    description = 'no description exists'
                f.write('\t_%s_\n' % description.strip())
                f.write('\n')
        os.chdir(homedir)
f.close()
