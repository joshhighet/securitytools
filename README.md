![](https://avatars0.githubusercontent.com/u/2897191?s=95&v=4)
# securitytools

this repository hosts an array of GitHub projects leveraged across the security community, indexed as submodules.

```shell
docker pull ghcr.io/thetanz/securitytools:latest
```

### adding submodules

git projects can be added to this repository by navigating to an applicable folder and replacing `git clone` with `git submodule add`

### removing submodules

_remove submodule entry from .git/config_

```shell
git submodule deinit -f path/to/submodule
```
_remove the submodule directory from .git/modules within the parent repo_

```shell
rm -rf .git/modules/path/to/submodule
```
_remove entry in .gitmodules & the submodule directory_

```shell
git rm -f path/to/submodule
```
# projects

[![report generator](https://github.com/thetanz/securitytools/actions/workflows/reporter.yml/badge.svg)](https://github.com/thetanz/securitytools/actions/workflows/reporter.yml)

this readme is dynamically generated based upon the contents of the submodules

## testing
* [testing/caldera](https://github.com/mitre/caldera)
	_Automated Adversary Emulation Platform_

* [testing/DeTTECT](https://github.com/rabobank-cdc/DeTTECT)
	_Detect Tactics, Techniques & Combat Threats_

* [testing/atomic-red-team](https://github.com/redcanaryco/atomic-red-team)
	_Small and highly portable detection tests based on MITRE's ATT&CK._

* [testing/PEASS-ng](https://github.com/carlospolop/PEASS-ng)
	_PEASS - Privilege Escalation Awesome Scripts SUITE (with colors)_

* [testing/joystick](https://github.com/mitre-attack/joystick)
	_Joystick is a tool that gives you the ability to transform the ATT&CK Evaluations data into concise views that brings forward the nuances in the results._

* [testing/all-about-apikey](https://github.com/daffainfo/all-about-apikey)
	_Detailed information about API key / OAuth token (Description, Request, Response, Regex, Example)_

## windows
* [windows/ForgeCert](https://github.com/GhostPack/ForgeCert)
	_"Golden" certificates_

* [windows/LiquidSnake](https://github.com/RiccardoAncarani/LiquidSnake)
	_LiquidSnake is a tool that allows operators to perform fileless lateral movement using WMI Event Subscriptions and GadgetToJScript_

* [windows/mimikatz](https://github.com/gentilkiwi/mimikatz)
	_A little tool to play with Windows security_

* [windows/nanodump](https://github.com/helpsystems/nanodump)
	_A crappy LSASS dumper with no ASCII art_

* [windows/SharpNoPSExec](https://github.com/juliourena/SharpNoPSExec)
	_Get file less command execution for lateral movement._

* [windows/Certipy](https://github.com/ly4k/Certipy)
	_Tool for Active Directory Certificate Services enumeration and abuse_

* [windows/AttackSurfaceAnalyzer](https://github.com/microsoft/AttackSurfaceAnalyzer)
	_Attack Surface Analyzer can help you analyze your operating system's security configuration for changes during software installation._

* [windows/RDPassSpray](https://github.com/xFreed0m/RDPassSpray)
	_Python3 tool to perform password spraying using RDP_

* [windows/SysmonSearch](https://github.com/JPCERTCC/SysmonSearch)
	_Investigate suspicious activity by visualizing Sysmon's event log_

* [windows/evtx](https://github.com/omerbenamram/evtx)
	_A Fast (and safe) parser for the Windows XML Event Log (EVTX) format_

## osint
* [osint/oxdork](https://github.com/rly0nheart/oxdork)
	_Google dorking tool_

* [osint/metagoofil](https://github.com/opsdisk/metagoofil)
	_Search Google and download specific file types_

* [osint/spiderfoot](https://github.com/smicallef/spiderfoot)
	_SpiderFoot automates OSINT for threat intelligence and mapping your attack surface._

* [osint/dorkScanner](https://github.com/madhavmehndiratta/dorkScanner)
	_A typical search engine dork scanner scrapes search engines with dorks that you provide in order to find vulnerable URLs._

* [osint/metabigor](https://github.com/j3ssie/metabigor)
	_Intelligence tool but without API key_

* [osint/reconspider](https://github.com/bhavsec/reconspider)
	_🔎 Most Advanced Open Source Intelligence (OSINT) Framework for scanning IP Address, Emails, Websites, Organizations._

* [osint/OSINT](https://github.com/sinwindie/OSINT)
	_Collections of tools and methods created to aid in OSINT collection_

* [osint/mitaka](https://github.com/ninoseki/mitaka)
	_A browser extension for OSINT search_

* [osint/awesome-osint](https://github.com/jivoi/awesome-osint)
	_:scream: A curated list of amazingly awesome OSINT_

* [osint/Scrummage](https://github.com/matamorphosis/Scrummage)
	_The Ultimate OSINT and Threat Hunting Framework_

* [osint/waybackpack](https://github.com/jsvine/waybackpack)
	_Download the entire Wayback Machine archive for a given URL._

* [osint/uDork](https://github.com/m3n0sd0n4ld/uDork)
	_uDork is a script written in Bash Scripting that uses advanced Google search techniques to obtain sensitive information in files or directories, find IoT devices, detect versions of web applications, and so on._

## industrial
* [industrial/s7scan](https://github.com/klsecservices/s7scan)
	_The tool for enumerating Siemens S7 PLCs through TCP/IP or LLC network_

* [industrial/isf](https://github.com/dark-lbp/isf)
	_ISF(Industrial Control System Exploitation Framework)，a exploitation framework based on Python_

* [industrial/ICS_IoT_Shodan_Dorks](https://github.com/AustrianEnergyCERT/ICS_IoT_Shodan_Dorks)

* [industrial/ICS-Security-Tools](https://github.com/ITI/ICS-Security-Tools)
	_Tools, tips, tricks, and more for exploring ICS Security._

## forensics
* [forensics/sleuthkit](https://github.com/sleuthkit/sleuthkit)
	_The Sleuth Kit® (TSK) is a library and collection of command line digital forensics tools that allow you to investigate volume and file system data. The library can be incorporated into larger digital forensics tools and the command line tools can be directly used to find evidence._

* [forensics/aa-tools](https://github.com/JPCERTCC/aa-tools)
	_Artifact analysis tools by JPCERT/CC Analysis Center_

* [forensics/ArtifactCollectionMatrix](https://github.com/swisscom/ArtifactCollectionMatrix)
	_Forensic Artifact Collection Tool Matrix_

## blueteam
* [blueteam/FalconFriday](https://github.com/FalconForceTeam/FalconFriday)
	_Bi-weekly hunting queries_

* [blueteam/detection-rules](https://github.com/elastic/detection-rules)
	_Rules for Elastic Security's detection engine_

* [blueteam/chronicle-detection-rules](https://github.com/chronicle/detection-rules)
	_Collection of YARA-L 2.0 sample rules for the Chronicle Detection API_

* [blueteam/sigma](https://github.com/SigmaHQ/sigma)
	_Generic Signature Format for SIEM Systems_

## collections
* [collections/the-book-of-secret-knowledge](https://github.com/trimstray/the-book-of-secret-knowledge)
	_A collection of inspiring lists, manuals, cheatsheets, blogs, hacks, one-liners, cli/web tools and more._

* [collections/Infosec_Reference](https://github.com/rmusser01/Infosec_Reference)
	_An Information Security Reference That Doesn't Suck; https://rmusser.net/git/admin-2/Infosec_Reference for non-MS Git hosted version._

* [collections/blackhat-arsenal-tools](https://github.com/toolswatch/blackhat-arsenal-tools)
	_Official Black Hat Arsenal Security Tools Repository_

* [collections/Awesome-Vulnerability-Research](https://github.com/securitychampions/Awesome-Vulnerability-Research)
	_🦄 A curated list of the awesome resources about the Vulnerability Research_

* [collections/RedTeam-OffensiveSecurity](https://github.com/bigb0sss/RedTeam-OffensiveSecurity)
	_Tools & Interesting Things for RedTeam Ops_

* [collections/pentest-wiki](https://github.com/nixawk/pentest-wiki)
	_PENTEST-WIKI is a free online security knowledge library for pentesters / researchers. If you have a good idea, please share it with others._

* [collections/ctf-tools](https://github.com/zardus/ctf-tools)
	_Some setup scripts for security research tools._

* [collections/the_cyber_plumbers_handbook](https://github.com/opsdisk/the_cyber_plumbers_handbook)
	_Free copy of The Cyber Plumber's Handbook_

* [collections/HackingTools](https://github.com/Laxa/HackingTools)
	_Exhaustive list of hacking tools_

* [collections/msticpy](https://github.com/microsoft/msticpy)
	_Microsoft Threat Intelligence Security Tools_

* [collections/OSINT](https://github.com/sinwindie/OSINT)
	_Collections of tools and methods created to aid in OSINT collection_

* [collections/tools](https://github.com/nullsecuritynet/tools)
	_Security and Hacking Tools, Exploits, Proof of Concepts, Shellcodes, Scripts._

* [collections/SecurityShepherd](https://github.com/OWASP/SecurityShepherd)
	_Web and mobile application security training platform_

* [collections/security](https://github.com/mozilla/security)
	_Repository for various tools around security_

* [collections/regular-expression-cheat-sheet](https://github.com/niklongstone/regular-expression-cheat-sheet)
	_Regular Expression Cheat Sheet - PCRE_

* [collections/awesome-devsecops](https://github.com/devsecops/awesome-devsecops)
	_An authoritative list of awesome devsecops tools with the help from community experiments and contributions._

* [collections/security-cheatsheets](https://github.com/andrewjkerr/security-cheatsheets)
	_🔒 A collection of cheatsheets for various infosec tools and topics._

* [collections/macOS-Security-and-Privacy-Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
	_Guide to securing and improving privacy on macOS_

* [collections/DefaultCreds-cheat-sheet](https://github.com/ihebski/DefaultCreds-cheat-sheet)
	_One place for all the default credentials to assist the Blue/Red teamers activities on finding devices with default password 🛡️_

* [collections/Red-Team-Infrastructure-Wiki](https://github.com/bluscreenofjeff/Red-Team-Infrastructure-Wiki)
	_Wiki to collect Red Team infrastructure hardening resources_

## indicators
* [indicators/yara](https://github.com/VirusTotal/yara)
	_The pattern matching swiss knife_

* [indicators/Yara-rules](https://github.com/bartblaze/Yara-rules)
	_Collection of private Yara rules._

* [indicators/awesome-yara](https://github.com/InQuest/awesome-yara)
	_A curated list of awesome YARA rules, tools, and people._

* [indicators/opencti](https://github.com/OpenCTI-Platform/opencti)
	_Open Cyber Threat Intelligence Platform_

* [indicators/yara-signator](https://github.com/fxb-cocacoding/yara-signator)
	_Automatic YARA rule generation for Malpedia_

* [indicators/IoCs](https://github.com/sophoslabs/IoCs)
	_Sophos-originated indicators-of-compromise from published reports_

* [indicators/misp-galaxy](https://github.com/MISP/misp-galaxy)
	_Clusters and elements to attach to MISP events or attributes (like threat actors)_

* [indicators/ja3](https://github.com/salesforce/ja3)
	_JA3 is a standard for creating SSL client fingerprints in an easy to produce and shareable way._

* [indicators/misp-warninglists](https://github.com/MISP/misp-warninglists)
	_Warning lists to inform users of MISP about potential false-positives or other information in indicators_

* [indicators/awesome-threat-intelligence](https://github.com/hslatman/awesome-threat-intelligence)
	_A curated list of Awesome Threat Intelligence resources_

* [indicators/vti-dorks](https://github.com/Neo23x0/vti-dorks)
	_Awesome VirusTotal Intelligence Search Queries_

* [indicators/yarGen](https://github.com/Neo23x0/yarGen)
	_yarGen is a generator for YARA rules_

* [indicators/python-iocextract](https://github.com/InQuest/python-iocextract)
	_Defanged Indicator of Compromise (IOC) Extractor._

* [indicators/jarm](https://github.com/salesforce/jarm)

## media
* [media/go-exif](https://github.com/dsoprea/go-exif)
	_A very complete, highly tested, standards-driven (but customizable) EXIF reader/writer lovingly written in Go._

* [media/unredacter](https://github.com/BishopFox/unredacter)
	_Never ever ever use pixelation as a redaction technique_

* [media/exiftool](https://github.com/exiftool/exiftool)
	_ExifTool meta information reader/writer_

## sdr
* [sdr/CubicSDR](https://github.com/cjcliffe/CubicSDR)
	_Cross-Platform Software-Defined Radio Application_

* [sdr/gqrx](https://github.com/gqrx-sdr/gqrx)
	_Software defined radio receiver powered by GNU Radio and Qt._

* [sdr/gnuradio](https://github.com/gnuradio/gnuradio)
	_GNU Radio – the Free and Open Software Radio Ecosystem_

* [sdr/srsRAN](https://github.com/srsran/srsRAN)
	_Open source SDR 4G/5G software suite from Software Radio Systems (SRS)_

* [sdr/gps-sdr-sim](https://github.com/osqzss/gps-sdr-sim)
	_Software-Defined GPS Signal Simulator_

* [sdr/RFSec-ToolKit](https://github.com/cn0xroot/RFSec-ToolKit)
	_RFSec-ToolKit is a collection of Radio Frequency Communication Protocol Hacktools.无线通信协议相关的工具集，可借助SDR硬件+相关工具对无线通信进行研究。Collect with ♥ by HackSmith_

* [sdr/urh](https://github.com/jopohl/urh)
	_Universal Radio Hacker: Investigate Wireless Protocols Like A Boss_

## microsoft&azure
* [microsoft&azure/Mandiant-Azure-AD-Investigator](https://github.com/fireeye/Mandiant-Azure-AD-Investigator)

* [microsoft&azure/o365creeper](https://github.com/LMGsec/o365creeper)
	_Python script that performs email address validation against Office 365 without submitting login attempts._

* [microsoft&azure/SkyArk](https://github.com/cyberark/SkyArk)
	_SkyArk helps to discover, assess and secure the most privileged entities in Azure and AWS_

* [microsoft&azure/MicroBurst](https://github.com/NetSPI/MicroBurst)
	_A collection of scripts for assessing Microsoft Azure security_

* [microsoft&azure/AzureAD-Attack-Defense](https://github.com/Cloud-Architekt/AzureAD-Attack-Defense)
	_This publication is a collection of various common attack scenarios on Azure Active Directory and how they can be mitigated or detected._

* [microsoft&azure/AzureADAssessment](https://github.com/AzureAD/AzureADAssessment)
	_Tooling for assessing an Azure AD tenant state and configuration_

* [microsoft&azure/Cloud-Katana](https://github.com/Azure/Cloud-Katana)
	_Unlocking Serverless Computing to Assess Security Controls_

* [microsoft&azure/azure-policy](https://github.com/Azure/azure-policy)
	_Repository for Azure Resource Policy built-in definitions and samples_

* [microsoft&azure/azucar](https://github.com/nccgroup/azucar)
	_Security auditing tool for Azure environments_

* [microsoft&azure/CRT](https://github.com/CrowdStrike/CRT)
	_Contact: CRT@crowdstrike.com_

* [microsoft&azure/Azure-Network-Security](https://github.com/Azure/Azure-Network-Security)
	_Resources for improving Customer Experience with Azure Network Security_

* [microsoft&azure/AzurePenTestScope](https://github.com/swiftsolves-msft/AzurePenTestScope)
	_The following scripts and programs are to help security professionals scope their organizations Azure footprint prior to penetration testing._

* [microsoft&azure/Sentinel-Queries](https://github.com/reprise99/Sentinel-Queries)
	_Collection of KQL queries_

* [microsoft&azure/o365recon](https://github.com/nyxgeek/o365recon)
	_retrieve information via O365 and AzureAD with a valid cred_

* [microsoft&azure/Sparrow](https://github.com/cisagov/Sparrow)
	_Sparrow.ps1 was created by CISA's Cloud Forensics team to help detect possible compromised accounts and applications in the Azure/m365 environment._

* [microsoft&azure/BlobHunter](https://github.com/cyberark/BlobHunter)
	_Find exposed data in Azure with this public blob scanner_

* [microsoft&azure/cs-suite](https://github.com/SecurityFTW/cs-suite)
	_Cloud Security Suite - One stop tool for auditing the security posture of AWS/GCP/Azure infrastructure._

* [microsoft&azure/Stormspotter](https://github.com/Azure/Stormspotter)
	_Azure Red Team tool for graphing Azure and Azure Active Directory objects_

* [microsoft&azure/o365-attack-toolkit](https://github.com/mdsecactivebreach/o365-attack-toolkit)
	_A toolkit to attack Office365_

* [microsoft&azure/msmailprobe](https://github.com/busterb/msmailprobe)
	_Office 365 and Exchange Enumeration_

* [microsoft&azure/TokenTactics](https://github.com/rvrsh3ll/TokenTactics)
	_Azure JWT Token Manipulation Toolset_

## macOS
* [macOS/macOS-enterprise-privileges](https://github.com/SAP/macOS-enterprise-privileges)
	_For Mac users in an Enterprise environment, this app gives the User control over administration of their machine by elevating their level of access to Administrator privileges on macOS.  Users can set the time frame using Preferences to perform specific tasks such as install or remove an application._

## reconnaisance
* [reconnaisance/Backlink-dorks](https://github.com/alfazzafashion/Backlink-dorks)
	_google dork for search top backlink_

* [reconnaisance/gau](https://github.com/lc/gau)
	_Fetch known URLs from AlienVault's Open Threat Exchange, the Wayback Machine, and Common Crawl._

* [reconnaisance/fierce](https://github.com/mschwager/fierce)
	_A DNS reconnaissance tool for locating non-contiguous IP space._

* [reconnaisance/recon-ng](https://github.com/lanmaster53/recon-ng)
	_Open Source Intelligence gathering tool aimed at reducing the time spent harvesting information from open sources._

* [reconnaisance/HostHunter](https://github.com/SpiderLabs/HostHunter)
	_HostHunter a recon tool for discovering hostnames using OSINT techniques._

* [reconnaisance/SubDomainizer](https://github.com/nsonaniya2010/SubDomainizer)
	_A tool to find subdomains and interesting things hidden inside, external Javascript files of page, folder, and Github._

* [reconnaisance/Sudomy](https://github.com/Screetsec/Sudomy)
	_Sudomy is a subdomain enumeration tool to collect subdomains and analyzing domains performing automated reconnaissance (recon) for bug hunting / pentesting_

* [reconnaisance/dnsrecon](https://github.com/darkoperator/dnsrecon)
	_DNS Enumeration Script_

* [reconnaisance/cloud_enum](https://github.com/initstring/cloud_enum)
	_Multi-cloud OSINT tool. Enumerate public resources in AWS, Azure, and Google Cloud._

* [reconnaisance/Ashok](https://github.com/powerexploit/Ashok)
	_Ashok is a OSINT Recon Tool , a.k.a :heart_eyes:  Swiss Army knife ._

* [reconnaisance/AttackSurfaceMapper](https://github.com/superhedgy/AttackSurfaceMapper)
	_AttackSurfaceMapper is a tool that aims to automate the reconnaissance process._

* [reconnaisance/fav-up](https://github.com/pielco11/fav-up)
	_IP lookup by favicon using Shodan_

* [reconnaisance/github-dorks](https://github.com/techgaun/github-dorks)
	_Find leaked secrets via github search_

## vuln-identification
* [vuln-identification/flan](https://github.com/cloudflare/flan)
	_A pretty sweet vulnerability scanner_

* [vuln-identification/tsunami-security-scanner](https://github.com/google/tsunami-security-scanner)
	_Tsunami is a general purpose network security scanner with an extensible plugin system for detecting high severity vulnerabilities with high confidence._

* [vuln-identification/nmap-vulners](https://github.com/vulnersCom/nmap-vulners)
	_NSE script based on Vulners.com API_

## containers
* [containers/dockerfiles](https://github.com/jessfraz/dockerfiles)
	_Various Dockerfiles I use on the desktop and on servers._

* [containers/docker-cheat-sheet](https://github.com/wsargent/docker-cheat-sheet)
	_Docker Cheat Sheet_

* [containers/docker-bench-security](https://github.com/docker/docker-bench-security)
	_The Docker Bench for Security is a script that checks for dozens of common best-practices around deploying Docker containers in production._

* [containers/dockerscan](https://github.com/cr0hn/dockerscan)
	_Docker security analysis & hacking tools_

## activedirectory
* [activedirectory/BloodHound](https://github.com/BloodHoundAD/BloodHound)
	_Six Degrees of Domain Admin_

* [activedirectory/SharpHound3](https://github.com/BloodHoundAD/SharpHound3)
	_C# Data Collector for the BloodHound Project, Version 3_

* [activedirectory/ADFSpoof](https://github.com/fireeye/ADFSpoof)

## scanners
* [scanners/StalkPhish](https://github.com/t4d/StalkPhish)
	_StalkPhish - The Phishing kits stalker, harvesting phishing kits for investigations._

* [scanners/watchdog](https://github.com/flipkart-incubator/watchdog)
	_Watchdog - A Comprehensive Security Scanning and a Vulnerability Management Tool._

* [scanners/RustScan](https://github.com/RustScan/RustScan)
	_🤖 The Modern Port Scanner 🤖_

* [scanners/trivy](https://github.com/aquasecurity/trivy)
	_Scanner for vulnerabilities in container images, file systems, and Git repositories, as well as for configuration issues and hard-coded secrets_

* [scanners/killshot](https://github.com/bahaabdelwahed/killshot)
	_A Penetration Testing Framework, Information gathering tool & Website Vulnerability Scanner_

* [scanners/faraday](https://github.com/infobyte/faraday)
	_Collaborative Penetration Test and Vulnerability Management Platform_

* [scanners/Striker](https://github.com/s0md3v/Striker)
	_Striker is an offensive information and vulnerability scanner._

* [scanners/masscan](https://github.com/robertdavidgraham/masscan)
	_TCP port scanner, spews SYN packets asynchronously, scanning entire Internet in under 5 minutes._

## blockchain
* [blockchain/smart-contract-attack-vectors](https://github.com/kadenzipfel/smart-contract-attack-vectors)
	_A collection of smart contract attack vectors along with prevention methods._

## authentication
* [authentication/SAML2Spray](https://github.com/LuemmelSec/SAML2Spray)
	_Python Script for SAML2 Authentication Passwordspray_

* [authentication/teleport](https://github.com/gravitational/teleport)
	_Certificate authority and access plane for SSH, Kubernetes, web apps, databases and desktops_

## email
* [email/PhishMailer](https://github.com/BiZken/PhishMailer)
	_Generate Professional Phishing Emails Fast And Easy_

* [email/espoofer](https://github.com/chenjj/espoofer)
	_An email spoofing testing tool that aims to bypass SPF/DKIM/DMARC and forge DKIM signatures.🍻_

* [email/checkdmarc](https://github.com/domainaware/checkdmarc)
	_A parser for SPF and DMARC DNS records_

* [email/miteru](https://github.com/ninoseki/miteru)
	_An experimental phishing kit detection tool_

## socials
* [socials/TweetFeed](https://github.com/0xDanielLopez/TweetFeed)
	_Collecting IOCs posted on Twitter_

* [socials/holehe](https://github.com/megadose/holehe)
	_holehe allows you to check if the mail is used on different sites like twitter, instagram and will retrieve information on sites with the forgotten password function._

* [socials/Discord-History-Tracker](https://github.com/chylex/Discord-History-Tracker)
	_Desktop app & browser script that saves Discord chat history into a file, and an offline viewer that displays the file._

* [socials/awesome-social-engineering](https://github.com/v2-dev/awesome-social-engineering)
	_A curated list of awesome social engineering resources._

* [socials/get-discord-bots-tokens-with-google](https://github.com/traumatism/get-discord-bots-tokens-with-google)
	_Google dorks to easily get some Discord bots tokens_

* [socials/Telepathy](https://github.com/jordanwildon/Telepathy)
	_Public release of Telepathy, an OSINT toolkit for investigating Telegram chats._

* [socials/AMITT](https://github.com/cogsec-collaborative/AMITT)
	_AMITT (Adversarial Misinformation and Influence Tactics and Techniques) framework for describing disinformation incidents. Includes TTPs and countermeasures._

* [socials/OSINT-Discord-resources](https://github.com/Dutchosintguy/OSINT-Discord-resources)
	_Some OSINT Discord resources_

* [socials/sherlock](https://github.com/sherlock-project/sherlock)
	_🔎 Hunt down social media accounts by username across social networks_

* [socials/NameSpi](https://github.com/waffl3ss/NameSpi)
	_Scrape LinkedIn, ZoomInfo, USStaff, and Hunter.io for usernames and employees._

* [socials/socialscan](https://github.com/iojw/socialscan)
	_Python library and CLI for accurately querying username and email usage on online platforms_

* [socials/CrossLinked](https://github.com/m8r0wn/CrossLinked)
	_LinkedIn enumeration tool to extract valid employee names from an organization through search engine scraping_

## assets
* [assets/snipe-it](https://github.com/snipe/snipe-it)
	_A free open source IT asset/license management system_

* [assets/streamalert](https://github.com/airbnb/streamalert)
	_StreamAlert is a serverless, realtime data analysis framework which empowers you to ingest, analyze, and alert on data from any environment, using datasources and alerting logic you define._

* [assets/archerysec](https://github.com/archerysec/archerysec)
	_Centralize Vulnerability Assessment and Management for DevSecOps Team_

* [assets/netdata](https://github.com/netdata/netdata)
	_Real-time performance monitoring, done right! https://www.netdata.cloud_

## internet-scale-research
* [internet-scale-research/Hunting-New-Registered-Domains](https://github.com/gfek/Hunting-New-Registered-Domains)
	_Hunting Newly Registered Domains_

* [internet-scale-research/opensquat](https://github.com/atenreiro/opensquat)
	_Detection of phishing domains and domain squatting. Supports permutations such as homograph attack, typosquatting and bitsquatting._

* [internet-scale-research/EyeWitness](https://github.com/FortyNorthSecurity/EyeWitness)
	_EyeWitness is designed to take screenshots of websites, provide some server header info, and identify default credentials if possible._

* [internet-scale-research/phishing_catcher](https://github.com/x0rz/phishing_catcher)
	_Phishing catcher using Certstream_

* [internet-scale-research/nuclei](https://github.com/projectdiscovery/nuclei)
	_Fast and customizable vulnerability scanner based on simple YAML based DSL._

* [internet-scale-research/httprobe](https://github.com/tomnomnom/httprobe)
	_Take a list of domains and probe for working HTTP and HTTPS servers_

* [internet-scale-research/aquatone](https://github.com/michenriksen/aquatone)
	_A Tool for Domain Flyovers_

## incidents
* [incidents/alerting-detection-strategy-framework](https://github.com/palantir/alerting-detection-strategy-framework)
	_A framework for developing alerting and detection strategies for incident response._

* [incidents/Aurora-Incident-Response](https://github.com/cyb3rfox/Aurora-Incident-Response)
	_Incident Response Documentation made easy. Developed by Incident Responders for Incident Responders_

* [incidents/Loki](https://github.com/Neo23x0/Loki)
	_Loki - Simple IOC and Incident Response Scanner_

## devops
* [devops/axiom](https://github.com/pry0cc/axiom)
	_The dynamic infrastructure framework for everybody! Distribute the workload of many different scanning tools with ease, including nmap, ffuf, masscan, nuclei, meg and many more!_

* [devops/credential-digger](https://github.com/SAP/credential-digger)
	_A Github scanning tool that identifies hardcoded credentials while filtering the false positive data through machine learning models :lock:_

* [devops/wraith](https://github.com/N0MoreSecr3ts/wraith)
	_Uncover forgotten secrets and bring them back to life, haunting security and operations teams._

* [devops/dog](https://github.com/ogham/dog)
	_A command-line DNS client._

* [devops/auditd](https://github.com/Neo23x0/auditd)
	_Best Practice Auditd Configuration_

* [devops/Fenrir](https://github.com/Neo23x0/Fenrir)
	_Simple Bash IOC Scanner_

* [devops/osquery](https://github.com/osquery/osquery)
	_SQL powered operating system instrumentation, monitoring, and analytics._

## websites
* [websites/CMSeeK](https://github.com/Tuhinshubhra/CMSeeK)
	_CMS Detection and Exploitation suite - Scan WordPress, Joomla, Drupal and over 180 other CMSs_

* [websites/weird_proxies](https://github.com/GrrrDog/weird_proxies)
	_Reverse proxies cheatsheet_

* [websites/ffuf](https://github.com/ffuf/ffuf)
	_Fast web fuzzer written in Go_

* [websites/AwesomeXSS](https://github.com/s0md3v/AwesomeXSS)
	_Awesome XSS stuff_

* [websites/slowloris](https://github.com/gkbrk/slowloris)
	_Low bandwidth DoS tool. Slowloris rewrite in Python._

* [websites/H5SC](https://github.com/cure53/H5SC)
	_HTML5 Security Cheatsheet - A collection of HTML5 related XSS attack vectors_

* [websites/nginxconfig.io](https://github.com/digitalocean/nginxconfig.io)
	_⚙️ NGINX config generator on steroids 💉_

* [websites/w3af](https://github.com/andresriancho/w3af)
	_w3af: web application attack and audit framework, the open source web vulnerability scanner._

* [websites/awesome-api-security](https://github.com/arainho/awesome-api-security)
	_A collection of awesome API Security tools and resources. The focus goes to open-source tools and resources that benefit all the community._

* [websites/dirsearch](https://github.com/maurosoria/dirsearch)
	_Web path scanner_

* [websites/payloads](https://github.com/foospidy/payloads)
	_Git All the Payloads! A collection of web attack payloads._

* [websites/PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)
	_A list of useful payloads and bypass for Web Application Security and Pentest/CTF_

* [websites/awesome-web-security](https://github.com/qazbnm456/awesome-web-security)
	_🐶 A curated list of Web Security materials and resources._

* [websites/sqlmap](https://github.com/sqlmapproject/sqlmap)
	_Automatic SQL injection and database takeover tool_

## cloud
* [cloud/stratus-red-team](https://github.com/DataDog/stratus-red-team)
	_:cloud: :zap: Granular, Actionable Adversary Emulation for the Cloud_

* [cloud/CloudPentestCheatsheets](https://github.com/dafthack/CloudPentestCheatsheets)
	_This repository contains a collection of cheatsheets I have put together for tools related to pentesting organizations that leverage cloud providers._

* [cloud/ScoutSuite](https://github.com/nccgroup/ScoutSuite)
	_Multi-Cloud Security Auditing Tool_

* [cloud/festin](https://github.com/cr0hn/festin)
	_FestIn - S3 Bucket Weakness Discovery_

## mobile
* [mobile/RE-iOS-Apps](https://github.com/ivRodriguezCA/RE-iOS-Apps)
	_A completely free, open source and online course about Reverse Engineering iOS Applications._

* [mobile/awesome-mobile-security](https://github.com/vaib25vicky/awesome-mobile-security)
	_An effort to build a single place for all useful android and iOS security related stuff. All references and tools belong to their respective owners. I'm just maintaining it._

* [mobile/objection](https://github.com/sensepost/objection)
	_📱 objection - runtime mobile exploration_

* [mobile/Mobile-Security-Framework-MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF)
	_Mobile Security Framework (MobSF) is an automated, all-in-one mobile application (Android/iOS/Windows) pen-testing, malware analysis and security assessment framework capable of performing static and dynamic analysis._

* [mobile/MobileApp-Pentest-Cheatsheet](https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet)
	_The Mobile App Pentest cheat sheet was created to provide concise collection of high value information on specific mobile application penetration testing topics._

* [mobile/iLEAPP](https://github.com/abrignoni/iLEAPP)
	_iOS Logs, Events, And Plist Parser_

* [mobile/owasp-mstg](https://github.com/OWASP/owasp-mstg)
	_The Mobile Security Testing Guide (MSTG) is a comprehensive manual for mobile app security testing and reverse engineering. It describes the technical processes for verifying the controls listed in the OWASP Mobile Application Security Verification Standard (MASVS)._

* [mobile/ssl-kill-switch2](https://github.com/nabla-c0d3/ssl-kill-switch2)
	_Blackbox tool to disable SSL certificate validation - including certificate pinning - within iOS and macOS applications._

* [mobile/andriller](https://github.com/den4uk/andriller)
	_📱 Andriller - is software utility with a collection of forensic tools for smartphones. It performs read-only, forensically sound, non-destructive acquisition from Android devices._

* [mobile/SMSSpoof](https://github.com/vpn/SMSSpoof)
	_Spoof who an SMS is from using an SMS API_

* [mobile/osx-and-ios-security-awesome](https://github.com/ashishb/osx-and-ios-security-awesome)
	_OSX and iOS related security tools_

## analysis
* [analysis/radare2](https://github.com/radareorg/radare2)
	_UNIX-like reverse engineering framework and command-line toolset_

* [analysis/fame](https://github.com/certsocietegenerale/fame)
	_FAME Automates Malware Evaluation_

* [analysis/CAPEv2](https://github.com/kevoreilly/CAPEv2)
	_Malware Configuration And Payload Extraction_

* [analysis/malwoverview](https://github.com/alexandreborges/malwoverview)
	_Malwoverview is a first response tool used for threat hunting and offers intel information from Virus Total, Hybrid Analysis, URLHaus, Polyswarm, Malshare, Alien Vault, Malpedia, ThreatCrowd, Malware Bazaar, ThreatFox, Triage and it is able to scan Android devices against VT._

* [analysis/hstsparser](https://github.com/thebeanogamer/hstsparser)
	_A tool to parse Firefox and Chrome HSTS databases into forensic artifacts!_

* [analysis/awesome-reversing](https://github.com/tylerha97/awesome-reversing)
	_A curated list of awesome reversing resources_

* [analysis/Cyber-Search-Shortcuts](https://github.com/Neo23x0/Cyber-Search-Shortcuts)
	_Browser Shortcuts for Cyber Security Related Online Services_

* [analysis/DeepBlueCLI](https://github.com/sans-blue-team/DeepBlueCLI)

* [analysis/munin](https://github.com/Neo23x0/munin)
	_Online hash checker for Virustotal and other services_

## networking
* [networking/nebula](https://github.com/slackhq/nebula)
	_A scalable overlay networking tool with a focus on performance, simplicity and security_

* [networking/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy)
	_dnscrypt-proxy 2 - A flexible DNS proxy, with support for encrypted DNS protocols._

* [networking/clash](https://github.com/Dreamacro/clash)
	_A rule-based tunnel in Go._

* [networking/Responder](https://github.com/lgandx/Responder)
	_Responder is a LLMNR, NBT-NS and MDNS poisoner, with built-in HTTP/SMB/MSSQL/FTP/LDAP rogue authentication server supporting NTLMv1/NTLMv2/LMv2, Extended Security NTLMSSP and Basic HTTP authentication._

* [networking/AutoRecon](https://github.com/Tib3rius/AutoRecon)
	_AutoRecon is a multi-threaded network reconnaissance tool which performs automated enumeration of services._

* [networking/bettercap](https://github.com/bettercap/bettercap)
	_The Swiss Army knife for 802.11, BLE, IPv4 and IPv6 networks reconnaissance and MITM attacks._

* [networking/Raven-Storm](https://github.com/Taguar258/Raven-Storm)
	_Raven-Storm is a powerful DDoS toolkit for penetration tests, including attacks for several protocols written in python. Takedown many connections using several exotic and classic protocols._

* [networking/Tunna](https://github.com/SECFORCE/Tunna)
	_Tunna is a set of tools which will wrap and tunnel any TCP communication over HTTP. It can be used to bypass network restrictions in fully firewalled environments._

* [networking/mubeng](https://github.com/kitabisa/mubeng)
	_An incredibly fast proxy checker & IP rotator with ease._

* [networking/CloudFlair](https://github.com/christophetd/CloudFlair)
	_🔎 Find origin servers of websites behind CloudFlare by using Internet-wide scan data from Censys._

* [networking/cloud-ranges](https://github.com/pry0cc/cloud-ranges)
	_A list of cloud ranges from different providers._

* [networking/justniffer](https://github.com/onotelli/justniffer)
	_Justniffer  Just A Network TCP Packet Sniffer .Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic_

* [networking/snort3](https://github.com/snort3/snort3)
	_Snort++_

* [networking/microsocks](https://github.com/rofl0r/microsocks)
	_tiny, portable SOCKS5 server with very moderate resource usage_

* [networking/rita](https://github.com/activecm/rita)
	_Real Intelligence Threat Analytics (RITA) is a framework for detecting command and control communication through network traffic analysis._

* [networking/pulledpork](https://github.com/shirkdog/pulledpork)
	_Pulled Pork for Snort and Suricata rule management (from Google code)_

* [networking/wifijammer](https://github.com/DanMcInerney/wifijammer)
	_Continuously jam all wifi clients/routers_

* [networking/awesome-shodan-queries](https://github.com/jakejarvis/awesome-shodan-queries)
	_🔍 A collection of interesting, funny, and depressing search queries to plug into shodan.io 👩‍💻_

* [networking/mitmengine](https://github.com/cloudflare/mitmengine)
	_A MITM (monster-in-the-middle) detection tool. Used to build MALCOLM:_

* [networking/aircrack-ng](https://github.com/aircrack-ng/aircrack-ng)
	_WiFi security auditing tools suite_

* [networking/pwnat](https://github.com/samyk/pwnat)
	_The only tool and technique to punch holes through firewalls/NATs where both clients and server can be behind separate NATs without any 3rd party involvement. Pwnat uses a newly developed technique, exploiting a property of NAT translation tables, with no 3rd party, port forwarding, DMZ, router administrative requirements, STUN/TURN/UPnP/ICE, or spoofing required._

* [networking/IPRotate_Burp_Extension](https://github.com/RhinoSecurityLabs/IPRotate_Burp_Extension)
	_Extension for Burp Suite which uses AWS API Gateway to rotate your IP on every request._

