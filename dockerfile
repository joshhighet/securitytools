FROM ubuntu:latest

LABEL org.opencontainers.image.source https://github.com/thetanz/securitytools

ARG user=sectools
ARG DEBIAN_FRONTEND=noninteractive
#package installation & housekeeping
RUN apt-get update --assume-yes
RUN apt-get upgrade --assume-yes
RUN apt-get install --assume-yes \
jq ufw zsh nmap tree cowsay lolcat openssl masscan tcpdump python3-pip gnupg2 \
torsocks curl  git bat nyx nano ca-certificates curl apt-transport-https gnupg \
lsb-release
RUN apt-get autoclean --assume-yes
RUN apt-get autoremove --assume-yes
#set default shell to zsh for root
RUN chsh --shell $(which zsh)
#install azure cli
RUN curl --location https://aka.ms/InstallAzureCLIDeb \
| bash
#add user and configure
RUN useradd --create-home --shell /bin/zsh $user
USER $user
WORKDIR /home/$user
#grab metasploit, don't install
RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/\
config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
RUN chmod +x msfinstall
#add ascii banner to rc config for zsh
RUN echo '[ ! -z "$TERM" -a -r /etc/motd ] && cat /etc/motd' \
| tee ~/.zshrc
#compile a list of paths to python requirements for submodules
RUN find -L /home/$user/securitytools -name "requirements.txt" \
| tee /home/$user/py.requirements
#for each requirement file, blindly install
RUN cat /home/$user/py.requirements \
| while read reqs; do pip3 install --requirement $reqs; done
RUN rm /home/$user/py.requirements
#set entrypoint
ENTRYPOINT /bin/zsh
COPY . ./
