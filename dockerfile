FROM ubuntu:latest

LABEL org.opencontainers.image.source https://github.com/thetanz/securitytools

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update --assume-yes
RUN apt-get upgrade --assume-yes
RUN apt-get install --assume-yes \
jq ufw zsh nmap tree cowsay lolcat openssl masscan tcpdump python3-pip \
gnupg2 torsocks curl git bat nyx nano ca-certificates curl gnupg lsb-release

RUN git clone https://github.com/thetanz/securitytools.git

RUN apt-get autoclean --assume-yes
RUN apt-get autoremove --assume-yes

RUN chsh --shell $(which zsh)

# ARG user=sectools
# RUN useradd --create-home --shell /bin/zsh $user
# USER $user
# WORKDIR /home/$user
# grab metasploit, don't install
# RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/\
# config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall
# RUN chmod +x msfinstall

RUN echo '[ ! -z "$TERM" -a -r /etc/motd ] && cat /etc/motd' | tee ~/.zshrc

# COPY . ./
# RUN find -L /home/$user/securitytools -name "requirements.txt" | tee /home/$user/py.requirements
# RUN cat /home/$user/py.requirements | while read reqs; do pip3 install --requirement $reqs; done
# RUN rm /home/$user/py.requirements

ENTRYPOINT /bin/zsh

