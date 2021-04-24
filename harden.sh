#!/bin/bash

# Foreground Colours
BLACK=$(tput setaf 0)
RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
YELLOW=$(tput setaf 3)
BLUE=$(tput setaf 4)
MAGENTA=$(tput setaf 5)
CYAN=$(tput setaf 6)
LIGHTGREY=$(tput setaf 7)
WHITE=$(tput setaf 8)

UNDERLINE=$(tput smul)
ENDUNDERLINE=$(tput rmul)
BOLD=$(tput smso)
ENDBOLD=$(tput rmso)

CLEARSCREEN=$(tput clear)

# Resets everything
RESET=$(tput sgr 0)

delete_unauthorised_users () {
    # Files necessary: 
    #   * users.txt

    USERS=$(grep -E "/bin/.*sh" /etc/passwd | grep -v -e root -e `whoami`| cut -d":" -f1)
    
    echo -e $USERS | sed "s/ /\\n/g" > accusers.txt
    INVALID=$(diff -n --suppress-common-lines users.txt accusers.txt | cut -d" " -f5-)

    for user in $INVALID
    do 
        sudo userdel -r $user
    done
    rm accusers.txt
}

delete_unauthorised_sudoers () {
    # Files necessary: 
    #   * sudoers.txt

    SUDOERS=$(grep "sudo" /etc/group | cut -d":" -f4 | sed "s/,/ /g") 

    echo -e $SUDOERS | sed "s/ /\\n/g" > accsudoers.txt
    INVALID=$(diff -n --suppress-common-lines sudoers.txt accsudoers.txt | cut -d" " -f5-)
    for sudoer in $INVALID
    do 
        sudo gpasswd -d $sudoer sudo
    done

    rm accsudoers.txt
}

add_new_users () {
    # Files necessary:
    #   NONE

    echo -n "${CLEARSCREEN}"
    echo "${RED}${BOLD}Type 'exit' to stop.${RESET}"
    while read -r -p "Username to create: " && [[ $REPLY != exit ]]; do 
        sudo useradd $REPLY
    done
}

autoupdate () {
    sudo apt install unattended-upgrades
}

update () {
    sudo apt update && sudo apt upgrade
}

enumerate_packages () {
    apt list --installed
}

remove_malware () {
    declare -a arr=(john, abc, sqlmap, aria2
                    aquisition, bitcomet, bitlet, bitspirit
                    endless-sky, zenmap, minetest, minetest-server
                    armitage, crack, apt pureg knocker, aircrack-ng
                    airbase-ng, hydra, freeciv
                    wireshark, tshark
                    hydra-gtk, netcat, netcat-traditional, netcat-openbsd
                    netcat-ubuntu, netcat-minimal, qbittorrent, ctorrent
                    ktorrent, rtorrent, deluge, transmission-common
                    transmission-bittorrent-client, tixati, frostwise, vuse
                    irssi, transmission-gtk, utorrent, kismet
                    medusa, telnet, exim4, telnetd
                    bind9, crunch, tcpdump, tomcat
                    tomcat6, vncserver, tightvnc, tightvnc-common
                    tightvncserver, vnc4server, nmdb, dhclient
                    telnet-server, ophcrack, cryptcat, cups
                    cupsd, tcpspray, ettercap
                    wesnoth, snort, pryit
                    weplab, wireshark, nikto, lcrack
                    postfix, snmp, icmp, dovecot
                    pop3, p0f, dsniff, hunt
                    ember, nbtscan, rsync, freeciv-client-extras
                    freeciv-data, freeciv-server, freeciv-client-gtk
                    )

    for i in "${arr[@]}"
    do
        sudo apt purge -y --force-yes $i
    done
}
