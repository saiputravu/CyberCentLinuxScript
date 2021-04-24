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

# Global variables
USERS=$(grep -E "/bin/.*sh" /etc/passwd | grep -v -e root -e `whoami` -e speech-dispatcher | cut -d":" -f1)


# -------------------- User functions -------------------- 
delete_unauthorised_users () {
    # Files necessary: 
    #   * users.txt

    echo -e $USERS | sed "s/ /\\n/g" > accusers.txt
    local INVALID=$(diff -n --suppress-common-lines users.txt accusers.txt | cut -d" " -f5-)

    for user in $INVALID
    do 
        sudo userdel -r $user
    done
    rm accusers.txt
}

delete_unauthorised_sudoers () {
    # Files necessary: 
    #   * sudoers.txt

    local SUDOERS=$(grep "sudo" /etc/group | cut -d":" -f4 | sed "s/,/ /g") 

    echo -e $SUDOERS | sed "s/ /\\n/g" > accsudoers.txt
    local INVALID=$(diff -n --suppress-common-lines sudoers.txt accsudoers.txt | cut -d" " -f5-)
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
        echo "${GREEN}[+] Added new user '${REPLY}'${RESET}"
        sudo useradd $REPLY
    done
}

change_users_passwords () {
    # Changes everyone's password to CyberPatriot1!
    for user in $USERS
    do 
        echo $i:'CyberPatriot1!' | sudo chpasswd 
    done
}

users_check_uid_0 () {
    # Checks for any UID 0 users in passwd 

    local UIDS=$(cut /etc/passwd -d: -f1,3 | grep -v root)
    for i in $UIDS
    do 
        local username=$(echo $i | cut -d: -f1)
        local user_uid=$(echo $i | cut -d: -f2)
        if [[ $user_uid -eq "0" ]]
        then 
            echo "${RED}${BOLD}Found a root UID user [${username} : uid ${user_uid}] !${RESET}"
            read -rp $'Press <enter> to continue\n'
        fi
    done
}   

check_shadow_password () { 
    # Checks for any users with an empty password
    local SHADOW=$(sudo cat /etc/shadow)
    for line in $SHADOW
    do 
        local password_hash=$(echo $line | cut -d: -f2)
        local account=$(echo $line | cut -d: -f1)
        if [[ -z $password_hash  ]]
        then 
            echo "${RED}${BOLD}Empty password${RESET}${RED} for account ${RED}${BOLD}${account}${RESET}${RED} found in ${RED}/etc/shadow!${RESET}"
            read -rp $'Press <enter> to continue\n'
        fi
    done
}

# -------------------- APT functions -------------------- 
autoupdate () {
    # Files necessary:
    #   NONE
    sudo apt install unattended-upgrades
}

update () {
    # Files necessary:
    #   NONE

    sudo apt update && sudo apt upgrade
}

enumerate_packages () {
    # Files necessary:
    #   NONE

    apt list --installed
}

remove_malware () {
    # Files necessary:
    #   NONE

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

# -------------------- Main functions -------------------- 
main_users () {
    echo -n ${CLEARSCREEN}

    local answer=""
    echo -n "${CYAN}Delete unauthorised users [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo 
            echo "${YELLOW}You will need to create a file called users.txt with all authorised users.${RESET}"
            echo "${CYAN}Press <enter> after adding ${BOLD}./users.txt${RESET}"
            read -r
            echo "${GREEN}[*] Deleting unauthorised users...${RESET}"
            delete_unauthorised_users
            ;;
        n|N)
            ;; # Do nothing
    esac

    echo -n "${CYAN}Delete unauthorised sudoers [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo
            echo "${YELLOW}You will need to create a file called sudoers.txt with all authorised users.${RESET}"
            echo "${CYAN}Press <enter> after adding ${BOLD}./sudoers.txt${RESET}"
            read -r
            echo "${GREEN}[*] Deleting unauthorised sudoers...${RESET}"
            delete_unauthorised_sudoers
            ;;
        n|N)
            ;; # Do nothing
    esac

    echo -n "${CYAN}Add users [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo 
            add_new_users 
            ;;
        n|N)
            ;; # Do nothing
    esac

    echo "${GREEN}[*] Changing every user's password to" 'CyberPatriot1!'"${RESET}"
    change_users_passwords

    echo "${GREEN}[*] Checking for any UID 0 users ... ${RESET}"
    users_check_uid_0

    echo "${GREEN}[*] Checking for any users with empty passwords ... ${RESET}"
    check_shadow_password

    # Order ran 
    # delete_unauthorised_users
    # delete_unauthorised_sudoers
    # add_new_users
    # change_users_passwords
    # users_check_uid_0
    # check_shadow_password
}

# Function to run everything
main () {
    main_users
}
main
