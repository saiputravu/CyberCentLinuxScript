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

# -------------------- User Policies functions -------------------- 

user_policies_install () {
    # Installs required packages for user policies hardening 

    sudo apt install --force-yes -y libpam-cracklib fail2ban
}

password_policies () {
    # common-password
    # Assumes you have run user_policies_install

    # Back the file up to correct directory
    cp /etc/pam.d/common-password backup/pam/common-password

    # sed -i is inplace so updates file, else prints to stdout
    sudo sed -ie "s/pam_cracklib\.so.*/pam_cracklib.so retry=3 minlen=8 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/" /etc/pam.d/common-password
    sudo sed -ie "s/pam_unix\.so.*/pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5/" /etc/pam.d/common-password
}

login_policies () {
    # /etc/logins.def
    
    # Back the file up 
    cp /etc/login.defs backup/pam/common-password

    # Replace the arguments
    sudo sed -ie "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS\\t90/" /etc/login.defs
    sudo sed -ie "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS\\t10/" /etc/login.defs
    sudo sed -ie "s/PASS_WARN_AGE.*/PASS_WARN_AGE\\t7/" /etc/login.defs
    sudo sed -ie "s/FAILLOG_ENAB.*/FAILLOG_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/LOG_UNKFAIL_ENAB.*/LOG_UNKFAIL_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/LOG_OK_LOGINS.*/LOG_OK_LOGINS\\tyes/" /etc/login.defs
    sudo sed -ie "s/SYSLOG_SU_ENAB.*/SYSLOG_SU_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/SYSLOG_SG_ENAB.*/SYSLOG_SG_ENAB\\tyes/" /etc/login.defs
    sudo sed -ie "s/LOGIN_RETRIES.*/LOGIN_RETRIES\\t5/" /etc/login.defs
    sudo sed -ie "s/ENCRYPT_METHOD.*/ENCRYPT_METHOD\\tSHA512/" /etc/login.defs
    sudo sed -ie "s/LOGIN_TIMEOUT.*/LOGIN_TIMEOUT\\t60/" /etc/login.defs
}

account_policies () {
    # common-auth
    # Assumes you have ran user_policies_install
    
    RANBEFORE=$(grep "pam_tally2.so" /etc/pam.d/common-auth)
    if [[ -z $RANBEFORE ]]
    then 
        echo "auth required pam_tally2.so deny=5 onerr=fail unlock_time=1800 audit even_deny_root silent" | sudo tee -a /etc/pam.d/common-auth > /dev/null
    fi
}


# -------------------- APT functions -------------------- 
autoupdate () {
    # Files necessary:
    #   NONE
    sudo apt install unattended-upgrades apt-listchanges
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

    echo "${RED}Please make sure you are 100% sure that there is no critcial services in this before running!!${RESET}"
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

# -------------------- Malware functions --------------------
anti_malware_software () {
    # Files necessary:
    #   NONE
    sudo apt install -y clamav, rkhunter, chrootkit, lynis 
}

run_antimalware () {
    # Files necessary:
    #   NONE
    chkrootkit -q

    rkhunter --update
    rkhunter --propupd
    rkhunter -c --enable all --disable none

    systemctl stop clamav-freshclam
    freshclam --stdout
    systemctl start clamav-freshclam
    clamscan -r -i --stdout --exclude-dir="^/sys"
}

# -------------------- Networking functions -------------------- 
networking_sysctl_config () {
    # Add a new local sysctl config file for the networking section
    sudo touch /etc/sysctl.d/cybercent-networking.conf

    # Add each config listed below 

    # IPv4 TIME-WAIT assassination protection
    echo net.ipv4.tcp_rfc1337=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    # IP Spoofing protection, Source route verification  
    # Scored
    echo net.ipv4.conf.all.rp_filter=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.default.rp_filter=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    # Ignore ICMP broadcast requests
    echo net.ipv4.icmp_echo_ignore_broadcasts=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    # Ignore Directed pings
    echo net.ipv4.icmp_echo_ignore_all=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    # Log Martians
    echo net.ipv4.conf.all.log_martians=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.icmp_ignore_bogus_error_responses=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    # Disable source packet routing
    echo net.ipv4.conf.all.accept_source_route=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.default.accept_source_route=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.all.accept_source_route=0  | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.accept_source_route=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    # Block SYN attacks
    echo net.ipv4.tcp_syncookies=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.tcp_max_syn_backlog=2048 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.tcp_synack_retries=2 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.tcp_syn_retries=4 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf # Try values 1-5


    # Ignore ICMP redirects
    echo net.ipv4.conf.all.send_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.default.send_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.all.accept_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.default.accept_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.all.secure_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv4.conf.default.secure_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf

    echo net.ipv6.conf.all.send_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf # ignore ?
    echo net.ipv6.conf.default.send_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf # ignore ?
    echo net.ipv6.conf.all.accept_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.accept_redirects=0  | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.all.secure_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf # ignore ?
    echo net.ipv6.conf.default.secure_redirects=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf # ignore ?

    # Note disabling ipv6 means you dont need the majority of the ipv6 settings

    # General options
    echo net.ipv6.conf.default.router_solicitations=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.accept_ra_rtr_pref=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.accept_ra_pinfo=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.accept_ra_defrtr=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.autoconf=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.dad_transmits=0 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.default.max_addresses=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.all.disable_ipv6=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf
    echo net.ipv6.conf.lo.disable_ipv6=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf


    # Reload the configs 
    # sudo sysctl -p /etc/sysctl.d/cybercent.conf
    sudo sysctl --system
}

firewall_setup () {
    # UFW Firewall setup
    # Since idk critical services, I didnt do these commands 
    #   * sudo ufw default deny incoming
    #   * sudo ufw default allow outgoing
    #   * sudo ufw allow <PORT>  (this is for each critical service) 

    sudo apt install -y ufw
    sudo ufw enable 
    sudo ufw status numbered
}

monitor_ports () { 
    # Pipes open tcp and udp ports into a less window
    sudo netstat -peltu | column -t | less
}

main_networking () {
    echo "${GREEN}[*] Configuring networking with sysctl ...${RESET}"
    networking_sysctl_config

    echo "${GREEN}[*] Installing and enabling UFW...${RESET}"
    firewall_setup

    local answer=""
    echo -n "${CYAN}See enumeration of local ports [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo 
            monitor_ports 
            ;;
        n|N)
            ;; # Do nothing
    esac
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

main_pam () {
    echo "${GREEN}[*] Installing libpam-cracklib and fail2ban ...${RESET}"
    user_policies_install

    echo "${GREEN}[*] Editing password policies | common-password ...${RESET}"
    password_policies

    echo "${GREEN}[*] Editing login policies | login.defs ...${RESET}"
    login_policies

    echo "${GREEN}[*] Editing account policies | common-auth ...${RESET}"
    account_policies
}

# Function to run everything
main () {
    # Make the backup directories
    mkdir -p backup/users
    mkdir -p backup/pam
    mkdir -p backup/apt
    mkdir -p backup/services
    mkdir -p backup/networking
    mkdir -p backup/system
    mkdir -p backup/malware
    mkdir -p backup/misc

    main_users
    main_pam
    main_networking
}
main
