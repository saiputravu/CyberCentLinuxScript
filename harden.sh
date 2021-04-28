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

DISTRO=$(lsb_release -i | cut -d: -f2 | sed "s/\\t//g")
CODENAME=$(lsb_release -c | cut -d: -f2 | sed "s/\\t//g")

APT=apt

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

disable_guests () {
    # Makes the self-added configs directory
    # Adds a new local config

    sudo mkdir -p /etc/lightdm/lightdm.conf.d
    sudo touch /etc/lightdm/lightdm.conf.d/myconfig.conf

    echo "[SeatDefaults]"                   | sudo tee /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "autologin-user=`whoami`"          | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "allow-guest=false"                | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "greeter-hide-users=true"          | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "greeter-show-manual-login=true"   | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "greeter-allow-guest=false"        | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "autologin-guest=false"            | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "AutomaticLoginEnable=false"       | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    echo "xserver-allow-tcp=false"          | sudo tee -a /etc/lightdm/lightdm.conf.d/myconfig.conf > /dev/null
    
    sudo lightdm --test-mode --debug 2> backup/users/lightdm_setup.log
    CONFIGSET=$(grep myconfig.conf backup/users/lightdm_setup.log)  
    if [[ -z CONFIGSET ]] 
    then 
        echo "${RED}LightDM config not set, please check manually.${RESET}"
        read -rp "Press <enter> to continue"
    fi

    sudo service lightdm restart
}

# -------------------- User Policies functions -------------------- 

user_policies_install () {
    # Installs required packages for user policies hardening 

    sudo $APT install --force-yes -y libpam-cracklib fail2ban
}

password_policies () {
    # common-password
    # Assumes you have run user_policies_install

    # Back the file up to correct directory
    cp /etc/pam.d/common-password backup/pam/common-password

    # sed -i is inplace so updates file, else prints to stdout
    sudo sed -ie "s/pam_cracklib\.so.*/pam_cracklib.so retry=3 minlen=8 difok=3 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1/" /etc/pam.d/common-password
    sudo sed -ie "s/pam_unix\.so.*/pam_unix.so obscure use_authtok try_first_pass sha512 minlen=8 remember=5/" /etc/pam.d/common-password

    # Remove any nullok (no password authentication)
    sudo sed -i 's/nullok//g' /etc/pam.d/common-password
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
    
    sudo sed -i 's/nullok//g' /etc/pam.d/common-auth
}


# -------------------- APT functions -------------------- 
enable_autoupdate () {
    # Files necessary:
    #   NONE
    sudo $APT install -y unattended-upgrades apt-listchanges
    
    # Set automatic updates
    echo 'APT::Periodic::Update-Package-Lists "1";'             | sudo tee /etc/apt/apt.conf.d/10periodic > /dev/null
    echo 'APT::Periodic::Download-Upgradeable-Packages "1";'    | sudo tee -a /etc/apt/apt.conf.d/10periodic > /dev/null
    echo 'APT::Periodic::Unattended-Upgrade "1";'               | sudo tee -a /etc/apt/apt.conf.d/10periodic > /dev/null
    echo 'APT::Periodic::AutocleanInterval "7";'                | sudo tee -a /etc/apt/apt.conf.d/10periodic > /dev/null

    echo 'APT::Periodic::Update-Package-Lists "1";'             | sudo tee /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    echo 'APT::Periodic::Download-Upgradeable-Packages "1";'    | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    echo 'APT::Periodic::Unattended-Upgrade "1";'               | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
    echo 'APT::Periodic::AutocleanInterval "7";'                | sudo tee -a /etc/apt/apt.conf.d/20auto-upgrades > /dev/null
}

fix_sources_list () { 
    local ubuntu_sources="
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME main restricted\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates main restricted\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME universe\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates universe\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME multiverse\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates multiverse\n
deb http://us.archive.ubuntu.com/ubuntu/ CHANGEME-backports main restricted universe multiverse\n
deb http://security.ubuntu.com/ubuntu CHANGEME-security main restricted\n
deb http://security.ubuntu.com/ubuntu CHANGEME-security universe\n
deb http://security.ubuntu.com/ubuntu CHANGEME-security multiverse\n

deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME main restricted\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates main restricted\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME universe\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates universe\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME multiverse\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-updates multiverse\n
deb-src http://us.archive.ubuntu.com/ubuntu/ CHANGEME-backports main restricted universe multiverse\n
deb-src http://security.ubuntu.com/ubuntu CHANGEME-security main restricted\n
deb-src http://security.ubuntu.com/ubuntu CHANGEME-security universe\n
deb-src http://security.ubuntu.com/ubuntu CHANGEME-security multiverse\n
"

    local debian_sources="
deb http://deb.debian.org/debian CHANGEME main\n
deb-src http://deb.debian.org/debian CHANGEME main\n
deb http://deb.debian.org/debian-security/ CHANGEME/updates main\n
deb-src http://deb.debian.org/debian-security/ CHANGEME/updates main\n
deb http://deb.debian.org/debian CHANGEME-updates main\n
deb-src http://deb.debian.org/debian CHANGEME-updates main\n
"

    sudo cp -r /etc/apt/sources.list* backup/apt/ 
    sudo rm -f /etc/apt/sources.list 
    case $DISTRO in 
        Debian)
            echo -e $debian_sources | sed "s/ deb/deb/g; s/CHANGEME/${CODENAME}/g" | sudo tee /etc/apt/sources.list > /dev/null
            ;;
        Ubuntu)
            echo -e $ubuntu_sources | sed "s/ deb/deb/g; s/CHANGEME/${CODENAME}/g" | sudo tee /etc/apt/sources.list > /dev/null
            ;;
        *)  
            sudo cp backup/apt/sources.list /etc/apt/sources.list
            echo -e "${RED}${BOLD}Distro not recognised!\nExiting#${RESET}"
            exit 1
            ;;

    esac
}

update () {
    # Files necessary:
    #   NONE
    sudo $APT update && sudo $APT upgrade -y
}

enumerate_packages () {
    # Files necessary:
    #   NONE

    sudo apt list --installed > backup/apt/apt_list_installed_packages.log
    sudo dpkg -l > backup/apt/dpkg_installed_packages.log # more useful

    # Manually installed
    sudo apt-mark showmanual > backup/apt/manually_installed_packages.log

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
        sudo $APT purge -y --force-yes $i
    done
}

# -------------------- Service functions --------------------
service_ssh () {
    # Unique config file each time
    sudo cp /etc/ssh/sshd_config backup/services/sshd_config_`date +%s`.bak

    sudo ufw allow ssh 

    # sshd_config 
    echo "Protocol 2" | sudo tee /etc/ssh/sshd_config > /dev/null

    echo "PermitRootLogin no"      | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PermitEmptyPasswords no" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "LoginGraceTime 2m"       | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "X11Forwarding no"         | sudo tee -a /etc/ssh/sshd_config > /dev/null 
    echo "AllowTcpForwarding no"    | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "AllowAgentForwarding no"  | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "UsePAM yes"                   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PasswordAuthentication no"    | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "HostBasedAuthentication no"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "RhostsRSAAuthentication no"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PubkeyAuthentication yes"     | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "IgnoreRhosts yes"             | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "StrictModes yes"              | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "UsePrivilegeSeparation yes"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PrintLastLog no"              | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PermitUserEnvironment no"     | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "SyslogFacility AUTH"          | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "LogLevel VERBOSE" | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "MaxAuthTries 3"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "MaxStartups 2"    | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "ChallengeResponseAuthentication no"   | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "KerberosAuthentication no"            | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "GSSAPIAuthentication no"              | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "UseDNS no"        | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "PermitTunnel no"  | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "ClientAliveInterval 300"  | sudo tee -a /etc/ssh/sshd_config > /dev/null
    echo "ClientAliveCountMax 0"    | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo 'MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256' | sudo tee -a /etc/ssh/sshd_config > /dev/null

    echo "Banner /etc/issue.net" | sudo tee -a /etc/ssh/sshd_config > /dev/null

    # New welcome banner
    echo "Cyber Centurion" | sudo tee /etc/issue.net > /dev/null

    GOODSYNTAX=$(sudo sshd -t)
    if [[ ! -z $GOODSYNTAX ]]
    then
        echo "${RED}Sshd config has some faults, please check script or ${BOLD}/etc/ssh/sshd_config${RESET}"
        read -rp ""
    fi

    sudo service ssh restart
}

service_samba () {
    # Unique config file each time
    sudo cp /etc/samba/smb.conf backup/services/smb_conf_`date +%s`.bak

    sudo ufw allow samba

    # smb.conf 
    echo "restrict anonymous = 2"       | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "encrypt passwords = True"     | sudo tee -a /etc/samba/smb.conf > /dev/null # Idk which one it takes
    echo "encrypt passwords = yes"      | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "read only = Yes"              | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "ntlm auth = no"               | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "obey pam restrictions = yes"  | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "server signing = mandatory"   | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "smb encrypt = mandatory"      | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "min protocol = SMB2"          | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "protocol = SMB2"              | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "guest ok = no"                | sudo tee -a /etc/samba/smb.conf > /dev/null
    echo "max log size = 24"            | sudo tee -a /etc/samba/smb.conf > /dev/null


    echo "${YELLOW}Please read the samba file ${BOLD}/etc/samba/smb.conf${RESET}${YELLOW} as well and check its contents${RESET}"

    sudo service smbd restart 
}

service_vsftpd () {
    # Unique config file each time
    sudo cp /etc/vsftpd/vsftpd.conf backup/services/vsftpd_conf_`date +%s`.bak

    sudo ufw allow ftp 
    sudo ufw allow 20

    # vsftpd.conf

    # Jail users to home directory (user will need a home dir to exist)
    echo "chroot_local_user=YES"                        | sudo tee /etc/vsftpd/vsftpd.conf > /dev/null
    echo "chroot_list_enable=YES"                       | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null
    echo "chroot_list_file=/etc/vsftpd.chroot_list"     | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null
    echo "allow_writeable_chroot=YES"                   | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # Only enable if you want files to be editable

    # Allow or deny users
    echo "userlist_enable=YES"                  | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null
    echo "userlist_file=/etc/vsftpd.userlist"   | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null
    echo "userlist_deny=NO"                     | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null

    # General config
    echo "anonymous_enable=NO"          | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # disable  anonymous login
    echo "local_enable=YES"             | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # permit local logins
    echo "write_enable=YES"             | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # enable FTP commands which change the filesystem
    echo "local_umask=022"              | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # value of umask for file creation for local users
    echo "dirmessage_enable=YES"        | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # enable showing of messages when users first enter a new directory
    echo "xferlog_enable=YES"           | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # a log file will be maintained detailing uploads and downloads
    echo "connect_from_port_20=YES"     | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # use port 20 (ftp-data) on the server machine for PORT style connections
    echo "xferlog_std_format=YES"       | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # keep standard log file format
    echo "listen=NO"                    | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # prevent vsftpd from running in standalone mode
    echo "listen_ipv6=YES"              | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # vsftpd will listen on an IPv6 socket instead of an IPv4 one
    echo "pam_service_name=vsftpd"      | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # name of the PAM service vsftpd will use
    echo "userlist_enable=YES"          | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # enable vsftpd to load a list of usernames
    echo "tcp_wrappers=YES"             | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null # turn on tcp wrappers

    echo "ascii_upload_enable=NO"   | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null 
    echo "ascii_download_enable=NO" | sudo tee -a /etc/vsftpd/vsftpd.conf > /dev/null 

    sudo service vsftpd restart 
}

service_pureftpd () {

    sudo cp /etc/pure-ftpd/pure-ftpd.conf backup/services/pure-ftpd_conf_`date +%s`.bak
    # Unique config file each time
    sudo ufw allow ftp 
    sudo ufw allow 20

    # pure-ftpd.conf

    echo "ChrootEveryone yes"           | sudo tee /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "NoAnonymous yes"              | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AnonymousOnly no"             | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AnonymousCanCreateDirs no"    | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AnonymousCantUpload yes"      | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AllowUserFXP no"              | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AllowAnonymousFXP no"         | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "DisplayDotFiles yes"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "ProhibitDotFilesWrite yes"    | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "ProhibitDotFilesRead no"      | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "DontResolve yes"              | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "VerboseLog yes"               | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "SyslogFacility ftp"           | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "PAMAuthenticate yes"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "UnixAuthenticate no"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "MaxClientsNumber 50"          | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "LimitRecursion 500 8"         | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "MaxClientsPerIp 3"            | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "MaxIdleTime 10"               | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "MaxLoad 4"                    | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "IPV4Only yes"                 | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "TLS 2"                        | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "Umask 133:022"                | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    echo "Daemonize yes"                | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "NoChmod yes"                  | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    # echo "KeepAllFiles yes"             | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "CreateHomeDir yes"            | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AutoRename yes"               | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "AntiWarez yes"                | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null
    echo "CustomerProof yes"            | sudo tee -a /etc/pure-ftpd/pure-ftpd.conf > /dev/null

    sudo service pure-ftpd restart 
}

service_proftpd () {
    # Unique config file each time
    sudo cp /etc/proftpd/proftpd.conf backup/services/proftpd_conf_`date +%s`.bak

    sudo ufw allow ftp 
    sudo ufw allow 20

    # proftpd.conf
    echo "Deny Filter \\*.*/"           | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "DelayEngine on"               | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "UseLastLog on"                | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "ServerIdent off"              | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "IdentLookups off"             | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "TLSEngine on"                 | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "TLSProtocol SSLv23"           | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "TLSRequired on"               | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "UseReverseDNS on"             | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "UseIPv6 off"                  | sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo 'AllowFilter "^[a-zA-Z0-9 ,]*$"'| sudo tee -a /etc/protpd/proftpd.conf > /dev/null
    echo "DeferWelcome on"              | sudo tee -a /etc/protpd/proftpd.conf > /dev/null

    sudo service proftpd restart 
}

service_apache2 () {
    # Unique config file each time
    sudo cp /etc/apache2/apache2.conf backup/services/apache2_conf_`date +%s`.bak
    sudo cp /etc/apache2/conf-available/security.conf backup/services/apache2_security_conf_`date +%s`.bak

    sudo ufw allow apache
    sudo ufw allow https 
    sudo ufw allow http

    # Mod security  & enabling/disabling modules
    sudo $APT install libapache2-mod-security2 -y

    sudo a2enmod userdir
    sudo a2enmod headers
    sudo a2enmod rewrite
    sudo a2dismod imap
    sudo a2dismod include
    sudo a2dismod info
    sudo a2dismod userdir
    echo "Yes, do as I say!" | sudo a2dismod autoindex

    # Ask to remove default index.html
    local answer=""
    echo -n "${CYAN}Remove default index.html [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo "" | sudo tee /var/www/html/index.html
            ;;
        n|N)
            ;; # Do nothing
    esac

    # apache.conf
    echo "HostnameLookups Off"              | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "LogLevel warn"                    | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "ServerTokens Prod"                | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "ServerSignature Off"              | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Options all -Indexes"             | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Header unset ETag"                | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Header always unset X-Powered-By" | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "FileETag None"                    | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "TraceEnable off"                  | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "Timeout 60"                       | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    
    echo "RewriteEngine On"                         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo 'RewriteCond %{THE_REQUEST} !HTTP/1\.1$'   | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo 'RewriteRule .* - [F]'                     | sudo tee -a /etc/apache2/apache2.conf > /dev/null

    echo '<IfModule mod_headers.c>'                         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo '    Header set X-XSS-Protection 1;'               | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo '</IfModule>'                                      | sudo tee -a /etc/apache2/apache2.conf > /dev/null

    # Secure /
    echo "<Directory />"            | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Options -Indexes"     | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    AllowOverride None"   | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Order Deny,Allow"     | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Options None"         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Deny from all"        | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "</Directory>"             | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    
    # Secure /var/www/html
    echo "<Directory /var/www/html>"    | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "    Options -Indexes"         | sudo tee -a /etc/apache2/apache2.conf > /dev/null
    echo "</Directory>"                 | sudo tee -a /etc/apache2/apache2.conf > /dev/null

    # security.conf
    # Enable HTTPOnly and Secure Flags
    echo 'Header edit Set-Cookie ^(.*)\$ \$1;HttpOnly;Secure'                                   | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Clickjacking Attack Protection
    echo 'Header always append X-Frame-Options SAMEORIGIN'                                      | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # XSS Protection
    echo 'Header set X-XSS-Protection "1; mode=block"'                                          | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Enforce secure connections to the server
    echo 'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"'    | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null  

    # MIME sniffing Protection
    echo 'Header set X-Content-Type-Options: "nosniff"'                                         | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Prevent Cross-site scripting and injections
    echo 'Header set Content-Security-Policy "default-src '"'self'"';"'                         | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

	# Secure root directory
    echo "<Directory />"            | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Options -Indexes"       | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  AllowOverride None"     | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Order Deny,Allow"       | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Deny from all"          | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "</Directory>"             | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # Secure html directory
    echo "<Directory /var/www/html>"        | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Options -Indexes -Includes"     | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  AllowOverride None"             | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Order Allow,Deny"               | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "  Allow from All"                 | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null
    echo "</Directory>"                     | sudo tee -a /etc/apache2/conf-available/security.conf > /dev/null

    # ssl.conf
    # TLS only
    sudo sed -i "s/SSLProtocol.*/SSLProtocol –ALL +TLSv1 +TLSv1.1 +TLSv1.2/" /etc/apache2/mods-available/ssl.conf
    # Stronger cipher suite
    sudo sed -i "s/SSLCipherSuite.*/SSLCipherSuite HIGH:\!MEDIUM:\!aNULL:\!MD5:\!RC4/" /etc/apache2/mods-available/ssl.conf

    sudo chown -R root:root /etc/apache2
    sudo chown -R root:root /etc/apache 2> /dev/null

    sudo service apache2 restart 
}

service_php () {
    local PHPCONFIG=/etc/php5/apache2/php.ini
    if [[ ! -f $PHPCONFIG ]]
    then 
        echo "${RED}Php.ini does not exist at ${PHPCONFIG}${RESET}"
        echo -n "${YELLOW}Please input the new location: ${RESET}"
        read -rp "" PHPCONFIG 
        if [[ ! -f $PHPCONFIG ]]
        then
            echo "${RED}${BOLD}The file you have entered does not exist, skipping php ... ${RESET}"
            return 1
        fi
    fi

    # Unique config file each time
    sudo cp $PHPCONFIG backup/services/php_ini_`date +%s`.bak

    # Safe mode
    echo 'sql.safe_mode = On'   | sudo tee -a $PHPCONFIG
    echo 'safe_mode = On'       | sudo tee -a $PHPCONFIG
    echo 'safe_mode_gid = On'   | sudo tee -a $PHPCONFIG

    # Disable Global variables
    echo 'register_globals = Off' | sudo tee -a $PHPCONFIG

    # Disable tracking, HTML, and display errors
    sudo sed -i "s/^;\?track_errors.*/track_errors = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?html_errors.*/html_errors = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?display_errors.*/display_errors = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?expose_php.*/expose_php = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?mail\.add_x_header.*/mail\.add_x_header = Off/" $PHPCONFIG

    # Disable Remote File Includes
    sudo sed -i "s/^;\?allow_url_fopen.*/allow_url_fopen = Off/" $PHPCONFIG
    sudo sed -i "s/^;\?allow_url_include.*/allow_url_include = Off/" $PHPCONFIG

    # Restrict File Uploads
    sudo sed -i "s/^;\?file_uploads.*/file_uploads = Off/" $PHPCONFIG

    # Control POST/Upload size
    sudo sed -i "s/^;\?post_max_size.*/post_max_size = 1K/" $PHPCONFIG
    sudo sed -i "s/^;\?upload_max_filesize.*/upload_max_filesize = 2M/" $PHPCONFIG

    # Protect sessions
    sudo sed -i "s/^;\?session\.cookie_httponly.*/session\.cookie_httponly = 1/" $PHPCONFIG

    # General
    echo "magic_quotes_gpc = Off" | sudo tee -a $PHPCONFIG
    sudo sed -i "s/^;\?session\.use_strict_mode.*/session\.use_strict_mode = On/" $PHPCONFIG

    # sudo sed -i 
    sudo sed -i "s/^;\?disable_functions.*/disable_functions = php_uname, getmyuid, getmypid, passthru, leak, listen, diskfreespace, tmpfile, link, ignore_user_abord, shell_exec, dl, set_time_limit, exec, system, highlight_file, source, show_source, fpaththru, virtual, posix_ctermid, posix_getcwd, posix_getegid, posix_geteuid, posix_getgid, posix_getgrgid, posix_getgrnam, posix_getgroups, posix_getlogin, posix_getpgid, posix_getpgrp, posix_getpid, posix, _getppid, posix_getpwnam, posix_getpwuid, posix_getrlimit, posix_getsid, posix_getuid, posix_isatty, posix_kill, posix_mkfifo, posix_setegid, posix_seteuid, posix_setgid, posix_setpgid, posix_setsid, posix_setuid, posix_times, posix_ttyname, posix_uname, proc_open, proc_close, proc_get_status, proc_nice, proc_terminate, phpinfo/" $PHPCONFIG
    # disable_functions = exec,shell_exec,passthru,system,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source,proc_open,pcntl_exec 

    sudo sed -i "s/^;\?max_execution_time.*/max_execution_time = 30/" $PHPCONFIG
    sudo sed -i "s/^;\?max_input_time.*/max_input_time = 30/" $PHPCONFIG
    sudo sed -i "s/^;\?memory_limit.*/memory_limit = 40M/" $PHPCONFIG
    # open_basedir = "/home/user/public_html" # -> correct html base dir 


    echo "${YELLOW}Checkout the PHP section in the guide, install suhosin${RESET}"
    sudo service apache2 restart
}

service_nginx () {
    # Unique config file each time
    sudo cp /etc/nginx/nginx.conf backup/services/nginx_conf_`date +%s`.bak
    sudo cp /etc/nginx/sites-available/default backup/services/nginx_default_`date +%s`.bak

    sudo ufw allow 'Nginx Full'
    sudo ufw allow https 
    sudo ufw allow http

    # Ask to remove default index.html
    local answer=""
    echo -n "${CYAN}Remove default index.html [${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo "" | sudo tee /var/www/html/index.html
            ;;
        n|N)
            ;; # Do nothing
    esac

    # nginx.conf
    ETAGEXISTS=$(grep -i etag /etc/nginx/nginx.conf)

    if [[ -z $ETAGEXISTS ]]
    then
        sudo sed -ie "s/#\?\\s*server_tokens.*/server_tokens off;\n\tetag off;/g" /etc/nginx/nginx.conf
    else
        sudo sed -ie "s/#\?\\s*server_tokens.*/server_tokens off;/g" /etc/nginx/nginx.conf
        sudo sed -ie "s/#\?\\s*etag.*/etag off;/g" /etc/nginx/nginx.conf
    fi

    # Use strong cipher suites
    sudo sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_ciphers ECDHE-RSA-AES256-GCM-SHA512:DHE-RSA-AES256-GCM-SHA512:ECDHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-SHA384;/" /etc/nginx/nginx.conf

    # Set ssl session timeout
    sudo sed -i "s/ssl_prefer_server_ciphers on;/ssl_prefer_server_ciphers on;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

    # Set ssl session cache
    sudo sed -i "s/ssl_session_timeout 5m;/ssl_session_cache shared:SSL:10m;\nssl_session_timeout 5m;/" /etc/nginx/nginx.conf

    # sites-available/default
    # Enable HttpOnly and Secure flags
    sudo sed -i "s|^\s*try_files \\\$uri \\\$uri/ =404;|try_files \\\$uri \\\$uri/ =404;\nproxy_cookie_path / \"/; secure; HttpOnly\";|" /etc/nginx/sites-available/default

    # Clickjacking Attack Protection
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Frame-Options DENY;|" /etc/nginx/sites-available/default

    # XSS Protection
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-XSS-Protection \"1; mode=block\";|" /etc/nginx/sites-available/default

    # Enforce secure connections to the server
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Strict-Transport-Security \"max-age=31536000; includeSubdomains;\";|" /etc/nginx/sites-available/default

    # MIME sniffing Protection
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Content-Type-Options nosniff;|" /etc/nginx/sites-available/default

    # Prevent Cross-site scripting and injections
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header Content-Security-Policy \"default-src 'self';\";|" /etc/nginx/sites-available/default

    # Set X-Robots-Tag
    sudo sed -i "s|root /var/www/html;|root /var/www/html;\nadd_header X-Robots-Tag none;|" /etc/nginx/sites-available/default

    sudo service nginx restart 
}


service_mysql () {
    # Unique config file each time
    sudo cp $PHPCONFIG backup/services/php_ini_`date +%s`.bak

    sudo ufw allow mysql 

    echo "${}[*] Setup mysql by running 'sudo mysql_secure_installation' ${RESET}"
    read -rp "Press <enter> when you are done" 

    #Disables LOCAL INFILE
    echo "local-infile=0" | sudo tee -a /etc/mysql/my.cnf

    #Lowers database privileges
    echo "skip-show-database" | sudo tee -a /etc/mysql/my.cnf

    # Disable remote access
    echo "bind-address=127.0.0.1" | sudo tee -a /etc/mysql/my.cnf
    sed -i '/bind-address/ c\bind-address = 127.0.0.1' /etc/mysql/my.cnf

    #Disables symbolic links
    echo "symbolic-links=0" | sudo tee -a /etc/mysql/my.cnf

    #Sets password expiration
    echo "default_password_lifetime = 90" | sudo tee -a /etc/mysql/my.cnf

    #Sets root account password
    echo "[mysqladmin]" | sudo tee -a /etc/mysql/my.cnf
    echo "user = root" | sudo tee -a /etc/mysql/my.cnf
    echo "password = CyberPatriot1!" | sudo tee -a /etc/mysql/my.cnf

    #Sets packet restrictions
    echo "key_buffer_size         = 16M" | sudo tee -a /etc/mysql/my.cnf
    echo "max_allowed_packet      = 16M" | sudo tee -a /etc/mysql/my.cnf

    sudo service mysql restart
}

# -------------------- Malware functions --------------------
anti_malware_software () {
    # Files necessary:
    #   NONE
    sudo $APT install -y chkrootkit clamav rkhunter apparmor apparmor-profiles 
}

run_antimalware () {
    # Files necessary:
    #   NONE
    sudo chkrootkit -q

    sudo rkhunter --update
    sudo rkhunter --propupd
    sudo rkhunter -c --enable all --disable none

    sudo systemctl stop clamav-freshclam
    sudo freshclam --stdout
    sudo systemctl start clamav-freshclam
    sudo clamscan -r -i --stdout --exclude-dir="^/sys"

    sudo wget https://downloads.cisofy.com/lynis/lynis-2.7.0.tar.gz -O ~/Desktop/lynis.tar.gz
    sudo tar -xzf ~/Desktop/lynis.tar.gz --directory /usr/share
    #/usr/share/lynis/lynis update info   NEED TO FIX/HELP
    #/usr/share/lynis/lynis audit system  NEED TO FIX/HELP
}

apparmor () {
    aa-enforce /etc/apparmor.d/*
}

# -------------------- Networking functions -------------------- 
networking_sysctl_config () {
    # Add a new local sysctl config file for the networking section
    sudo touch /etc/sysctl.d/cybercent-networking.conf

    # Add each config listed below 

    # IPv4 TIME-WAIT assassination protection
    echo net.ipv4.tcp_rfc1337=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # IP Spoofing protection, Source route verification  
    # Scored
    echo net.ipv4.conf.all.rp_filter=1      | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.rp_filter=1  | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Ignore ICMP broadcast requests
    echo net.ipv4.icmp_echo_ignore_broadcasts=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Ignore Directed pings
    echo net.ipv4.icmp_echo_ignore_all=1 | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Log Martians
    echo net.ipv4.conf.all.log_martians=1               | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.icmp_ignore_bogus_error_responses=1   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Disable source packet routing
    echo net.ipv4.conf.all.accept_source_route=0        | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.accept_source_route=0    | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.all.accept_source_route=0        | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_source_route=0    | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Block SYN attacks
    echo net.ipv4.tcp_syncookies=1          | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.tcp_max_syn_backlog=2048  | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.tcp_synack_retries=2      | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.tcp_syn_retries=4         | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # Try values 1-5


    # Ignore ICMP redirects
    echo net.ipv4.conf.all.send_redirects=0         | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.send_redirects=0     | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.all.accept_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.accept_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.all.secure_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv4.conf.default.secure_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    echo net.ipv6.conf.all.send_redirects=0         | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?
    echo net.ipv6.conf.default.send_redirects=0     | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?
    echo net.ipv6.conf.all.accept_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.all.secure_redirects=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?
    echo net.ipv6.conf.default.secure_redirects=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null # ignore ?

    # Note disabling ipv6 means you dont need the majority of the ipv6 settings

    # General options
    echo net.ipv6.conf.default.router_solicitations=0   | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_ra_rtr_pref=0     | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_ra_pinfo=0        | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.accept_ra_defrtr=0       | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.autoconf=0               | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.dad_transmits=0          | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.default.max_addresses=1          | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.all.disable_ipv6=1               | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null
    echo net.ipv6.conf.lo.disable_ipv6=1                | sudo tee -a /etc/sysctl.d/cybercent-networking.conf > /dev/null

    # Reload the configs 
    # sudo sysctl -p /etc/sysctl.d/cybercent.conf
    sudo sysctl --system

    # Disable IPV6
    sudo sed -i '/^IPV6=yes/ c\IPV6=no\' /etc/default/ufw
    echo 'blacklist ipv6' | sudo tee -a /etc/modprobe.d/blacklist > /dev/null
}

firewall_setup () {
    # UFW Firewall setup
    # Since idk critical services, I didnt do these commands 
    #   * sudo ufw default deny incoming
    #   * sudo ufw default allow outgoing
    #   * sudo ufw allow <PORT>  (this is for each critical service) 

    # Flush/Delete firewall rules
    sudo iptables -F
    sudo iptables -X
    sudo iptables -Z

    sudo $APT install -y ufw
    sudo ufw enable 
    sudo ufw logging full
    sudo ufw deny 23    #Block Telnet
    sudo ufw deny 2049  #Block NFS
    sudo ufw deny 515   #Block printer port
    sudo ufw deny 111   #Block Sun rpc/NFS
    sudo ufw status verbose > backup/networking/firewall_ufw.log 

    # Iptables specific
    # Block null packets (DoS)
    sudo iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

    # Block syn-flood attacks (DoS)
    sudo iptables -A INPUT -p tcp ! --syn -m state --state NEW -j DROP

    #Drop incoming packets with fragments
    sudo iptables -A INPUT -f -j DROP

    # Block XMAS packets (DoS)
    sudo iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

    # Allow internal traffic on the loopback device
    sudo iptables -A INPUT -i lo -j ACCEPT

    # Allow ssh access
    # sudo iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT

    # Allow established connections
    sudo iptables -I INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

    # Allow outgoing connections
    sudo iptables -P OUTPUT ACCEPT

    # Set default deny firewall policy
    # sudo iptables -P INPUT DROP

    #Block Telnet
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 23 -j DROP

    #Block NFS
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 2049 -j DROP

    #Block X-Windows
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 6000:6009 -j DROP

    #Block X-Windows font server
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 7100 -j DROP

    #Block printer port
    sudo iptables -A INPUT -p tcp -s 0/0 -d 0/0 --dport 515 -j DROP

    #Block Sun rpc/NFS
    sudo iptables -A INPUT -p udp -s 0/0 -d 0/0 --dport 111 -j DROP

     #Deny outside packets from internet which claim to be from your loopback interface.
    sudo iptables -A INPUT -p all -s localhost  -i eth0 -j DROP

    # Save rules
    sudo iptables-save > /etc/sudo iptables/rules.v4

}

monitor_ports () { 
    # Pipes open tcp and udp ports into a less window
    sudo netstat -peltu | column -t > backup/networking/open_ports.log

    sudo $APT install nmap -y
    sudo nmap -oN backup/networking/nmap.log -p- -v localhost 
    sudo $APT purge nmap -y
}

# -------------------- System functions -------------------- 
system_sysctl_config() {

    # Add a new config file
    sudo touch /etc/sysctl.d/cybercent-networking.conf

    # Add these configs
    echo kernel.dmesg_restrict=1            | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored
    echo fs.suid_dumpable=0                 | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Core dumps # Scored
    echo kernel.msgmnb=65536                | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.msgmax=65536                | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.sysrq=0                     | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.maps_protect=1              | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.core_uses_pid=1             | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.shmmax=68719476736          | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.shmall=4294967296           | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.exec_shield=1               | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.panic=10                    | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.kptr_restrict=2             | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo vm.panic_on_oom=1                  | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo fs.protected_hardlinks=1           | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo fs.protected_symlinks=1            | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null
    echo kernel.randomize_va_space=2        | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored ASLR; 2 = full; 1 = semi; 0 = none
    echo kernel.unprivileged_userns_clone=0 | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored
    echo kernel.ctrl-alt-del=0              | sudo tee -a /etc/sysctl.d/cybercent-system.conf > /dev/null # Scored CTRL-ALT-DEL disable

    sudo sysctl --system
}

disable_ctrl_alt_del () {
    echo 'exec shutdown -r now "Control-Alt-Delete pressed"' | sudo tee -a /etc/init/control-alt-delete.conf
    
    sudo systemctl mask ctrl-alt-del.target
    sudo systemctl daemon-reload
}

file_perms () {
    sudo chown root:root /etc/fstab     # Scored
    sudo chmod 644 /etc/fstab           # Scored
    sudo chown root:root /etc/group     # Scored
    sudo chmod 644 /etc/group           # Scored
    sudo chown root:root /etc/shadow    # Scored
    sudo chmod 400 /etc/shadow  	    # Scored	
    sudo chown root:root /etc/apache2   # Scored
    sudo chmod 755 /etc/apache2         # Scored

    sudo chmod 0600 /etc/securetty
    sudo chmod 644 /etc/crontab
    sudo chmod 640 /etc/ftpusers
    sudo chmod 440 /etc/inetd.conf
    sudo chmod 440 /etc/xinetd.conf
    sudo chmod 400 /etc/inetd.d
    sudo chmod 644 /etc/hosts.allow
    sudo chmod 440 /etc/ers
    sudo chmod 640 /etc/shadow              # Scored
    sudo chmod 600 /boot/grub/grub.cfg      # Scored
    sudo chmod 600 /etc/ssh/sshd_config     # Scored
    sudo chmod 600 /etc/gshadow-            # Scored
    sudo chmod 600 /etc/group-              # Scored
    sudo chmod 600 /etc/passwd-             # Scored

    sudo chown root:root /etc/ssh/sshd_config # Scored
    sudo chown root:root /etc/passwd-         # Scored
    sudo chown root:root /etc/group-          # Scored
    sudo chown root:root /etc/shadow          # Scored
    sudo chown root:root /etc/securetty
    sudo chown root:root /boot/grub/grub.cfg  # Scored

    sudo chmod og-rwx /boot/grub/grub.cfg  	# Scored
    sudo chown root:shadow /etc/shadow-
    sudo chmod o-rwx,g-rw /etc/shadow-
    sudo chown root:shadow /etc/gshadow-
    sudo chmod o-rwx,g-rw /etc/gshadow-

    # Idk about this one chief 

    # sudo touch /etc/cron.allow
    # sudo touch /etc/at.allow
    # sudo chmod og-rwx /etc/cron.allow
    # sudo chmod og-rwx /etc/at.allow
    # sudo chown root:root /etc/cron.allow
    # sudo chown root:root /etc/at.allow
    # sudo chown root:root /etc/cron.d
    # sudo chmod og-rwx /etc/cron.d
    # sudo chown root:root /etc/crontab
    # sudo chmod og-rwx /etc/crontab
    # sudo chmod -R g-wx,o-rwx /var/log/*
}

set_grub_password () {
    echo "${GREEN}Setting the GRUB password to" '"CyberPatriot1!"' "make sure to log in as root at startup.${RESET}"
    #Secures Grub and sets password CyberPatriot1!
    sudo $APT install grub-common -y
    echo "set superusers=\"root\"" | sudo tee -a /etc/grub.d/40_custom
    echo "password_pbkdf2 root grub.pbkdf2.sha512.10000.80D8ACE911690CBCE96A4B94DB030A138377FA49F6F03EB84DFB388E5D6A9746F8E81B92265CF6535ACEBE0C0B2DF5189E362493A2A9F5395DB87524D94F07D4.CECEB26E93C1FD33EF69D59D71FB7B51562C06385A5466B4138A9687D1248915555DE07495C87A50C75333FC2F3751B99605430241EF4FD30494477B5C2C9D9A" | sudo tee -a /etc/grub.d/40_custom
    update-grub
}

# -------------------- Misc functions -------------------- 

delete_media () {
    sudo find / -name '*.mp3' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.mov' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.mp4' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.avi' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.mpg' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.mpeg' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.flac' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.m4a' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.flv' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find / -name '*.ogg' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find /home -name '*.gif' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find /home -name '*.png' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find /home -name '*.jpg' -type f -exec mv {} backup/misc \; 2> /dev/null
    sudo find /home -name '*.jpeg' -type f -dexec mv {} backup/misc \; 2> /dev/null
}

chattr_all_config_files () {
    # Chattr all files that will need to be edited by script
    sudo find /etc/ -type f -exec chattr -i {} \;
    sudo find /bin/ -type f -exec chattr -i {} \;
    sudo find /home/ -type f -exec chattr -i {} \;
}

# -------------------- Main functions -------------------- 

main_apt () {
    echo "${GREEN}[*] Reverting sources.list file to default ...${RESET}"
    fix_sources_list
    sudo $APT update

    echo "${GREEN}[*] Enabling auto updates ...${RESET}"
    enable_autoupdate

    echo "${GREEN}[*] Uninstalling any packages breaching policies ... ${RESET}"
    remove_malware

    echo "${GREEN}[*] Updating all packages (this may take a long time) ... ${RESET}"
    update

    echo "${GREEN}[*] Enumerating packages ${BOLD}saved to backups/apt/${RESET}"
    enumerate_packages
}

main_users () {
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

    echo "${GREEN}[*] Lightdm configs ${RESET}"
    disable_guests

    # Order ran 
    # delete_unauthorised_users
    # delete_unauthorised_sudoers
    # add_new_users
    # change_users_passwords
    # users_check_uid_0
    # check_shadow_password
    # disable_guests
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

main_system () {
    echo "${GREEN}[*] Configuring system with sysctl ...${RESET}"
    system_sysctl_config

    echo "${GREEN}[*] Disabling CTRL+ALT+DELETE ...${RESET}"
    disable_ctrl_alt_del

    echo "${GREEN}[*] Setting correct file permissions for sensitive files ...${RESET}"
    file_perms

    local answer=""
    echo -n "${CYAN}Set grub password to" '"CyberPatriot!"' "[${GREEN}y${CYAN}|${RED}N${CYAN}] : ${RESET}"
    read -rp "" answer
    case $answer in 
        y|Y)
            echo 
            set_grub_password
            ;;
        n|N)
            ;; # Do nothing
    esac
}

# Function to run everything
main () {
    echo -n "${CLEARSCREEN}"
    echo "${GREEN}For best performance, please run this script using ${BOLD}TMUX${RESET}"

    # Make the backup directories
    mkdir -p backup/users
    mkdir -p backup/pam
    mkdir -p backup/apt
    mkdir -p backup/services
    mkdir -p backup/networking
    mkdir -p backup/system
    mkdir -p backup/malware
    mkdir -p backup/misc

    # Ensure all config files can be edited
    chattr_all_config_files

    # Apt fast install
    sudo add-apt-repository ppa:apt-fast/stable -y
    sudo apt-get update
    sudo DEBIAN_FRONTEND=noninteractive apt install -y apt-fast && APT=apt-fast

    # Each main section
    main_apt
    main_users
    main_pam
    main_networking
    main_system
}
main
