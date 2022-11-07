#!/bin/bash
# set -x
###
# copy this file to :/ dir ->
# scp ~/path_to_file/zeus_plus.sh root@xxx.xxx.xxx.xxx:/
#
# chang permissions ->
# ssh root@xxx.xxx.xxx.xxx  'chmod 755 /zeus_plus.sh'
# 
# login as root User ->
# ssh root@xxx.xxx.xxx.xxx
#
# run script  (install additional packages , then choose [1] to  create mno user  and type new password->
# /zeus_plus.sh
# choose [9] to exit
# exit ( close ssh connect)
#
# Login as Dash Admin (eg ssh mno@xxx.xxx.xxx.xxx)
# run script ->
# zeus_plus.sh
# choose [1] Install and configure a new DASH Masternodes
# You will need to restart the server during installation (press any key when ready to reboot)
#
# login as Dasd Admin with new ssh port, eg 1234)-->
# eg ssh mno@xxx.xxx.xxx.xxx -p1234
#
# run script ->
# zeus_plus.sh
# enter your bls keys or just type ENTER for default
#
#  wait for sync to complete (only dash01 )
# 	run -->
#  zeus_plus.sh and chose [6] refactor Masterodes
# 	
# 
######
# # you can define the full synchronization time -->
# startDate=$(sudo grep "Synchronizing blockheaders, height: 2000" /home/dash01/.dashcore/debug.log | awk '{print $1}')
# startDateStamp=$(date --date=$startDate +"%s")
# finalDate=$(sudo grep "CMasternodeSync::SwitchToNextAsset -- Sync has finished" /home/dash01/.dashcore/debug.log | awk '{print $1}')
# finalDateStamp=$(date --date=$startDate1 +"%s")
# diff=$(($finalDateStamp  - $startDateStamp))
# date -d@"$diff" -u +%H:%M:%S
# sise debug.log 550 Mb! 

##############
#
# Main code :
#
##############

# # Define some colours
txtblk='\e[0;30m' # Black - Regular
txtred='\e[0;31m' # Red
txtgrn='\e[0;32m' # Green
txtylw='\e[0;33m' # Yellow
txtblu='\e[0;34m' # Blue
txtpur='\e[0;35m' # Purple
txtcyn='\e[0;36m' # Cyan
txtwht='\e[0;37m' # White
bldblk='\e[1;30m' # Black - Bold
bldred='\e[1;31m' # Red
bldgrn='\e[1;32m' # Green
bldylw='\e[1;33m' # Yellow
bldblu='\e[1;34m' # Blue
bldpur='\e[1;35m' # Purple
bldcyn='\e[1;36m' # Cyan
bldwht='\e[1;37m' # White
unkblk='\e[4;30m' # Black - Underline
undred='\e[4;31m' # Red
undgrn='\e[4;32m' # Green
undylw='\e[4;33m' # Yellow
undblu='\e[4;34m' # Blue
undpur='\e[4;35m' # Purple
undcyn='\e[4;36m' # Cyan
undwht='\e[4;37m' # White
bakblk='\e[40m'   # Black - Background
bakred='\e[41m'   # Red
badgrn='\e[42m'   # Green
bakylw='\e[43m'   # Yellow
bakblu='\e[44m'   # Blue
bakpur='\e[45m'   # Purple
bakcyn='\e[46m'   # Cyan
bakwht='\e[47m'   # White
txtrst='\e[0m'    # Text Reset

check_dependencies(){

# check missing applications on your system and installing,
	nc -h >/dev/null 2>&1 || sudo apt install netcat
 	jq -V >/dev/null 2>&1 || sudo apt install jq
	figlet -V >/dev/null 2>&1 || sudo apt install figlet 
	
}

check_dependencies

# basic example default set to yes
# shure "question message" y && echo "answer yes" || echo "answer no"
# print "question message [Y/n]? : "
function shure(){
    if [ $# -gt 1 ] && [[ "$2" =~ ^[yY]*$ ]] ; then
        arg="[Y/n]"
        reg=$(locale noexpr)
        default=(0 1)
    else
        arg="[y/N]"
        reg=$(locale yesexpr)
        default=(1 0)
    fi
    read -p "$1 ${arg}? : " answer
    [[ "$answer" =~ $reg ]] && return ${default[1]} || return ${default[0]}
}

idCheck(){
	(( $(id -u) == 0 )) && return 1
	msg="$(basename "$ZEUS") is now checking if you have sudo access to the root account\\n"
	msg+="from this user $(whoami). You may be prompted for your password now.\\n"
	msg+="Enter your user's password when prompted. NO CHANGES will be made at this time,\\n"
	msg+="this is just a check.\\n"
	echo -e "$msg"
	sid=$(sudo id -u)
	(( $? != 0 )) && return 2
	(( sid == 0 )) && return 0
}

# The function takes two arguments, the size or the progress bar to display in chars
# and the percent complete.
# Will print part of the progress bar each time it is called, valid ranges are
# 0 to 100.  The function must be called with 100 to complete the progress bar
# and reset the terminal.
# An optional 3rd arg can be given to display as text to left of the progress bar.
printGraduatedProgressBar(){

	(( $# < 2 )) && return 1
	[[ "$1" =~ ^[0-9]+$ ]] || return 2
	(( $1 < 9 || $2 > 121 )) && return 3
	[[ "$2" =~ ^[0-9]+$ ]] || return 4
	(( $2 < 0 || $2 > 100 )) && return 5

	# Create the progress bar area and return the cursor to the left (D)
	# Up (A), Down (B), Right (C), Left (D)
	if (( $2 == 0 ));then
		spaces=
		progress=0
		for ((i=0; i<$1; i++));do spaces+=" ";done
		[[ ! -z "$3" ]] && text="$3 "
		echo -en "\\e[1;37m${text}[$spaces]\\e[0m\\e[$(($1+1))D"
	fi
	step=$((100 / $1))
	# Due to rounding, sometimes the step is too small causing overshoot
	# adjust for that.
	(($((step * $1))<100))&&((step++))
	while((progress<$2));do
		((progress+=step))
		echo -en "\\e[48;2;0;$((progress * 2 + 20));0m "
	done

	(( $2 == 100 )) && echo -e '\e[0m'
}

# 1st parameter is the number of blocks to print, it is mandatory.
# 2nd parameter is between 1 and 300 for the speed of the variance,
# 1 is the slowest, this parameter is optional.
# 3rd parameter is for the intensity, between 1 and 900, higher
# numbers tend to black, lower numbers tend to white.
busyLoop24bit(){
	(( $# < 1 )) && return 1
	[[ $1 =~ ^[0-9]+$ ]] || return 2
	i=$1
	[[ -z $2 ]] && speed=20||speed=$2
	[[ -z $3 ]] && intensity=42||intensity=$3
	[[ $speed =~ ^[0-9]+$ ]] || return 3
	[[ $intensity =~ ^[0-9]+$ ]] || return 4
	(( speed < 1 || speed > 300 )) && return 5
	(( intensity < 1 || intensity > 900 )) && return 6

	# Set the initial colour
	#r=$(( RANDOM % 256 ))
	#g=$(( RANDOM % 256 ))
	#b=$(( RANDOM % 256 ))
	r=0;g=0;b=0
	while ((i--)) ;do
		r_delta=$(( speed - RANDOM % intensity ))
		g_delta=$(( speed - RANDOM % intensity ))
		b_delta=$(( speed - RANDOM % intensity ))

		r=$((r + r_delta))
		g=$((g + g_delta))
		b=$((b + b_delta))

		((r<0))&&r=0;((r>255))&&r=255
		((g<0))&&g=0;((g>255))&&g=255
		((b<0))&&b=0;((b>255))&&b=255

		echo -en "\\e[48;2;$r;$g;$b""m "
	done
	echo -e '\e[0m'
}

# Checks the Operating system for compatibility with this tool.
# Returns 0 for successful confirmation of Debian or Ubuntu OS.
# Returns 1 for Raspbian.
# Returns 2 for Fedora - Maybe be a supported OS in a later version
# Returns 9 for all other OSs.
osCheck(){
	if grep ^NAME /etc/os-release|grep -qi "Ubuntu\|Debian"
	then
		echo "OS Check passed, operating system is Debian based."
		return 0
	elif grep ^NAME /etc/os-release|grep -qi Raspbian
	then
		echo "OS Check passed, operating system is Raspbian."
		return 1
	elif grep ^NAME /etc/os-release|grep -qi Fedora
	then
		echo "Fedora is not a currently supported OS, please install and manage your masternode manually."
		return 2
	else
		echo "Cannot identify your system, please install and manage your masternode manually."
	fi
	return 99
}

# Will print a random string that can be used for password, if a numerical parameter is given,
# then it will be used as the length of the string.
getRandomString(){
	length=${1:-32}
	< /dev/urandom tr -dc A-Za-z0-9 | head -c"${length}";echo
}

createMnoUser(){
	msg="Creating the Dash Admin user.\\n"
	echo -en "$msg"
	if grep -q 'Dash Admin' /etc/passwd &&\
	dash_admin=$(grep 'Dash Admin' /etc/passwd | awk 'BEGIN {FS= ":"} { print $1 }')
	then
		echo -en "Found existing Dash Admin  ( ${bldcyn}$dash_admin${txtrst} ) user on this system."
		grep $dash_admin /etc/group|grep -q sudo || { echo "Adding ${bldcyn}$dash_admin${txtrst} to the sudo group";usermod -aG sudo $dash_admin; }
		echo -en "Would you like to reset the password of the ${bldcyn}$dash_admin${txtrst} "
		shure "user? " y && setpasswd="Y"
	else
		echo "There is no Dash Admin user on this system, creating it now."
		# Attempt to delete the group in case this is a rogue entry.
# 		groupdel $dash_admin >/dev/null 2>&1
		echo -en "Enter the Dash Admin username eg ${bldcyn}mno${txtrst} [["${bldcyn}mno${txtrst}"]] " 
		read -r -p ":" dash_admin
		echo -e "\\n$dash_admin">>"$LOGFILE"
		dash_admin=${dash_admin:-mno}
		useradd -m -c "Dash Admin" $dash_admin -s /bin/bash -G sudo
		if (( $? != 0 ));then
			msg="Could not create user, this is bad.\\n"
			msg+="There may be some remnants of it in the passwd or group or shadow files.\\n"
			msg+="Check those files and clean them up and try again."
			echo -e "$msg"
			exit 1
		fi
		setpasswd="Y"
	fi
	if [[ ! -z "$setpasswd" ]];then
		msg="You will now be prompted to set a password for the ${bldcyn}$dash_admin${txtrst} user.\\n"
# 		msg+="Choose a long password and write it down, do not loose this password.\\n"
# 		msg+="It should be at least 14 characters long.  Below is a secure and unique password\\n"
# 		msg+="you can use for this account, be sure to keep a copy in your password vault if you do.\\n\\n"
# 		msg+="$(getRandomString 32)\\n\\n"
		echo -e "$msg"
		while ! passwd $dash_admin;do : ;done
		echo
		read -r -s -n1 -p "Press any key to continue. "
		echo
	fi
	unset setpasswd
		
	[[ ! -d /home/$dash_admin/bin ]] && mkdir /home/$dash_admin/bin
	cp "$ZEUS" /home/$dash_admin/bin&&chown -R $dash_admin:$dash_admin /home/$dash_admin/bin
	
	mkdir /home/$dash_admin/.ssh &>/dev/null
	chmod 0700 /home/$dash_admin/.ssh &>/dev/null
	touch /home/$dash_admin/.ssh/authorized_keys &>/dev/null
	chmod 0644 /home/$dash_admin/.ssh/authorized_keys &>/dev/null
	cp /root/.ssh/authorized_keys /home/$dash_admin/.ssh/authorized_keys &>/dev/null
	chown -v -R $dash_admin.$dash_admin /home/$dash_admin/.ssh &>/dev/null

	msg="The ${bldcyn}$dash_admin${txtrst} user is now ready to use, please logout and log back in as the ${bldcyn}$dash_admin${txtrst} user\\n"
	msg+="to continue with setting up your masternode.\\nThis script has been copied to the ${bldcyn}~/bin/${txtrst} directory of the ${bldcyn}$dash_admin${txtrst} user.\\n"
	msg+="When you have logged back in as ${bldcyn}$dash_admin${txtrst} by ${bldcyn}ssh $dash_admin@$ip${txtrst}, you can continue this script by typing in  ${bldcyn}$(basename "$ZEUS")${txtrst}\\n"
	msg+="and choose [${bldcyn}1${txtrst}] to continuing..."
	echo -e "$msg"
	read -r -s -n1 -p "Press any key to continue. "
	echo
	exit
}

createDash_commonUser(){
# set -x

if grep -q ^dash-common /etc/passwd
then
	echo "Found existing dash-common user on this system."
else
	sudo useradd -m -c dash-common dash-common -s /usr/sbin/nologin
	sudo mkdir -p /home/dash-common/.dashcore/blocks
	sudo chown -v -R dash-common.dash-common /home/dash-common/
	sudo chmod -v -R g+wxr /home/dash-common/
	sudo usermod -aG  dash-common $dash_admin
fi
# set -x
}

createDashUser(){

# set -x
	if grep -q ^dash0$1 /etc/passwd
	then
		echo "Found existing dash0$1 user on this system." 
	else
		echo "Creating the dash0$1 user."
		# Attempt to delete the group in case this is a rogue entry.
 		sudo groupdel dash0$1>/dev/null 2>&1
		sudo useradd -m -c dash0$1 dash0$1 -s /bin/bash -G dash-common
		if (( $? != 0 ));then
			msg="Could not create dash0$1 user, this is bad.\\n"
			msg+="There may be some remnants of it in the passwd or group or shadow files.\\n"
			msg+="Check those files and clean them up and try again."
			echo -e "$msg"
			exit 1
		fi
		sudo mkdir /home/dash0$1/.ssh
		sudo chmod 0700 /home/dash0$1/.ssh
		sudo touch /home/dash0$1/.ssh/authorized_keys
		sudo chmod 0644 /home/dash0$1/.ssh/authorized_keys
		sudo cp /root/.ssh/authorized_keys /home/dash0$1/.ssh/authorized_keys
		sudo chown -v -R dash0$1.dash0$1 /home/dash0$1/.ssh
	fi
	# Finally add the $dash_admin user to the dash0$1 group.
	sudo usermod -aG  dash0$1 $dash_admin
# set +x	
}	

qpreventRootSSHLogins(){
	grep ^PermitRootLogin /etc/ssh/sshd_config |tail -1|grep -q "PermitRootLogin no"\
	&& { echo "Login as root via ssh is already disabled, continuing...";return 0;}
	msg="**** Disabling root logins from ssh connections. ****\\n\\n"
	msg+="For security reasons we want to disable remote logins to the root user from now on.\\n"
	msg+="The root user exists on every UNIX/Linux machine and its password is being brute force\\n"
	msg+="attacked all the time!  From now on you must *always* logon with the $(whoami) user."
	echo -e "$msg"
	if (( $(id -u) != 0 )); then
		sudo bash -c \
		"grep -q \".*PermitRootLogin [ny][oe].*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*PermitRootLogin [ny][oe].*/PermitRootLogin no/g' /etc/ssh/sshd_config||\
		echo \"PermitRootLogin no\">>/etc/ssh/sshd_config"
	else echo "Only run this block as your Dash Admin (${bldcyn}mno${txtrst}) user, not root."; fi
	read -r -s -n1 -p "Press any key to continue. ";echo
}

preventRootSSHLogins(){
	dash_admin=$(whoami)
	grep ^PermitRootLogin /etc/ssh/sshd_config |tail -1|grep -q "PermitRootLogin no"\
	&& { echo "Login as root via ssh is already disabled, continuing...";return 0;}
	msg="Replace default ssh port (22) with a new port between 1024 and 65536.\\n"
	msg+="just type in ENTER use default.\\n"
	echo -e "$msg"
	option='n'
	until [[ "$option" = 'Y' || "$option" = 'y' ]];do
		read -r -p "Enter the new ssh port eg 1234 [[22]] : " new_ssh_port
		new_ssh_port=${new_ssh_port:-22}
		echo $new_ssh_port > /tmp/new_ssh_port
		echo -en "\nYou entered Port is \"${bldcyn}$new_ssh_port${txtrst}\".\\nPress [${bldcyn}Y${txtrst}]  to accept, [${bldcyn}N${txtrst}]  to re-enter. "
		read -r -n1 option
		echo -e "\\n$option">>"$LOGFILE"
		echo
		option=${option:-N}
	done
  	if (( $(id -u) != 0 )); then
		sudo bash -c \
		"grep -q \".*Port *.*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*Port .*/Port $new_ssh_port/g' /etc/ssh/sshd_config||\
		echo \"Port $new_ssh_port\">>/etc/ssh/sshd_config&&\
		grep -q \".*PermitRootLogin [nw][or].*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*PermitRootLogin [ny][oe].*/PermitRootLogin no/g' /etc/ssh/sshd_config||\
		echo \"PermitRootLogin no\">>/etc/ssh/sshd_config &&\
		grep -q \".*PasswordAuthentication [ny][oe].*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*PasswordAuthentication [ny][oe].*/PasswordAuthentication no/g' /etc/ssh/sshd_config||\
		echo \"PasswordAuthentication no\">>/etc/ssh/sshd_config &&\
		grep -q \".*PermitEmptyPasswords [ny][oe].*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*PermitEmptyPasswords [ny][oe].*/PermitEmptyPasswords no/g' /etc/ssh/sshd_config||\
		echo \"PermitEmptyPasswords no\">>/etc/ssh/sshd_config &&\
		grep -q \".*AllowUsers /*.*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*AllowUsers .*/AllowUsers root $dash_admin dash01 dash02 dash03  dash-common/g' /etc/ssh/sshd_config||\
		echo \"AllowUsers root $dash_admin dash01 dash02 dash03  dash-common\">>/etc/ssh/sshd_config &&\
		grep -q \".*ClientAliveInterval /*.*\" /etc/ssh/sshd_config &&\ 
		sed -i 's/.*ClientAliveInterval .*/ClientAliveInterval 30/g' /etc/ssh/sshd_config||\
		echo \"ClientAliveInterval 30\">>/etc/ssh/sshd_config &&\
		grep -q \".*TCPKeepAlive /*.*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*TCPKeepAlive .*/TCPKeepAlive yes/g' /etc/ssh/sshd_config||\
		echo \"TCPKeepAlive yes\">>/etc/ssh/sshd_config &&\
		grep -q \".*ClientAliveCountMax /*.*\" /etc/ssh/sshd_config &&\
		sed -i 's/.*ClientAliveCountMax .*/ClientAliveCountMax 99999/g' /etc/ssh/sshd_config||\
		echo \"ClientAliveCountMax 99999\">>/etc/ssh/sshd_config" 
		else echo "Only run this block as your $dash_admin user, not root."
	fi
	sudo /etc/init.d/ssh restart
	read -r -s -n1 -p "Press any key to continue. ";echo	
}

uninstallJunkPackages(){
	# Removing this list of programs should be safe for running of masternode and infact should make it more secure since
	# tmux and screen are good ways for hackers to hide their running sessions.
	# Remove polkit because CVE was discovered in it and it seems to be pretty much useless.
	# Doing it like this because if any one of the packages is unknown to the package manager, apt will do nothing, so remove them one by one.
	echo "Uninstalling unnecessary programs..."
	packages="screen tmux rsync usbutils pastebinit  libthai-data libthai0 eject ftp dosfstools command-not-found wireless-regdb ntfs-3g snapd libmysqlclient21 g++-10 gcc-10 policykit-1 libpolkit-gobject-1-0 popularity-contest"
	for package in $packages
	do
		echo "*** Removing $package ***"
		sudo apt-get -y remove "$package" --purge
	done
	# After removing all this cruft, I found the following was also needed to make systemd stop trying to bring up removed services.
	for service in apparmor.service console-setup.service snap.lxd.activate.service
	do
		sudo systemctl disable "$service"
	done

	sudo apt-get -y autoremove --purge
	sudo apt-get autoclean
	sudo apt-get clean
}

updateSystem(){

		msg="Updating your system using apt update/upgrade.\\n"
		msg+="Answer any prompts as appropriate...\\n"
		echo -e "$msg"

		# Doing it like this because on a fresh system it is possible a background task is locking the package manager causing this to fail for some time.
		until sudo apt-get update&&sudo apt-get upgrade;do echo "Trying again, please wait...";sleep 30;done

		uninstallJunkPackages

		echo "Finished applying system updates."

		echo " Install additional packages needed for masternode operation..."
		sudo apt-get -y install ufw python3 virtualenv git curl wget tor unzip pv bc jq speedtest-cli catimg &&\
		sudo apt-get autoremove --purge &&\
		sudo apt-get clean && echo "Additional packages were installed successfully..." ||\
		{ echo "There was an error installing the additional packages, exiting...";exit 2; }
}

YN_updateSystem(){
if [ -s /tmp/date_update ];then 
# 	Checking, when was the last updatete 
	last_update=$(echo $(tail -1 /tmp/date_update) | awk '{ print $1 }')
	l=$(( $nowEpoch - $last_update ))
	days=$((l / 86400))
	if [ $days -eq 0 ]; then 
	hours=$((l / 3600 ))
		echo return 1
		msg="System was updated $hours hour(s) ago! Skipping update... \n"
		echo -en "$msg"
	else		
		msg="system was updated $days ago\n"
		msg+="update now ? [y [Y], any other key to skipping... \n"
		echo -en "$msg"
		read -r -n1 option
		echo -e "\\n$option">>"$LOGFILE"
		echo
		option=${option:-Y}
		if [[ $option = [yY] ]]
		then
			updateSystem
			echo $nowEpoch >> /tmp/date_update
		else
			echo exit
		fi	
	fi	
else
	updateSystem
	echo $nowEpoch >> /tmp/date_update
fi	
}

disable_ipv6(){
	# set -x
	grep ^IPV6 /etc/default/ufw |tail -1|grep -q "IPV6=no"\
	&& { echo "IPV6 is already disabled, continuing...";return 0;}
	if [ `id -u` -ne 0 ]; then
	sudo bash -c \
	"grep -q \".*IPV6=[ny][oe].*\" /etc/default/ufw &&\
	sed -i 's/.*IPV6=[ny][oe].*/IPV6=no/g' /etc/default/ufw||\
	echo \"IPV6=no\">>/etc/default/ufw"
	else echo "IPV6=no"; fi
	# set +x
}

enableFireWall(){
	new_ssh_port=$(cat /tmp/new_ssh_port)
	echo "Checking for a firewall..."
	firewall=$(sudo ufw status)
	grep -q ^$new_ssh_port.tcp\ *[LA][IL][ML] <<<"$firewall" &&\
	grep -q ^9999.tcp\ *[LA][IL][ML] <<<"$firewall"
	if (( $? != 0 ));then
		echo "Setting up a firewall..."
		sudo ufw allow $new_ssh_port/tcp &&\
		sudo ufw limit $new_ssh_port/tcp &&\
		sudo ufw allow 9999/tcp &&\
		sudo ufw allow 9050/tcp &&\
		sudo ufw logging on &&\
		sudo ufw enable &&\
		echo "Firewall configured successfully!" ||\
		echo "Error enabling firewall."
	else
		echo "Your firewall is OK."
	fi
	
}

configureSwap(){
# set -x	
	echo "Checking your available swap space..."
	if (( $(free -m|awk '/Swap/ {print $2}') < 2048 ))
	then
		echo "Adding 6GB swap..."
		swapfile="/var/swapfile"
		[[ -f /var/swapfile ]] && swapfile="$swapfile.$RANDOM"
		sudo bash -c "fallocate -l 6G \"$swapfile\"&&\
		chmod 600 \"$swapfile\"&&\
		mkswap \"$swapfile\"&&\
		swapon \"$swapfile\"&&\
		grep -q \"^\"$swapfile\".none.swap.sw.0.0\" /etc/fstab ||\
		echo -e \"\"$swapfile\"\tnone\tswap\tsw\t0\t0\" >>/etc/fstab"
		(( $? != 0 )) && echo "Error adding swap."
	else
		echo "You already have enough swap space."
	fi
# set +x	
}

# Re-runable function to configure TOR for dash.
configureTOR(){
# set -x
	echo "Configuring TOR..."
	x=$(grep -c ^Co[no][tk][ri] /etc/tor/torrc)
	if((x != 3));then
		sudo bash -c "echo -e 'ControlPort 9051\nCookieAuthentication 1\nCookieAuthFileGroupReadable 1' >> /etc/tor/torrc"
	fi
	sudo systemctl enable --now tor
	sleep 1
# set +x
}

configureTORgroup(){

	echo "Configuring TOR group (debian_tor)..."
	group=$(procs=$(ps -A -O pid,ruser:12,rgroup:12,comm);grep $(pidof tor)<<<"$procs"|awk '{print $3}')
	if((PIPESTATUS == 0));then
		sudo usermod -aG "$group" dash0$1
	else
		echo "Error detecting the tor group name."
	fi
	sudo systemctl restart tor

}

# Re-runnable.
increaseNoFileParam(){

	echo "Checking open file limits..."
	nofile=$(sudo grep -v ^# /etc/security/limits.conf|grep dash|grep -o "nofile.*"|tail -1|awk '{print $2}')
	[[ -z $nofile ]] && nofile=0
	if ((nofile!=4096));then
		echo "Adjusting nofile limit in limits.conf"
		sudo sed -i 's/\(dash.*nofile.*\)/#\1/g' /etc/security/limits.conf
		echo "dash - nofile 4096"|sudo tee -a /etc/security/limits.conf
	fi
	if ! sudo grep -v ^# /etc/systemd/system.conf|grep -q DefaultLimitNOFILE=4096;then
		echo "Adjusting nofile limit in system.conf"
		sudo sed -i 's/\(^DefaultLimitNOFILE=.*\)/#\1/g' /etc/systemd/system.conf
		echo "DefaultLimitNOFILE=4096:524288"|sudo tee -a /etc/systemd/system.conf
	fi
	
}

# Returns:-
# 0 if the change was made
# 1 is no change was necessary.
addSysCtl(){
# set -x
	sudo grep -q "^vm\.overcommit_memory" /etc/sysctl.conf\
	&& return 1\
	|| { echo "Adjusting kernel parameter in /etc/sysctl.conf to optimise RAM usage.";sudo bash -c "echo \"vm.overcommit_memory=1\">>/etc/sysctl.conf";}
# set +x
}

rebootSystem(){
# set +x
	ip=$(hostname -I | awk '{ print $1}')
	msg="A reboot is required at this time to allow the changes to take effect\\n"
	msg+="and to verify the system is still working correctly.\\n"
	msg+="After reboot SSH connect: ${bldcyn}ssh $dash_admin@$ip -p$new_ssh_port${txtrst}, \\n"	
	msg+="type ${bldcyn}$(basename "$ZEUS")${txtrst} and choose [${bldcyn}1${txtrst}] continue installing the DASH masternode(s).\\n"	
	echo -e "$msg"
	read -r -s -n1 -p "Press any key when ready to reboot. "
	echo
	sudo reboot
# set -x
}

downloadInstallDash(){
	echo "Starting Download of dashcore..."
	echo "Checking machine type to determine package for download..."
	# Try to be smart and determine arch of this host.
	mach=$(uname -m)
	case $mach in
		armv7l)
			arch="arm-linux-gnueabihf"
			;;
		aarch64)
			arch="aarch64-linux-gnu"
			;;
		x86_64)
			arch="x86_64-linux-gnu"
			;;
		*)
			msg="ERROR: Machine type ($mach) not recognised.\\n"
			msg+="Could not download the dashcore binaries.  Aborting..."
			echo -e "$msg"
			return 1
			;;
	esac
	cd /tmp
	wget -q -O SHA256SUMS.asc https://github.com/dashpay/dash/releases/latest/download/SHA256SUMS.asc ||\
	{ echo "Download of SHA256SUMS.asc has failed!  Aborting..."; return 3;}
	echo "Download of SHA256SUMS.asc completed successfully!"
	awk_string="awk '/dashcore.*$mach.*.tar.gz/ {print \$2}' SHA256SUMS.asc"
	filename=$(eval "$awk_string")
	wget -q -O "$filename" https://github.com/dashpay/dash/releases/latest/download/"$filename"
	file_hash=$(sha256sum "$filename"|awk '{print $1}')
	grep -i "$file_hash" SHA256SUMS.asc|grep "$filename" ||\
	{ echo "The sha256 hash does not match to the expected!  Cannot continue, aborting..."; return 4;}
	echo "Verified the hash of $filename successfully !"

	# Now let's install it!
	echo "Installing the dashcore package..."
	cd "$INSTALL_LOCATION" ||\
	{ echo "Install location $INSTALL_LOCATION is not accessible.  Aborting...";return 5;}
	base_dir=$(basename $(tar tf /tmp/"$filename" |head -1))
	sudo tar xf /tmp/"$filename" ||\
	{ echo "Failed to extract the archive, check that tar is working.  Aborting...";return 6;}
	sudo rm -f dash >/dev/null 2>&1
	sudo ln -s "$base_dir" dash
	[[ -f dash/bin/dashd ]] ||\
	{ echo "dashd is not accessible via the symlink.  Aborting...";return 7;}
	ldd dash/bin/dashd >/dev/null 2>&1 ||\
	{ echo "dashd is not executable on this machine, possible cause is the wrong architecture was downloaded for this system.  Aborting...";return 8;}
}

# Re-runnable, it will only make the change once.
configureManPages(){

	echo "Adding Dash man pages to the MANPATH..."
	sudo bash -c "grep -q \"^MANPATH_MAP.*/opt/dash/bin.*/opt/dash/share/man\" /etc/manpath.config||\
					echo -e \"MANPATH_MAP\t/opt/dash/bin\t\t/opt/dash/share/man\">>/etc/manpath.config"
}

# Re-runnable, it will only make the change once.
# This is specific to Debian based OSs only.
configurePATH(){

	echo "Adding Dash binaries to the PATH of the dash0$1 user..."
	osCheck >/dev/null 2>&1
	if (( $? <= 1 ));then
		sudo bash -c "grep -q '^PATH=\$PATH:/opt/dash/bin' /home/dash0$1/.profile||\
			echo 'PATH=\$PATH:/opt/dash/bin'>>/home/dash0$1/.profile"
	else
		echo "Your operating system is not supported, please edit your PATH manually."
	fi
}

createDashConf(){
	
	# Configure a bare bones dash.conf file.
	DASH_CONF="/home/dash0$1/.dashcore/dash.conf"
	echo "$DASH_CONF"
	
	if sudo test -f "$DASH_CONF";then
		echo "******************** $DASH_CONF ********************"
		sudo cat "$DASH_CONF"
		echo "******************** $DASH_CONF ********************"
		msg="A dash.conf file already exists at $DASH_CONF\\n"
		msg+="It is displayed on the screen above this text. Would you like to overwrite\\n"
		msg+="this file? Recommend to not overwrite, especially if your masternode is working.\\n"
		msg+="Overwrite dash.conf? [${bldcyn}y${txtrst} [${bldcyn}N${txtrst}]] "
		echo -en "$msg"
		read -r -n1 option
		echo -e "\\n$option">>"$LOGFILE"
		echo
		option=${option:-N}
		if [[ $option = [nN] ]]
		then
			return 1
		else
			dash0$1_conf_bak="$DASH_CONF-"$(date +"%Y%m%d%H%M")
			sudo -u dash0$1 bash -c "cp \"$DASH_CONF\" \"$dash0$1_conf_bak\""
			echo "A backup has been made of your existing dash0$1 conf at $dash0$1_conf_bak"
		fi
	fi

	# We will try and populate as much as is possible in the below template.
	echo "Initialising a default dash.conf file for you...."
	rpcuser=$(getRandomString 40)
	rpcpassword=$(getRandomString 40)
	msg="Next you need your bls private that you got from the 'bls generate' command\\n"
	msg+="in the core walletor from DMT.\\n"
	msg+="Note: This is NOT your collateral private key !\\n"
	msg+="Please enter your bls private (secret) key, if you don't have it ready,\\n"
	msg+="press ENTER for set some random bls key and edit masternodeblsprivkey in $DASH_CONF file later."
	echo -e "$msg"
	option='n'
	until [[ "$option" = 'Y' || "$option" = 'y' ]];do
		read -r -n64 -p "bls key " bls_key
		bls_key=${bls_key:-"set random"}
		echo -en "You entered a bls key of \"$bls_key\".\\nPress 'Y' to accept, 'N' to re-enter. "
		read -r -n1 option
		echo -e "\\n$option">>"$LOGFILE"
		echo
		option=${option:-N}
	done
	# Case insensitive match.  Set some random bls key because the masternode won't start without it.
	[[ ${bls_key,,} = "set random" ]]&& bls_key="000000c757797986f29fb529ad5352de587f7c9ecdfd1ff727e572fa193e0dec"
	echo "Creating dash.conf file..."
	sudo -u dash0$1 bash -c "mkdir -p $(dirname "$DASH_CONF")&&cat >\"$DASH_CONF\"<<\"EOF\"
#----

rpcuser=$rpcuser
rpcpassword=$rpcpassword
rpcallowip=127.0.0.1
rpcport=$(( 9999-$1 ))
#----
listen=1
server=1
daemon=1
# dbcache=4
# maxmempool=10
#----
masternodeblsprivkey=$bls_key
bind=$(hostname -I | awk '{ print $(echo '$1')}')
externalip=$(hostname -I | awk '{ print $(echo '$1')}')
#----
proxy=127.0.0.1:9050
torcontrol=127.0.0.1:9051
#----
EOF"
}

editDashConf(){
	
	# Configure a bare bones dash.conf file.
	DASH_CONF="/home/dash0$1/.dashcore/dash.conf"
	msg="Once you are done editing this file exit with [${bldcyn}CTRL + X${txtrst}] and answer [${bldcyn}Y${txtrst}] to save,\\n"
	msg+="if you're using vi, press ESC, then type in :wq to write and quit."
	echo -e "$msg"
	read -r -s -n1 -p "Press any key to continue. "
	echo
	if test -x $(which nano);then
		# Since nano wont work right without a stderr, I am re-establishing a stderr from
		# the copy I saved earlier and then after nano is done I tie stderr to stdout again
		# so that the tee can continue log everything.
		exec 2>&4
		sudo -i -u dash0$1 bash -c "nano $DASH_CONF"
		exec 2>&1
	elif test -x $(which vi);then
		exec 2>&4
		sudo -i -u dash0$1 bash -c "vi $DASH_CONF"
		exec 2>&1
	else
		echo "Could not find an editor on you machine, remember to edit the file /home/dash0$1/.dashcore yourself later."
	fi
}

# Next we wish to register the `dashd` deamon as a system process so that is starts
# automatically when the VPS boots and shutdown automatically when the VPS shutsdown,
# it will also restart the process if it should crash for some reason.

createDashdService(){

	[[ -f /etc/systemd/system/dashd0$1.service ]] &&\
	{ echo "Systemd dashd0$1 unit file already exists, skipping...";return 1;}
	# Gotta escape the " with \ in the here document.
	sudo mkdir -p /etc/systemd/system&&\
	sudo bash -c "cat >/etc/systemd/system/dashd0$1.service<<\"EOF\"
[Unit]
Description=Dash Core Daemon ($1)
Documentation=https://dash.org
After=syslog.target network.target

# Watch the daemon service actions in the syslog journal with:
# sudo journalctl -u dashd0$1.service -f

[Service]
Type=forking
User=dash0$1
Group=dash0$1

ExecStart=/opt/dash/bin/dashd
# Time that systemd gives a process to start before shooting it in the head
TimeoutStartSec=10m

# If ExecStop is not set, systemd sends a SIGTERM, which is \"okay\", just not ideal
ExecStop=/opt/dash/bin/dash-cli stop

# Time that systemd gives a process to stop before shooting it in the head
TimeoutStopSec=300

Restart=on-failure
RestartSec=120

# Allow for three failures in five minutes before trying to spawn another instance
StartLimitInterval=300
StartLimitBurst=3

# If the OOM kills this process, systemd should restart it.
OOMPolicy=continue

PrivateTmp=true

[Install]
WantedBy=multi-user.target

EOF"

	# Next we register with systemd which controls all the processes (daemons) running
	# on the VPS and ask it to enable `dashd` at boot and to launch it for the first time.

	sudo systemctl daemon-reload &&\
	sudo systemctl enable --now dashd0$1 &&\
	echo "Dash0$1 is now installed as a system service and initializing..." ||\
	echo "There was a problem registering and starting the dashd0$1 daemon via systemd."
	sudo systemctl stop dashd0$1 
}

createTopRC(){

	# We wont overwrite your .toprc if you already have one.
	[[ -f ~/.toprc ]] && return 1
	echo "Configuring ~/.toprc"
	echo "H4sICIxNGGMAAy50b3ByYwC11Elv00AUAOBz/Ct8ogmYYntsk0LcliYKdElZ2rKUxTj22JnW4zEz
duPyf6AVJ6QWRU0IFJH8L8ZVpHEPXFC4jN7TLO99erJTkiwwuUniAIVyG0VQrm6hOMvlhBIPMgaZ
3Edpjy+xT/qsJq379w4UuUN86LhRyjxqq7MUUZQnzNYUuQUj99hJEYY2WOTbzYzy+7YqtWBQCRCM
fOZl1P50enb+bfR9fDkZDC+mNxZqN28ptxfvqJpu1ZdXHqw12w8frW9sbnW2Hz95+mxnd+/5i5ev
9l+/efvOee92PR8GYQ8dHEY4JskHytLsqJ8ff5QqvFYQuSFvxQK6qSsyIzTl/ee2Vldk7Oapyw5Z
0XdI3aTneElWyjDEV5lPsm4EnSwpRB7BXRTD2VGpwjKMvYgWW5iFbBb2oOsXIVDkokQR6tIG6ZbN
ny8Gw+rZ+WQ0Xm2cTAXZnJd5CdQNo2RW/4Ws/p1sCbIlyHcF2ZI6EJfJw1Fj/OPn5a/O2vbvFjAG
fNTVa/ClGXpeZF2bs9kUZlOYDWE2pT1Gr4355PTLVz7qybR2BdV0YHDp/Ya9vLL6P8YM5kwGggwE
WRdkILVRDn2nj3zI0uKpHX7VwcxzI1h8Dbv8YCndh5Q4LEsSyn8rvJL0B+aNueJ7BAAA"|base64 -d|zcat >~/.toprc
	# Test top, because this toprc may not work with different versions of top
	top -v >/dev/null 2>&1|| rm -f ~/.toprc
}

patchSentinel(){

	echo "Installing sentinel, a backup has been made of any previous version..."

	# Create a patch file for sentinel to avoid the nag about RPC env vars.
	cat > /tmp/sentinel.patch <<"EOF"
--- sentinel-orig/lib/init.py	2022-08-19 11:27:40.593795243 +0000
+++ sentinel/lib/init.py	2022-08-19 11:28:15.321761009 +0000
@@ -104,9 +104,10 @@
         print("DashCore must be installed and configured, including JSONRPC access in dash.conf")
         sys.exit(1)
 
-    # deprecation warning
-    if not has_required_env_vars() and has_dash_conf():
-        print("deprecation warning: JSONRPC credentials should now be set using environment variables. Using dash.conf will be deprecated in the near future.")
+# Deprecate this deprecation warning.
+#    # deprecation warning
+#    if not has_required_env_vars() and has_dash_conf():
+#        print("deprecation warning: JSONRPC credentials should now be set using environment variables. Using dash.conf will be deprecated in the near future.")
 
 
 main()
EOF
	chmod 664 /tmp/sentinel.patch
}
	
installSentinel(){	

	# The below will install and configure sentinel.
	sudo -i -u dash0$1 bash <<EOF
	[[ -d sentinel ]] && { sentinel_old="sentinel-\$(date +"%Y%m%d%H%M")";echo "\$sentinel_old";mv sentinel "\$sentinel_old"; }
	git clone https://github.com/dashpay/sentinel &&\
	cd ~/sentinel &&\
	patch -Np1 -i /tmp/sentinel.patch;\
	virtualenv -p \$(which python3) venv &&\
	venv/bin/pip install -r requirements.txt &&\
	venv/bin/py.test test &&\
	venv/bin/python bin/sentinel.py && echo "Sentinel installed successfully!" ||\
	{ echo "Sentinel install failed, rolling back.";cd ; [[ -d "\$sentinel_old" ]] && rm -fr sentinel/ ;mv "\$sentinel_old" sentinel; }
EOF
}

installDashCrontab(){

	echo "Configuring sentinel in dash0$1's crontab..."

	dash_crontab=$(sudo crontab -u dash0$1 -l)
	grep -q "venv/bin/python bin/sentinel.py" <<< "$dash_crontab" ||\
	dash_crontab+=$(echo -e "\n*/10 * * * * { test -f ~/.dashcore/dashd.pid&&cd ~/sentinel && venv/bin/python bin/sentinel.py;} >> ~/sentinel/sentinel-cron.log 2>&1")
	sudo crontab -u dash0$1 - <<< "$dash_crontab"&&\
	echo "Successfully installed dash0$1 cron."||\
	echo "Failed to install dash0$1 cron."
}

installRootCrontab(){
	echo "Configuring root's crontab..."

	root_crontab=$(sudo crontab -u root -l)
	grep -q "weekly systemctl restart dashd" <<< "$root_crontab" ||\
	root_crontab+=$(echo -e "\n@weekly systemctl restart dashd")
	sudo crontab -u root - <<< "$root_crontab"&&\
	echo "Successfully installed root cron."||\
	echo "Failed to install root cron."
}

installMasternode(){

# set -x
dash_admin=$(whoami)	
	echo "Installing the DASH Masternode."
	# This section will run again after the first reboot, it should be fairly harmless and quick
	# but in the future I might jump over this block if the dash user already exists on the system.
	createDash_commonUser
for (( i=1; i <=$n_ip; i++ ));do
	createDashUser "$i"
	sudo -u dash0$i whoami >/dev/null 2>&1
	if (( $? != 0 ));then
		msg="Cannot run a command as the dash0$i user. Check that the dash0Si user exists\\n"
		msg+="and that this user $(whoami) has the correct permissions to sudo."
		echo -e "$msg"
		read -r -s -n1 -p "Press any key to exit. "
		echo
		return 2		
	fi
done
	preventRootSSHLogins
	YN_updateSystem
	disable_ipv6
	enableFireWall
	configureSwap
	configureTOR
	increaseNoFileParam
	addSysCtl && rebootSystem
	sleep 1
	for (( i=1; i <=$n_ip; i++ ));do
		sudo -u dash0$i whoami >/dev/null 2>&1
		if (( $? != 0 ));then
			msg="Cannot run a command as the dash user. Check that the dash user exists\\n"
			msg+="and that this user $(whoami) has the correct permissions to sudo."
			echo -e "$msg"
			read -r -s -n1 -p "Press any key to exit. "
			echo
			return 2
		fi
	done
	echo "... continue installing the DASH Masternode."
	downloadInstallDash || echo "Something went wrong with installing dashcore, you might want to look into this."
	configureManPages
	patchSentinel
	for (( i=1; i <=$n_ip; i++ ));do
		configureTORgroup "$i"
		configurePATH "$i"
		createDashConf "$i"
		createDashdService "$i" 	# The below also starts the dashd daemon.
		installDashCrontab "$i"
		installSentinel "$i"
	done
	createTopRC
	installRootCrontab
	sudo systemctl start dashd01 
	
	read -r -s -n1 -p "Installation has completed successfully, 
	Now running MN-1 (dashd01)
	wait for sync to complete (see Masternode sync : MASTERNODE_SYNC_FINISH )
	then go to Masternode Menu  and choose [6] - refactor Masterodes.
	... press any key to continue . "
	echo
# set +x
}

# Enter parameter 1 as the block time and out comes the time as a string.
convertBlocksToTime(){

	block_time="2.625"
	(( $# != 1 )) && return 1
	[[ "$1" =~ ^[0-9]+$ ]] || return 2
	mins=$(echo "scale=4;$block_time * $1"|bc -l)
	if (( $(echo "$mins>2880"|bc -l) ));then
		echo "$(echo "scale=2;$mins/60/24"|bc) days"
	elif (( $(echo "scale=2;$mins>300"|bc -l) ));then
		echo "$(echo "$mins/60"|bc) hours"
	else
		echo "$mins minutes"
	fi
}

showStatus(){

	printGraduatedProgressBar 50 0 "Working..."
	cpu=$(printf '%.2f%%' $(echo "scale=4;$(awk '{print $2}' /proc/loadavg)/$(grep -c ^processor /proc/cpuinfo)*100"|bc))
	printGraduatedProgressBar 50 5
	disk=$(df -h)
	printGraduatedProgressBar 50 10
	disk_size=$(awk '/\/$/ {print $2}'<<<"$disk")
	disk_used=$(awk '/\/$/ {print $3}'<<<"$disk")
	disk_free=$(awk '/\/$/ {print $4}'<<<"$disk")

	ram=$(free -h)
	printGraduatedProgressBar 50 15
	ram_size=$(awk '/^Mem/ {print $2}'<<<"$ram")
	ram_used=$(awk '/^Mem/ {print $3}'<<<"$ram")
	ram_free=$(awk '/^Mem/ {print $4}'<<<"$ram")

	swap_size=$(awk '/^Swap/ {print $2}'<<<"$ram")
	swap_used=$(awk '/^Swap/ {print $3}'<<<"$ram")
	swap_free=$(awk '/^Swap/ {print $4}'<<<"$ram")

# 	externalip=$(curl -s http://ipecho.net/plain)
	externalip=$(hostname -I | awk '{ print $(echo '$1')}')
# 	(( $? !=0 || ${#externalip} < 7 || ${#externalip} > 15 ))\
# 	&& externalip="Error"
# 	printGraduatedProgressBar 50 25


	nc -z -w 2 $externalip 9999 >/dev/null
	(( $? ==0 ))&&port_9999="OPEN" || port_9999="CLOSED" 
	printGraduatedProgressBar 50 25

# set -x
	if [[ "$externalip" != "Error" ]];then
		curl -s -d test --connect-timeout 2 ${externalip}:9999
		(( $? == 52 ))&&local_port_9999="OPEN"||local_port_9999="CLOSED"
	else
		local_port_9999="????"
	fi
# set +x
	dashd_version=$(sudo -i -u dash0$1 bash -c "dashd -version 2>/dev/null" 2>/dev/null)
	(( $? != 0 )) && dashd_version="Not found!"\
	||dashd_version=$(head -1 <<< "$dashd_version")
	printGraduatedProgressBar 50 50
# will only list the processes called dashd AND owned by dasho$1
# 	dash0N_procs=$(pgrep -u dash0$1 dashd)
	dashd_procs=$(pidof dashd)
	all_procs=$(ps aux)
	num_dashd_procs=$(awk '{print NF}'<<<"$dashd_procs")
	dashd_pid=()
	dashd_user=()
	((i=0))
 	if (( num_dashd_procs > 0 ));then
		for p in $dashd_procs;do
			dashd_pid[$i]=$p
			dashd_user[$i]=$(awk "/$p.*dashd/ {print \$1}"<<<"$all_procs")
			((i++))
		done
	fi	
	printGraduatedProgressBar 50 55

	if (( num_dashd_procs > 0 ));then
		block_height=$(sudo -i -u dash0$1 bash -c "dash-cli getblockcount 2>/dev/null" 2>/dev/null)
		# Test is for good return, must be a number between 1 and 8 digits long.
		(( $? != 0 )) || [[ ! "$block_height" =~ ^[0-9]+$ ]] ||  ((${#block_height} > 8 || ${#block_height} == 0 )) && block_height="Error"
	else
		block_height="dashd down"
	fi
	
	blockchair_height=$({ curl -s https://api.blockchair.com/dash/stats|jq -r '.data.best_block_height';} 2>/dev/null)
	(( $? != 0 )) || [[ ! "$blockchair_height" =~ ^[0-9]+$ ]] ||  ((${#blockchair_height} > 8 || ${#blockchair_height} == 0 )) && blockchair_height="Error"
	printGraduatedProgressBar 50 65


	cryptoid_height=$(curl -s https://chainz.cryptoid.info/dash/api.dws?q=getblockcount)
	(( $? != 0 )) || [[ ! "$cryptoid_height" =~ ^[0-9]+$ ]] ||  ((${#cryptoid_height} > 8 || ${#cryptoid_height} == 0 )) && cryptoid_height="Error" || ((cryptoid_height++))
	printGraduatedProgressBar 50 75

	if [[ "$blockchair_height" =~ ^[0-9]+$ ]] && (( blockchair_height == cryptoid_height ));then
		[[ "$block_height" != "$blockchair_height" ]] && block_height="!!! $block_height !!!"
	fi


	if (( num_dashd_procs > 0 ));then
		num_peers=$(sudo -i -u dash0$1 bash -c "dash-cli getpeerinfo 2>/dev/null|jq -r '.|length' 2>/dev/null" 2>/dev/null)
	else
		num_peers="dashd down"
	fi


	if (( num_dashd_procs > 0 ));then
		masternode_status=$(sudo -i -u dash0$1 bash -c "dash-cli masternode status 2>/dev/null|jq -r '.status' 2>/dev/null" 2>/dev/null)
		(( ${#masternode_status} == 0 )) && masternode_status=$(sudo -i -u dash bash -c "dash-cli masternode status 2>&1|tail -1" 2>/dev/null)
	else
		masternode_status="dashd down"
	fi
	printGraduatedProgressBar 50 80

	if (( num_dashd_procs > 0 ));then
		pose_score=$(sudo -i -u dash0$1 bash -c "dash-cli masternode status 2>/dev/null|jq -r '.dmnState.PoSePenalty' 2>/dev/null" 2>/dev/null)
		(( $? != 0 )) || [[ ! "$pose_score" =~ ^[0-9]+$ ]] ||  ((${#pose_score} > 8 || ${#pose_score} == 0 )) && pose_score="N/A"
	else
		pose_score="dashd down"
	fi
	printGraduatedProgressBar 50 85


	if (( num_dashd_procs > 0 ));then
		enabled_mns=$(sudo -i -u dash0$1 bash -c "dash-cli masternode count 2>/dev/null|jq -r '.enabled' 2>/dev/null" 2>/dev/null)
		(( $? != 0 )) || [[ ! "$enabled_mns" =~ ^[0-9]+$ ]] ||  ((${#enabled_mns} > 8 || ${#enabled_mns} == 0 )) && enabled_mns="Unknown"
	else
		enabled_mns="dashd down"
	fi


	if (( num_dashd_procs > 0 ));then
		mn_sync=$(sudo -i -u dash0$1 bash -c "dash-cli mnsync status 2>/dev/null|jq -r '.AssetName' 2>/dev/null" 2>/dev/null)
		(( ${#mn_sync} == 0 )) && mn_sync="Unknown"
	else
		mn_sync="dashd down"
	fi
	printGraduatedProgressBar 50 90

	if (( num_dashd_procs > 0 ));then
		last_paid_height=$(sudo -i -u dash0$1 bash -c "dash-cli masternode status 2>/dev/null|jq -r '.dmnState.lastPaidHeight' 2>/dev/null" 2>/dev/null)
		if (( $? != 0 )) || [[ ! "$last_paid_height" =~ ^[0-9]+$ ]] ||  ((${#last_paid_height} > 8 || ${#last_paid_height} == 0 ));then
			next_payment="Unknown"
		else
			if [[ "$enabled_mns" =~ ^[0-9]+$ &&  "$block_height" =~ ^[0-9]+$ ]];then
				next_payment=$((last_paid_height + enabled_mns - block_height))
				next_payment=$(convertBlocksToTime $next_payment)
			else
				next_payment="Unknown"
			fi
		fi
	else
		next_payment="dashd down"
	fi

	sentinel=$(sudo -i -u dash0$1 bash -c "cd ~/sentinel 2>/dev/null&& venv/bin/python bin/sentinel.py" 2>/dev/null)
	(( $? == 0 && ${#sentinel} == 0 ))\
	&& sentinel="OK"\
	|| sentinel="Failed"
	sentinel_version=$(sudo -i -u dash0$1 bash -c "cd ~/sentinel/ 2>/dev/null&&venv/bin/python bin/sentinel.py --version" 2>/dev/null)
	printGraduatedProgressBar 50 100

	# Now print it all out nicely formatted on screen.
	msg="${bldcyn}$(date)\\n"
	msg+="=====================================================\\n"
	msg+="================== System info ======================\\n"
	msg+="=====================================================\\n"
	echo -e "$msg"

	printf "$bldblu%17s : $txtgrn%s\n" "CPU Load" "$cpu"
	printf "$bldblu%17s : $txtgrn%s\n" "Disk used / size" "$disk_used / $disk_size"
	printf "$bldblu%17s : $txtgrn%s\n" "Disk free" "$disk_free"
	printf "$bldblu%17s : $txtgrn%s\n" "RAM used / size" "$ram_used / $ram_size"
	printf "$bldblu%17s : $txtgrn%s\n" "RAM free" "$ram_free"
	printf "$bldblu%17s : $txtgrn%s\n" "Swap used / size" "$swap_used / $swap_size"
	printf "$bldblu%17s : $txtgrn%s\n" "Swap free" "$swap_free"

	msg="\\n"
	msg+="$bldcyn=====================================================\\n"
	msg+="=================== dashd0$1 info ======================\n"
	msg+="=====================================================\\n"
	echo -e "$msg"

	printf "$bldblu%17s : $txtgrn%s\n" "dashd version" "$dashd_version"
	printf "$bldblu%17s : $txtgrn%s\n" "IP address" "$externalip"
	printf "$bldblu%17s : $txtgrn%s\n" "Port (9999)" "$port_9999"
	printf "$bldblu%17s : $txtgrn%s\n" "Local Port (9999)" "$local_port_9999"

	if (( num_dashd_procs == 0 ));then
		printf "$bldblu%17s : $txtgrn%s\n" "dashd running?" "No!"
	else
		for ((i=0; i<${#dashd_pid[@]}; i++));do
			printf "$bldblu%17s : $txtgrn%s\n" "dashd pid / user" "${dashd_pid[$i]} / ${dashd_user[$i]}"
		done
	fi

	printf "$bldblu%17s : $txtgrn%s\n" "Block height" "$block_height"
	printf "$bldblu%17s : $txtgrn%s\n" "Blockchair height" "$blockchair_height"
	printf "$bldblu%17s : $txtgrn%s\n" "CryptoId height" "$cryptoid_height"
	printf "$bldblu%17s : $txtgrn%s\n" "Connected peers" "$num_peers"
	printf "$bldblu%17s : $txtgrn%s\n" "Masternode status" "$masternode_status"
	printf "$bldblu%17s : $txtgrn%s\n" "PoSe score" "$pose_score"
	printf "$bldblu%17s : $txtgrn%s\n" "Masternode sync" "$mn_sync"
	printf "$bldblu%17s : $txtgrn%s\n" "Sentinel" "$sentinel"
	printf "$bldblu%17s : $txtgrn%s\n" "Sentinel version" "$sentinel_version"
	printf "$bldblu%17s : $txtgrn%s\n" "Next payment" "$next_payment"
	echo -e "$txtrst"
	linesOfStatsPrinted=34
	if (( num_dashd_procs > 1));then
		((linesOfStatsPrinted=linesOfStatsPrinted + num_dashd_procs -1))
	fi
}

# Intelligently display the logfile from the most recent startup.
displayDebugLog(){
	# In order for less to work, we have to restore the file descriptors for stdin and stdout.
	exec 1>&3
	exec 2>&4

	# Sending commands as a here-doc where only the $ needs to be escaped.
	# awk was behaving badly using the -c option on ubuntu, not raspbian.
	sudo -i -u dash0$option bash<<EOF
		[[ -f ~/.dashcore/debug.log ]] || { echo "Could not open debug.log!";exit 1;}
		lineno=\$(grep -n -i Dash\ Core\ version ~/.dashcore/debug.log |tail -1|awk -F ':' '{print \$1}')
		linecount=\$(wc -l ~/.dashcore/debug.log|awk '{print \$1}')
		lines=\$((linecount - lineno +5))
		tail -\${lines} ~/.dashcore/debug.log|less
EOF
	exec 2>&1
}

reclaimFreeDiskSpace(){
	uninstallJunkPackages
	# Shrink logs.
	sudo journalctl --disk-usage
	sudo journalctl --vacuum-time=2d
	sudo truncate -s0 /var/log/btmp

	msg="\\nThe app cache and the journal logs have been cleaned.\\n"
	msg+="To recover more space, you should reboot your VPS now.\\n"
	msg+="Press r to reboot now, any other key to return to the menu."
	echo -en "$msg"
	read -r -n1 option
	echo -e "\\n$option">>"$LOGFILE"
	echo
	option=${option:-N}
	[[ $option = [rR] ]] && sudo reboot
}

refactorNodes(){

	# Shutdown all the nodes!  This is important otherwise the data will not be consistent!
	msg="Shutting down all the nodes..."
	echo -e "$msg"
	for (( i=1; i <= $n_ip; i++ ));do
		sudo systemctl stop dashd0$i
		while pidof dashd0$i;do sleep 1;done
		echo "dashd0$i stoped successful."
		sleep 2
	done
	
	
	files=$(sudo find /home/dash01/.dashcore/blocks -type f -name "blk*"|sort|head -$(($(sudo find /home/dash01/.dashcore/blocks -type f -name "blk*"|wc -l)-1)))
	files+=$(echo;sudo find /home/dash01/.dashcore/blocks -type f -name "rev*"|sort|head -$(($(sudo find /home/dash01/.dashcore/blocks -type f -name "rev*"|wc -l)-1)))

	# Only do the below if the $files variable contains elements.
	((${#files}==0))&&exit 1

	for f in $files;do sudo mv -v $f /home/dash-common/.dashcore/blocks/;done
	sudo chmod -v -R g+wrx /home/dash-common/.dashcore/blocks/
	sudo chown -vR dash-common:dash-common /home/dash-common/.dashcore/blocks/

	for f in $files;do sudo ln -vs "../../../dash-common/.dashcore/blocks/$(basename $f)" "/home/dash01/.dashcore/blocks/$(basename $f)";done
	sudo chown -Rv dash01:dash01 /home/dash01/.dashcore/blocks/

	for (( i=2; i <= $n_ip; i++ ));do
		sudo rm /tmp/[do][an][si][ho]*[ok][ne][fy]
		sudo bash -c "cp -v /home/dash0$i/.dashcore/[do][an][si][ho]*[ok][ne][fy] /tmp/" &&\
		{ sudo rm -fr /home/dash0$i/.dashcore/
		sudo cp -va /home/dash01/.dashcore /home/dash0$i
		sudo bash -c "rm -fr /home/dash0$i/.dashcore/{.lock,.walletlock,d*.log,*.dat,onion*key} /home/dash0$i/.dashcore/backups/"
		sudo cp -v /tmp/[do][an][si][ho]*[ok][ne][fy] /home/dash0$i/.dashcore/
		sudo chown -v -R dash0$i:dash0$i /home/dash0$i/;}
	done

	# Just reboot and all the nodes will come back on-line themselves.
	read -r -s -n1 -p "Press any key to reboot... "
	sudo reboot

}

getLogo(){
	catimg -h >/dev/null 2>&1 || return 1
	if [[ ! -f /tmp/dash_logo_2018_rgb_for_screens.png ]];then
		wget -q -O /tmp/dash_logo_2018_rgb_for_screens.png https://media.dash.org/wp-content/uploads/dash_logo_2018_rgb_for_screens.png || return 2
	fi
	file /tmp/dash_logo_2018_rgb_for_screens.png 2>/dev/null|grep -q "PNG image data" || return 3
	# By now, we have downloaded and verified a PNG image from the dash.org website and can attempt to render it.
	COLOUR_LOGO=1
}

function printRootMenu(){

	msg+="You are running as the 'root' user, the only tasks that are necessary to be done\n"
	msg+="as root is to create the user for the administration of the Dash masternode (Dash Admin).\n"
	msg+="This script will create the 'Dash Admin' user \n"
	msg+="this user is a privileged user that can also run commands as root and hence change the system.\n"
	msg+="Later when you log back in as the Dash Admin user, the dash user(s) will be created which is whatthe masternode will run as.\n"
	msg+="The dash user is a unprivileged user and thus cannot make changes to the system.\n"
	msg+="It is important to have these two users separate to improve the security of your masternode, \n"
	msg+="after all you don't want your masternode to get hacked and end up mining Monero and becoming unstable!\n\n"
	msg+="The first option will check to see if the Dash Admin user already exists on your system before making changes\n\n"
	echo -e "$msg"
	figlet '      Root Menu :'
	msg="\n\nMake a selection from the below options.\n"
	msg+="1. Create Dash Admin user for a new masternode(s) server.\n"
	msg+="9. Quit.\n"
	echo -e "$msg"
}

function rootMenu(){
	while :
	do
		echo -en "Choose option [1 [9]]: "
		read -r -n1 option
		echo -e "\n$option">>"$LOGFILE"
		echo
		option=${option:-9}
		case $option in
			1)
				createMnoUser
				return 0
				;;
			9)
				echo "Exiting..."
				return 9
				;;
			*)
				echo "Invalid selection, please enter again."
				return 0
				;;
		esac
	done

}

manageMasternodeMenu(){
	figlet ' '
	figlet ' '
	figlet '  Masternode'
	figlet '           Menu :'
	figlet ' '
	msg="\n\nMake a selection from the below options.\n"
	msg+="1. (Re)install dash binaries, use this for updates.\n"
	msg+="2. (Re)install sentinel and update it.\n"
	msg+="3. Review and edit your dash.conf file.\n"
	msg+="4. Reindex dashd.\n"
	msg+="5. View debug.log.\n"
	msg+="6. refactor Masterodes\n"
	msg+="9. Return to Main Menu.\n"
	echo -e "$msg"
	echo -en "Choose option [1 2 3 4 5 6 [9$txtrst]]: "
	read -r -n1 option
	echo -e "\n$option">>"$LOGFILE"
	echo
	option=${option:-9}
	case $option in
		1)
			msg="This will re-install your dash binaries.  Use this option if you wish to\n"
			msg+="update the dash daemon, the dashd service will be automatically restarted\n"
			msg+="after the update.\n\n"
			msg+="Press [${bldcyn}Y${txtrst}] to continue or another other key to return to the main menu [y [N]] "
			echo -en "$msg"
			read -r -n1 option
			echo -e "\n$option">>"$LOGFILE"
			option=${option:-N}
			[[ $option = [yY] ]] || return 0
			echo
			downloadInstallDash
			if (( $? == 0 ));then
				echo "Installation has been successful, restarting the dashd01 daemon..."
				for (( i=1; i <= $n_ip; i++ ));do
				sudo systemctl stop dashd0$i
				sudo systemctl start dashd0$i
				if (( $? == 0 ));then
						echo "Restart dashd0$i has been successful."
					else
						echo "Restart dashd0$i ohas been unsuccessful, please investigate or seek support!"
				fi
				done
			else
				echo "Installation  has been unsuccessful, please investigate or seek support!"
			fi
			read -r -s -n1 -p "Press any key to continue. "
			echo
			return 0
			;;
		2)
			msg="This will update and replace your sentinel with a new one from Github.\n"
			msg+="Use this option if your sentinel is not working right, or if you need to\n"
			msg+="upgrade it.\n\n"
			msg+="Press [${bldcyn}Y${txtrst}] to continue or another other key to return to the main menu [y [N]] "
			echo -en "$msg"
			read -r -n1 option
			echo -e "\n$option">>"$LOGFILE"
			option=${option:-N}
			[[ $option = [yY] ]] || return 0
			echo
			patchSentinel
			for (( i=1; i <= $n_ip; i++ ));do
				installSentinel $i
					if (( $? == 0 ));then
						echo "Installation has been successful."
					else
						echo "Installation of sentinel has been unsuccessful, please investigate or seek support!"
					fi
			done
			read -r -s -n1 -p "Press any key to continue. "
			echo
			return 0
			;;
		3)	
			msg="This option will open the dash.conf \n"
			msg+="Press "
			if	(( $n_ip>1 ));then 
				for (( i=1; i <= $n_ip; i++ ));do
					if (( $i<$n_ip ));then
					msg+="[${bldcyn}$i${txtrst}] "
					else
					msg+="or [${bldcyn}$i${txtrst}] "
					fi
				done
					msg+="to proceed and view dash.conf "
				for (( i=1; i <= $n_ip; i++ ));do
					if (( $i<$n_ip ));then
					msg+=${bldcyn}"MN-$i  "${txtrst}
					else
					msg+="or"${bldcyn}" MN-$i  "${txtrst}
					fi
				done
			else
				msg+="[${bldcyn}$n_ip${txtrst}] to proceed and view dash.conf [${bldcyn}MN-$n_ip${txtrst}] "
			fi
			msg+=", or any other key to return to the main menu "
			echo -en "$msg"
			read -r -n1 option
			echo -e "\n$option">>"$LOGFILE"
			if [[  "${N_IP[@]}"  =~  "${option}"  ]]; then
						
			DASH_CONF="/home/dash0$option/.dashcore/dash.conf"
			echo "$DASH_CONF"
			echo "******************** $DASH_CONF ********************"
			sudo cat "$DASH_CONF"
			echo "******************** $DASH_CONF ********************"
			msg="\nAbove is your existing dash0$option.conf (MN-$option), if you wish to edit it press [${bldcyn}Y${txtrst}] any other key will\n"
			msg+="return to the main menu. [y [N]] "
			echo -en "$msg"
			read -r -n1 option_yn
			echo -e "\n$option_yn">>"$LOGFILE"
			option_yn=${option_yn:-N}
			[[ $option_yn = [yY] ]] || return 0
			echo	
			editDashConf $option
# 			sudo systemctl stop dashd0$option
# 			sudo systemctl start dashd0$option
			else
			return 0
			echo
			fi
			read -r -s -n1 -p "Done!  Press any key to continue. "
			echo
			return 0
			;;
		4)
			msg="As a last resort if your node is stuck, you can choose to reindex it.\n"
			msg+="This process will take about 3 hours depending on your hardware.\n"
			msg+="You can monitor the progress from the status page...\n"
			msg+="Press [${bldcyn}Y${txtrst}] to proceed, or any other key to return to the main menu [y [N]] "
			echo -en "$msg"
			read -r -n1 option
			echo -e "\n$option">>"$LOGFILE"
			option=${option:-N}
			[[ $option = [yY] ]] || return 0
			echo
			for (( i=1; i <= $n_ip; i++ ));do
				sudo systemctl stop dashd0$i 
			done
			sudo -i -u dash01 bash -c "dashd -reindex"
			read -r -s -n1 -p "Reindex has started!  Press any key to continue. "
			echo
			return 0
			;;
		5)
			msg="This option will open the debug.log file in less from when the node\n"
			msg+="was last started. To navigate the log file use the below hints.\n"
			msg+="G - Pressing uppercase G will take you to the end of the log file to see the most recent entries.\n"
			msg+="g - Pressing lowercase g takes you to the start (oldest entries).\n"
			msg+="q - To quit.\n"
			msg+="/ - Typing / and search term will search the file for that term.\n"
			msg+="n - When in search mode n will skip to the next occurance of the term.\n"
			msg+="b - When in search mode b will go back to the previous occurance of the term.\n\n\n"
			msg+="Press "
			if	(( $n_ip>1 ));then 
				for (( i=1; i <= $n_ip; i++ ));do
					if (( $i<$n_ip ));then
					msg+="[${bldcyn}$i${txtrst}] "
					else
					msg+="or [${bldcyn}$i${txtrst}] "
					fi
				done
					msg+="to proceed and view "
				for (( i=1; i <= $n_ip; i++ ));do
					if (( $i<$n_ip ));then
					msg+=${bldcyn}"MN-$i  "${txtrst}
					else
					msg+="or"${bldcyn}" MN-$i  "${txtrst}
					fi
				done
			else
				msg+="[${bldcyn}$n_ip${txtrst}] to proceed and view debug.log [${bldcyn}MN-$n_ip${txtrst}] "

			fi
			msg+=", or any other key to return to the main menu "
			echo -en "$msg"
			read -r -n1 option
			echo -e "\n$option">>"$LOGFILE"
			if [[ "${N_IP[@]}"  =~ "${option}" ]]; then	
			displayDebugLog $option
			else
			return 0
			echo
			fi
			;;
		6)	
			msg="As a last resort if your node is stuck, you can choose to reindex it.\n"
			msg+="Press [${bldcyn}Y${txtrst}] to continue or another other key to return to the main menu [y [N]] "
			echo -en "$msg"
			read -r -n1 option
			echo -e "\n$option">>"$LOGFILE"
			option=${option:-N}
			[[ $option = [yY] ]] || return 0
			echo
			files=$(sudo find /home/dash01/.dashcore/blocks -type f -name "blk*"|sort|head -$(($(sudo find /home/dash01/.dashcore/blocks -type f -name "blk*"|wc -l)-1)))
			# Only do the below if the $files variable contains elements.
			if [ ${#files} -eq 0 ];then
			echo "You have nothing to optimize !" ;\
			echo "Back to Main Menu..."
			return 9
			else
			refactorNodes
			fi
			return 0
			echo
			read -r -s -n1 -p "Press any key to continue. "
			echo
			return 0
			;;
		
		9)
			echo "Back to Main Menu..."
			return 9
			;;
		*)
			echo "Invalid selection, please enter again."
			busyLoop24bit 5000 300 800
			return 0
			;;
	esac
}

function printMainMenu (){
		msg="\n\n"
		figlet "       Main Menu :"	
		msg+="\n\nMake a selection from the below options.\n"
		msg+="1. Install and configure a new DASH Masternode(s) ("
		for (( i=1; i<=$n_ip; i++ ));do
			msg+=" MN-$i "
		done
		msg+=").\n"
		msg+="2. Check system status.\n"
		msg+="3. Manage your masternode(s).\n"
		msg+="4. Reclaim free disk space.\n" 
		msg+="9. Quit.\n"
		echo -e "$msg"
}

function mainMenu (){
	while :
	do
		echo -en "Choose option [1 2 3 4 [9$txtrst]]: "
		read -r -n1 option
		echo -e "\n$option">>"$LOGFILE"
		echo
		option=${option:-9}
		case $option in
			1)
				installMasternode
				return 0
				;;
			
			2)
				msg="Press "
				if	(( $n_ip>1 ));then 
					for (( i=1; i <= $n_ip; i++ ));do
						if (( $i<$n_ip ));then
						msg+="[${bldcyn}$i${txtrst}] "
						else
						msg+="or [${bldcyn}$i${txtrst}] "
						fi
					done
						msg+=" to proceed and view "
					for (( i=1; i <= $n_ip; i++ ));do
						if (( $i<$n_ip ));then
						msg+=${bldcyn}"MN-$i  "${txtrst}
						else
						msg+="or"${bldcyn}" MN-$i  "${txtrst}
						fi
					done
				else
				msg+="[${bldcyn}$n_ip${txtrst}] to proceed and view  [${bldcyn}dash0$n_ip${txtrst}] "
				fi
				msg+="status or any other key to return to the main menu "
				echo -en "$msg"
				read -r -n1 option
				echo -e "\n$option">>"$LOGFILE"
				if [[  "${N_IP[@]}"  =~  "${option}"  ]]; then	
					option_r='r'
					while [[ "$option_r" = 'R' || "$option_r" = 'r' ]];do
						showStatus $option
						echo -en "Press $bldcyn""R""$txtrst to check status again or any other key to return to main menu. "
						read -r -n1 option_r
						option_r=${option_r:-N}
						[[ $option_r = [rR] ]] && echo -e "\e[$((linesOfStatsPrinted +1))A\e[73D"
					done
				fi
				echo
				return 0
				;;	
				
			3)
				while manageMasternodeMenu;do : ;done
				return 0
				;;
			
			4)
				reclaimFreeDiskSpace
				return 0
				;;
						
			9)
				echo "Exiting..."
				return 9
				;;
			*)
				echo "Invalid selection, please enter again."
				busyLoop24bit 5000 300 800
				return 0
				;;
		esac
	done
}

##############################################################
#
#	Main
#
##############################################################

LOGFILE="$(pwd)/$(basename "$0").log"
ZEUS="$0"
# dashd install location.
INSTALL_LOCATION="/opt"
# DASH_CONF="/home/dash/.dashcore/dash.conf"
nowEpoch=`date +%s`
n_ip=$(hostname -I | wc -w)
N_IP=($(seq 1 $n_ip))
ip=$(hostname -I | awk '{ print $1 }')
# I need to save the file descriptor for stderr since without a
# working stderr nano doesn't work correctly.
exec 3>&1
exec 4>&2
{
	echo -e "$ZEUS\t$VERSION"
	getLogo
	osCheck
	OS=$?;export OS
	(( OS <= 1 ))|| exit $OS
	idCheck
	idcheckretval=$?
	retval=0
	while (( retval != 9 ))
	do
		figlet '    '
		figlet 'Dash Masternode'
		figlet '                 ZEUS'
		if (( idcheckretval == 0 ))
		then
			printMainMenu
			mainMenu
		elif (( idcheckretval == 1 ))
		then
			printRootMenu
			rootMenu
		else
			msg="Your sudo does not seem to be working, either you entered the wrong password\n"
			msg+="or this user lacks sudo privileges.  You can try again, or try running this\n"
			msg+="program under another account, for example root."
			echo -e "$msg"
			break
		fi
		retval=$?
	done
} 2>&1 |tee -a "$LOGFILE"
