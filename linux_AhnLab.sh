#!/bin/sh

echo off

LANG=C
export LANG

HOSTNAME=`hostname`
DATE=`date +%Y-%m-%d`
FILENAME=Linux_${HOSTNAME}

PASSWD="/etc/passwd"
SHADOW="/etc/shadow"
GROUP="/etc/group"
PROFILE="/etc/profile"
PASSWD_CONF="/etc/login.defs"
LOGIN_CONF="/etc/pam.d/login"
INETD_CONF="/etc/inetd.conf"
XINETD_CONF="/etc/xinetd.conf"
HOSTS_EQUIV="/etc/hosts.equiv"
HOSTS="/etc/hosts"
ISSUE="/etc/issue"
CRON_ALLOW="/etc/cron.allow"
CRON_DENY="/etc/cron.deny"
AT_ALLOW="/etc/at.allow"
AT_DENY="/etc/at.deny"
GROUP="/etc/group"
SERVICES="/etc/services"
TELNET_BANNER="/etc/issue.net"
FTP_BANNER="/etc/welcome.msg"
SMTP_CONF="/etc/mail/sfinishmail.cf"
SNMP_CONF="/etc/snmp/snmpd.conf"
SYSLOG_CONF="/etc/syslog.conf"
NFS_CONF="/etc/exports"
CRONTABS="/etc/crontab"
ATJOBS="/var/spool/cron/atjobs"
SSH_CONF="/etc/ssh/sshd_config"
SECURETTY="/etc/securetty"
#HTTPD_CONF="/etc/httpd/conf/httpd.conf"
#HTTPD_ROOT=""
#SERVER_CONFIG_DIR=""


echo "*************************************************************"
echo "******  AhnLab System Checklist for Linux ver 15.6.2 ********"
echo "******   Copyright 2015 Ahnlab. All right Reserved   ********"
echo "*************************************************************"

echo "*************************************************************"						>> ./$FILENAME.log 2>&1
echo "******   AhnLab System Checklist for Linix ver 15.6.2 *******"						>> ./$FILENAME.log 2>&1
echo "******    Copyright 2015 Ahnlab. All right Reserved   *******"						>> ./$FILENAME.log 2>&1
echo "*************************************************************"						>> ./$FILENAME.log 2>&1

echo " "
echo "System check start. Please wait..."
	date
echo " "

echo "### Start Time ###" 											>> ./$FILENAME.log 2>&1
	date 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### OS Info. ###"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	uname -a												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	cat /proc/version											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### network ###"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	ifconfig -a												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

############################################
### Apache Variables
############################################

echo "### Apache Conf ###"											>> ./$FILENAME.log 2>&1
if [ `ps -ef | grep httpd | grep -v grep | wc -l` -ge 1 ]; then
	APACHE_CHECK=ON
	HTTPD_ROOT=`httpd -V | grep "HTTPD_ROOT" | sed 's/^.*=\(\)/\1/' | tr -d [\"][\]`
	SERVER_CONFIG_DIR=`httpd -V | grep "SERVER_CONFIG_FILE" | sed 's/^.*=\(\)/\1/' | tr -d [\"][\]`
		
	for dir in $HTTPD_ROOT
	do
	  for file in $SERVER_CONFIG_DIR
	  do
	    HTTPD_CONF=$dir/$file
	 if [ -f $HTTPD_CONF ]
	      then
			ls -alL $HTTPD_CONF									>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
else
	APACHE_CHECK=OFF
fi
echo $APACHE_CHECK												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1




echo "----------------------- 1. Accounts and passwords -----------------------"				>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-1 start"												>> ./$FILENAME.log 2>&1
echo "[ SSH service ]"												>> ./$FILENAME.log 2>&1
	(ps -ef | grep ssh	| grep -v grep)									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SSH port ]"				 								>> ./$FILENAME.log 2>&1
	(netstat -an | grep :22 | grep LISTEN) 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ TELNET service ]"											>> ./$FILENAME.log 2>&1
	(ps -ef | grep telnet	| grep -v grep)									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ TELNET service(/etc/xinetd.d/telnet) ]"									>> ./$FILENAME.log 2>&1
	(cat /etc/xinetd.d/telnet)										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ TELNET port ]"				 								>> ./$FILENAME.log 2>&1
	(netstat -an | grep :23 | grep LISTEN) 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SSH ]"													>> ./$FILENAME.log 2>&1
	(cat $SSH_CONF | grep -i PermitRootLogin || echo "[no config]")						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ Telnet ]" 												>> ./$FILENAME.log 2>&1
	(cat $LOGIN_CONF | grep -i pam_securetty.so || echo "[no config]")					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ securetty ]" 												>> ./$FILENAME.log 2>&1
	(ls -al $SECURETTY)											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	(cat $SECURETTY)											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-1 finish"												>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### U-2 start"												>> ./$FILENAME.log 2>&1
echo " [Fedora & Gentoo & Red Hat ] " 										>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/system-auth | egrep -i 'pam_cracklib.so' || echo pam_cracklib.so no setting) 		>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " [Ubuntu & Suse & Debian ] " 										>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/common-password | egrep -i 'pam_cracklib.so' || echo pam_cracklib.so no setting) 	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-2 finish"												>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### U-3 start"												>> ./$FILENAME.log 2>&1
echo " [Fedora & Gentoo & Red Hat ] " 										>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/system-auth | egrep -i 'no_magic_root' || echo "no_magic_root no setting")		>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/system-auth | egrep -i 'pam_tally.so' || echo "pam_tally.so no setting")		>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/system-auth | grep -i 'pam_tally2.so' || echo "no setting pam_tally2.so") 		>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " [Ubuntu & Suse & Debian] " 										>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/common-auth | egrep -i 'no_magic_root' || echo "no_magic_root no setting")		>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/common-auth | egrep -i 'pam_tally.so' || echo "pam_tally.so no setting")		>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/common-auth | grep -i 'pam_tally2.so' || echo "no setting pam_tally2.so")		>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-3 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-4 start"												>> ./$FILENAME.log 2>&1
echo "[ $PASSWD ]"												>> ./$FILENAME.log 2>&1
	cat $PASSWD						 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ $SHADOW ]"												>> ./$FILENAME.log 2>&1
	cat $SHADOW						 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-4 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-5 start"												>> ./$FILENAME.log 2>&1
echo "[ root UID '0' ]"												>> ./$FILENAME.log 2>&1
	(awk -F: '$3==0 { print $1 " -> UID=" $3 }' $PASSWD | grep -v root)					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ $PASSWD ]"												>> ./$FILENAME.log 2>&1
	awk -F: '{print $1, $3}' $PASSWD 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-5 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-6 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/pam.d/su  ]"											>> ./$FILENAME.log 2>&1
	(ls -al /etc/pam.d/su)											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /bin/su  ]"												>> ./$FILENAME.log 2>&1
	(ls -al /bin/su)											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ group ]"				 								>> ./$FILENAME.log 2>&1
	DIRS=`ls -al /etc/pam.d/su| awk '{print $4}'`
         for dir in $DIRS
          do
	    cat /etc/group | grep $dir:										>> ./$FILENAME.log 2>&1
	    echo "+++++" 											>> ./$FILENAME.log 2>&1
         done
echo " " 													>> ./$FILENAME.log 2>&1
	(cat /etc/group | grep wheel)										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/pam.d/su ]"											>> ./$FILENAME.log 2>&1
	(cat /etc/pam.d/su | grep auth)										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-6 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-7 start"												>> ./$FILENAME.log 2>&1
	cat $PASSWD_CONF | grep -i PASSLENGTH									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	cat $PASSWD_CONF | grep -i PASS_MIN_LEN									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-7 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-8 start"												>> ./$FILENAME.log 2>&1
	cat $PASSWD_CONF | grep -i MAXWEEKS 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	cat $PASSWD_CONF | grep -i PASS_MAX_DAYS  								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-8 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-9 start"												>> ./$FILENAME.log 2>&1
	cat $PASSWD_CONF | grep -i PASS_MIN_DAYS								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-9 finish"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-10 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/passwd ]"												>> ./$FILENAME.log 2>&1
	cat $PASSWD | grep -v 'nologin' | grep -v 'false' 				 			>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/shadow ]"												>> ./$FILENAME.log 2>&1
	cat $SHADOW						 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-10 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-11 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/group ]"												>> ./$FILENAME.log 2>&1
	cat /etc/group | grep root										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-11 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-12 start"												>> ./$FILENAME.log 2>&1
echo "[no member] " 												>> ./$FILENAME.log 2>&1
	awk -F: '$4==null' /etc/group										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-12 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-13 start"												>> ./$FILENAME.log 2>&1
	ret=`awk -F: '{ print $3}' $PASSWD | sort | uniq -d | wc -l`
	if [ $ret -eq 0 ]; then
		echo "Restrict overlapping UID"									>> ./$FILENAME.log 2>&1
		echo " " 											>> ./$FILENAME.log 2>&1
		echo "UID : USERNAME"										>> ./$FILENAME.log 2>&1
		awk -F: '{ print $3 ":" $1 }' $PASSWD | sort							>> ./$FILENAME.log 2>&1
	else
		echo "Exists overlapping UID"									>> ./$FILENAME.log 2>&1
		ret2=`awk -F: '{ print $3 }' $PASSWD | sort | uniq -d`
		
		for RPM in $ret2; do
			awk -F: '$3=='$RPM' { print $0 }' $PASSWD						>> ./$FILENAME.log 2>&1
		done
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-13 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-14 start"												>> ./$FILENAME.log 2>&1
echo "[Check shell] " 												>> ./$FILENAME.log 2>&1
	cat $PASSWD | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin"	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-14 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-15 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/profile ]"												>> ./$FILENAME.log 2>&1
	ls -al $PROFILE 									 		>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/profile ]"										>> ./$FILENAME.log 2>&1
	cat $PROFILE | grep -i TMOUT || echo TMOUT no setting	 						>> ./$FILENAME.log 2>&1
	echo "+++++" 												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-15 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "----------------------- 2. file and directory management -----------------------"				>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-16 start"												>> ./$FILENAME.log 2>&1
	if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]; then
		echo "@ OK"											>> ./$FILENAME.log 2>&1
	else
		echo "'.' Exist"										>> ./$FILENAME.log 2>&1
	fi
	echo $PATH												>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-16 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-17 start"												>> ./$FILENAME.log 2>&1
	find / -xdev \( -nouser -o -nogroup \) -exec ls -al {} \; 2>/dev/null					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-17 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-18 start"												>> ./$FILENAME.log 2>&1
	ls -al $PASSWD						 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-18 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-19 start"												>> ./$FILENAME.log 2>&1
	ls -al $SHADOW						 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-19 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-20 start"												>> ./$FILENAME.log 2>&1
	ls -al $HOSTS $HOSTS_EQUIV 						 				>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-20 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-21 start"												>> ./$FILENAME.log 2>&1
	ls -al $INETD_CONF 							 				>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	ls -al $XINETD_CONF 							 				>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-21 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-22 start"												>> ./$FILENAME.log 2>&1
	ls -al $SYSLOG_CONF 		 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	ls -al /etc/rsyslog.conf										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-22 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-23 start"												>> ./$FILENAME.log 2>&1
	ls -al $SERVICES 											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-23 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-24 start"												>> ./$FILENAME.log 2>&1
echo "[CHECK SUID & SGID]"											>> ./$FILENAME.log 2>&1
	FILES="/sbin/dump /sbin/restore /sbin/unix_chkpwd /usr/bin/at /usr/bin/lpq
           /usr/bin/lpq-lpd /usr/bin/lpr /usr/bin/lpr-lpd /usr/bin/lprm /usr/bin/lprm-lpd
		/usr/bin/newgrp /usr/sbin/lpc /usr/sbin/lpc-lpd /usr/sbin/traceroute"
	for check_file in $FILES
	  do
	    if [ -f $check_file ];
	      then
		echo `ls -alL $check_file`									>> ./$FILENAME.log 2>&1
	       else
		echo $check_file "There is no files "								>> ./$FILENAME.log 2>&1
	    fi
	done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[CHECK Sticky bit (/tmp, /var/tmp)]"									>> ./$FILENAME.log 2>&1
	ls -ald /tmp /var/tmp											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[CHECK ETC]"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	FILES="/usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/write
		/usr/sbin/usernetctl /usr/sbin/userhelper /bin/mount /bin/umount
		/usr/sbin/lockdev /bin/ping /bin/ping6"
	for check_file in $FILES
	  do
	    if [ -f $check_file ];
	      then
		echo `ls -alL $check_file`									>> ./$FILENAME.log 2>&1
	       else
		echo $check_file "There is no files "								>> ./$FILENAME.log 2>&1
	    fi
	done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-24 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-25 start"												>> ./$FILENAME.log 2>&1
	ls -al $PROFILE												>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | grep -v "#" | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
	FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"


	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    FILE=$dir/$file
	    if [ -f $FILE ];
	      then
			ls -alL $FILE										>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-25 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-26 start"												>> ./$FILENAME.log 2>&1
	find /usr /dev /etc /var /tmp /home /root -xdev -type f -perm -2 -exec ls -al {} \; > u-26.txt 2>&1
	if [ `ls -al u-26.txt | awk '{ print $5 }'` -le 1 ]; then
		echo "World writable files does not exist."							>> ./$FILENAME.log 2>&1
	else
		echo "World writable files is exist"								>> ./$FILENAME.log 2>&1
		cat u-26.txt											>> ./$FILENAME.log 2>&1
	fi
	
rm -rf u-26.txt
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-26 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-27 start"												>> ./$FILENAME.log 2>&1
	find /dev -type f -exec ls -al {} \;									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-27 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-28 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/hosts.equiv ]"											>> ./$FILENAME.log 2>&1
	cat $HOSTS_EQUIV 											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[ /.rhosts ]"												>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
	FILES=".rhosts"

	for file in $FILES
	  do
	    FILE=$FILES
	    if [ -f $FILE ]
	      then
	        ls -alL $FILE											>> ./$FILENAME.log 2>&1
	    fi
	  done

	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    FILE=$dir/$file
	    if [ -f $FILE ]
	      then
			echo "- $FILE"										>> ./$FILENAME.log 2>&1
			cat $FILE										>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-28 finish"											>> ./$FILENAME.log 2>&1
echo " "	 												>> ./$FILENAME.log 2>&1

echo "##### U-29 start"												>> ./$FILENAME.log 2>&1
	ls -l /etc/hosts.lpd											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-29 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-30 start"												>> ./$FILENAME.log 2>&1
	(ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v "grep")			>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-30 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-31 start"												>> ./$FILENAME.log 2>&1
echo "[ umask ]"												>> ./$FILENAME.log 2>&1
	umask													>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[ /etc/profile  ]" 											>> ./$FILENAME.log 2>&1
	(cat $PROFILE | grep -i umask || echo umask no setting) 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[ /etc/default/login ]"	 										>> ./$FILENAME.log 2>&1
    ls -al $LOGIN_CONF 												>> ./$FILENAME.log 2>&1
	(cat $LOGIN_CONF | grep -i umask	|| echo umask no setting)					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-31 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-32 start"												>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: 'length($6) > 0 {print $6}' | sort -u`

         for dir in $HOMEDIRS
          do
            ls -dal $dir 											>> ./$FILENAME.log 2>&1
         done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-32 finish"											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### U-33 start"												>> ./$FILENAME.log 2>&1
HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: 'length($6) > 0 {print $1, $6}'`
USERS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: '{print $1}'`

	for user in $USERS; do
		if [ ! -d `awk -F: -v "usr=${user}" '{ if ( $1==usr ) print $6 }' $PASSWD` ]; then
			echo "[ Home Directory does not exist ]"						>> ./$FILENAME.log 2>&1
			echo "$user : " `awk -F: -v "usr=${user}" '{ if ( $1==usr ) print $6 }' $PASSWD`	>> ./u-34.txt 2>&1
		fi
	done

	if [ `ls -al u-34.txt | awk '{print $5}'` -gt 0 ]; then
		echo "Home Directory is OK"									>> ./$FILENAME.log 2>&1
	else
		cat u-34.txt											>> ./$FILENAME.log 2>&1
		rm -rf u-34.txt
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-33 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-34 start"												>> ./$FILENAME.log 2>&1
echo "[ result1 ] "												>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v 'nologin' | grep -v 'false' | awk -F: 'length($6) > 0 {print $6}' | sort -u`

         for dir in $HOMEDIRS
          do
	    echo "----------<" ${dir} ">----------"								>> ./$FILENAME.log 2>&1
	  		 ls -a $dir | grep "^\."								>> ./$FILENAME.log 2>&1
         done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[ result2 ] "												>> ./$FILENAME.log 2>&1
	find / -xdev -iname ".*" -type f -perm -1 -exec ls -al {} \;						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-34 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "----------------------- 3. Service security -----------------------"					>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-35 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/hosts.allow ]"											>> ./$FILENAME.log 2>&1
	ls -al /etc/hosts.allow											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/hosts.allow ]"										>> ./$FILENAME.log 2>&1
	cat /etc/hosts.allow 											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/hosts.deny ]"											>> ./$FILENAME.log 2>&1
	ls -al /etc/hosts.deny											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/hosts.deny ]"										>> ./$FILENAME.log 2>&1
	cat /etc/hosts.deny 											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/sysconfig/iptables ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/sysconfig/iptables										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/sysconfig/iptables ]"									>> ./$FILENAME.log 2>&1
	cat /etc/sysconfig/iptables 										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-35 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-36 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/inetd.conf ]"			 								>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep finger || echo "Finger service disable")					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/xinetd.d ]"			 								>> ./$FILENAME.log 2>&1
	(ls -al /etc/xinetd.d | grep finger)									>> ./$FILENAME.log 2>&1
	(cat /etc/xinetd.d/finger | egrep "service|disable" )							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ finger Process ]"			 								>> ./$FILENAME.log 2>&1
	(ps -ef | grep finger | grep -v grep || echo "Finger service disable")					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-36 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-37 start"												>> ./$FILENAME.log 2>&1
echo "[ FTP service ]"			 									>> ./$FILENAME.log 2>&1
	(ps -ef | grep ftp | grep -v grep) 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ FTP port ]"												>> ./$FILENAME.log 2>&1
	(netstat -an | grep :21 | grep LISTEN)									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ FTP account ]"												>> ./$FILENAME.log 2>&1
	(cat $PASSWD | grep '^ftp' | grep -v grep) 								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ vsftp  ]"												>> ./$FILENAME.log 2>&1
	(cat /etc/vsftpd/vsftp.conf	| grep -i anonymous_enable)						>> ./$FILENAME.log 2>&1
	(cat /etc/vsftp.conf	| grep -i anonymous_enable)							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " [ ftp access checking ] "										>> ./$FILENAME.log 2>&1
ftpd=`netstat -na |grep -E LISTEN | grep -E tcp| grep -E ":21"`							>> ./$FILENAME.log 2>&1
echo $ftpd													>> ./$FILENAME.log 2>&1
ftpd_len=${#ftpd}
if [ $ftpd_len -gt 0 ]; then
  echo "**********************"											>> ./$FILENAME.log 2>&1
  echo "ftp service Running !!"											>> ./$FILENAME.log 2>&1
  echo "**********************"											>> ./$FILENAME.log 2>&1
ftp -inv 127.0.0.1 << finishFTP											>> ./$FILENAME.log 2>&1
user anonymous ftp@ftp.com											>> ./$FILENAME.log 2>&1
bye														>> ./$FILENAME.log 2>&1
finishFTP
else
  echo "ftp service Not running....OK"										>> ./$FILENAME.log 2>&1
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-37 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-38 start"												>> ./$FILENAME.log 2>&1
echo "[ r commands /etc/inetd.conf ]" 										>> ./$FILENAME.log 2>&1
	ls -al $INETD_CONF											>> $FILENAME.log 2>&1
	(cat $INETD_CONF | grep -v '^#' | egrep 'rsh|rcp|rlogin|rexec' || echo no r commands)			>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ r commands /etc/xinetd.d ]" 										>> ./$FILENAME.log 2>&1
	(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'rsh|rcp|rlogin|rexec' || echo no r commands)		>> $FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ Process ]" 												>> ./$FILENAME.log 2>&1
	(ps -ef | egrep 'rsh|rcp|rlogin|rexec' | grep -v grep || echo rsh,rcp,rlogin,rexec no process)		>> $FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/hosts.equiv ]"											>> ./$FILENAME.log 2>&1
	cat $HOSTS_EQUIV 											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /.rhosts ]"												>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | grep -v '/bin/false' | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
	FILES=".rhosts"

	for file in $FILES
	  do
	    FILE=$FILES
	    if [ -f $FILE ];
	      then
	        ls -alL $FILE											>> ./$FILENAME.log 2>&1
	    fi
	  done

	for dir in $HOMEDIRS
	do
	  for file in $FILES
	  do
	    FILE=$dir/$file
	    if [ -f $FILE ];
	      then
			echo "- $FILE"										>> ./$FILENAME.log 2>&1
			cat $FILE										>> ./$FILENAME.log 2>&1
	    fi
	  done
	done
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-38 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-39 start"												>> ./$FILENAME.log 2>&1
echo "[ cron ]"													>> ./$FILENAME.log 2>&1
	ls -al $CRON_ALLOW $CRON_DENY										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-39 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-40 start"												>> ./$FILENAME.log 2>&1
echo "[ inetd.conf  ]"												>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep -v '^#' | egrep 'echo|discard|daytime|chargen' || echo "[ no service ]")	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/xinetd.d  ]"											>> ./$FILENAME.log 2>&1
	(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'echo|discard|daytime|chargen' || echo "[ no service ]")	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ Process ]" 												>> ./$FILENAME.log 2>&1
	(ps -ef | egrep 'echo|discard|daytime|chargen' | grep -v grep || echo "echo,discard,daytime,chargen no process")			>> $FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-40 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-41 start"												>> ./$FILENAME.log 2>&1
echo "[ NFS  ]"													>> ./$FILENAME.log 2>&1
	(ps -ef | egrep 'nfs|statd|lockd' | grep -v grep) 							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-41 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-42 start"												>> ./$FILENAME.log 2>&1
echo "[  /etc/exports ]"										>> ./$FILENAME.log 2>&1
	ls -al $NFS_CONF											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of  /etc/exports ]"										>> ./$FILENAME.log 2>&1
	cat $NFS_CONF												>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ share ] "												>> ./$FILENAME.log 2>&1
	share													>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/dfs/dfstab ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/dfs/dfstab											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/dfs/dfstab ]"										>> ./$FILENAME.log 2>&1
	cat /etc/dfs/dfstab											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-42 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1


echo "##### U-43 start"												>> ./$FILENAME.log 2>&1
echo "Linux SVR : N/A"												>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-43 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-44 start"												>> ./$FILENAME.log 2>&1
echo "[ rpc $INETD_CONF ]" 											>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep -v '^#' | egrep 'rpc.cmsd|rusersd|rstatd|rpc.statd|kcms_server|rpc.ttdbserverd|Walld|rpc.nids|rpc.ypupdated|cachefsd|sadmind|sprayd|rpc.pcnfsd|rexd|rpc.rquotad')	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ rpc /etc/xinetd.d ]" 											>> ./$FILENAME.log 2>&1
	(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'rpc.cmsd|rusersd|rstatd|rpc.statd|kcms_server|rpc.ttdbserverd|Walld|rpc.nids|rpc.ypupdated|cachefsd|sadmind|sprayd|rpc.pcnfsd|rexd|rpc.rquotad')	>> $FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ rpc Process ]" 												>> ./$FILENAME.log 2>&1
	(ps -ef | egrep 'rpc.cmsd|rusersd|rstatd|rpc.statd|kcms_server|rpc.ttdbserverd|Walld|rpc.nids|rpc.ypupdated|cachefsd|sadmind|sprayd|rpc.pcnfsd|rexd|rpc.rquotad' | grep -v grep) >> $FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-44 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-45 start"												>> ./$FILENAME.log 2>&1
echo "[ NIS, NIS+ service ]"											>> ./$FILENAME.log 2>&1
	(ps -ef | grep -v 'grep' | egrep 'ypserv|ypbind|rpc.yppasswdd|ypxfrd|rpc.ypupdate' | grep -v grep || echo NIS no service) 		>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-45 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-46 start"												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/inetd.conf ]"										>> ./$FILENAME.log 2>&1
	(cat $INETD_CONF | grep -v '^#' | egrep 'tftp|talk|ntalk' || echo "[no tftp, talk service]")		>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/xinetd.d ]"											>> ./$FILENAME.log 2>&1
	(ls -al /etc/xinetd.d | grep -v '^#' | egrep 'tftp|talk|ntalk' || echo "[no tftp, talk service]")	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ Process ]" 												>> ./$FILENAME.log 2>&1
	(ps -ef | egrep 'tftp|talk' | grep -v grep || echo "tftp,talk no process") >> $FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-46 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-47 start"												>> ./$FILENAME.log 2>&1
echo "[ SMTP service ]"			 									>> ./$FILENAME.log 2>&1
	(ps -ef | grep sfinishmail | grep -v grep) 								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SMTP port ]"												>> ./$FILENAME.log 2>&1
	netstat -an | grep :25 | grep LISTEN 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ Sfinishmail Package Version ]"										>> ./$FILENAME.log 2>&1
	(rpm -q sfinishmail --queryformat '%{name} %{version}\n') 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ Sfinishmail Version ]"											>> ./$FILENAME.log 2>&1
	(grep DZ $SMTP_CONF) 											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-47 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-48 start"												>> ./$FILENAME.log 2>&1
echo "[ SPAM relay ]"												>> ./$FILENAME.log 2>&1
	cat /etc/mail/access										 	>> ./$FILENAME.log 2>&1
	cat /etc/mail/access.db										 	>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ sfinishmail.cf ]"											>> ./$FILENAME.log 2>&1
	(cat /etc/mail/sfinishmail.cf | grep "R$\*" | grep "Relaying denied"	)				>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-48 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-49 start"												>> ./$FILENAME.log 2>&1
echo "[ SMTP conf check ($SMTP_CONF) ]"										>> ./$FILENAME.log 2>&1
	(cat $SMTP_CONF  | grep PrivacyOptions) 								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-49 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-50 start"												>> ./$FILENAME.log 2>&1
echo "[ DNS service ]"												>> ./$FILENAME.log 2>&1
    (ps -ef | grep named | grep -v grep || echo named daemon no service)					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ DNS port(53) ]"												>> ./$FILENAME.log 2>&1
	netstat -an | grep :53 | grep LISTEN || echo 53 port no open 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ DNS version ]"												>> ./$FILENAME.log 2>&1
    dig @localhost txt chaos version.bind. 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-50 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-51 start"												>> ./$FILENAME.log 2>&1
echo "[ DNS ZoneTransfer(/etc/named.conf)  ]"									>> ./$FILENAME.log 2>&1
	(cat /etc/named.conf | grep allow-transfer || echo DNS Zone Transfer no setting)			>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-51 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-52 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i indexes | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "*** Allowed Directory Listing($HTTPD_CONF)"					>> ./$FILENAME.log 2>&1
			grep -n -i indexes $HTTPD_CONF | grep -v '#'						>> ./$FILENAME.log 2>&1
		fi
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-52 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-53 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `ps -ef | grep httpd | grep -v root | grep -v grep | wc -l` -ge 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v root | grep -v grep					>> ./$FILENAME.log 2>&1
		else
			echo "Apache is running as root"							>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v grep							>> ./$FILENAME.log 2>&1
		fi
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-53 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-54 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		ret=`awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$' | grep -i indexes`
		if [ `awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$' | grep -i indexes | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Indexes is set"									>> ./$FILENAME.log 2>&1
			ps -ef | grep httpd | grep -v grep							>> ./$FILENAME.log 2>&1
		fi
		awk '/<Directory \/>/,/Directory>/' $HTTPD_CONF | grep -v '#' | grep -v '^$'			>> ./$FILENAME.log 2>&1
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-54 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-55 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `ls -ald $HTTPD_ROOT | egrep -i 'samples|docs' | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			echo `ls -ald $HTTPD_ROOT`								>> ./$FILENAME.log 2>&1
			ls -al $HTTPD_ROOT									>> ./$FILENAME.log 2>&1
		else
			echo "Unnecessary file exists"								>> ./$FILENAME.log 2>&1
			ls -al $HTTPD_ROOT | egrep -i 'samples|docs'						>> ./$FILENAME.log 2>&1
		fi
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-55 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-56 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i followsymlinks | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Allowed Symbolic link($HTTPD_CONF)"						>> ./$FILENAME.log 2>&1
			grep -n -i followsymlinks $HTTPD_CONF | grep -v '#'					>> ./$FILENAME.log 2>&1
		fi
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-56 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-57 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		if [ `grep -n -i options $HTTPD_CONF | grep -v '#' | grep -i limitrequestbody | wc -l` -ge 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
			grep -n -i limitrequestbody $HTTPD_CONF | grep -v '#'					>> ./$FILENAME.log 2>&1
		else
			echo "No limit capacity to upload and download"						>> ./$FILENAME.log 2>&1
		fi
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-57 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-58 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		grep -i "^documentroot" $HTTPD_CONF | awk '{print$2}' | tr -d \" > u-58.txt

		if [ `cat u-58.txt | grep '$HTTPD_ROOT' | wc -l` -eq 0 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "DocumentRoot exists in the installation directory of Apache."			>> ./$FILENAME.log 2>&1
		fi
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-58 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-59 start"												>> ./$FILENAME.log 2>&1
echo "[ SSH service ]"												>> ./$FILENAME.log 2>&1
	ps -ef | grep ssh	| grep -v grep									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SSH port ]"				 								>> ./$FILENAME.log 2>&1
	netstat -an | grep :22 | grep LISTEN 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-59 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-60 start"												>> ./$FILENAME.log 2>&1
echo "[ FTP service ]"			 									>> ./$FILENAME.log 2>&1
	ps -ef | grep ftp | grep -v grep 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ FTP port ]"												>> ./$FILENAME.log 2>&1
	netstat -an | grep :21 | grep LISTEN									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-60 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-61 start"												>> ./$FILENAME.log 2>&1
echo "[ FTP account ]"												>> ./$FILENAME.log 2>&1
	(cat $PASSWD | grep '^ftp' || echo "[ no account ]") 							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-61 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-62 start"												>> ./$FILENAME.log 2>&1
echo "[ PROFTP ]	"											>> ./$FILENAME.log 2>&1
echo "[ /etc/ftpusers ]"											>> ./$FILENAME.log 2>&1
	ls -al /etc/ftpusers											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ NCFTP ]	"												>> ./$FILENAME.log 2>&1
echo "[ /etc/ftpd/ftpusers ]"											>> ./$FILENAME.log 2>&1
	ls -al /etc/ftpd/ftpusers										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ VSFTP ]	"												>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd.userlist]"											>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd.userlist										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/user_list ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/user_list										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/vsftpd.userlist ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/vsftpd.userlist									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/ftpusers ]"											>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/ftpusers 										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/vsftpd.ftpusers ]"										>> ./$FILENAME.log 2>&1
	ls -al /etc/vsftpd/vsftpd.ftpusers 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-62 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-63 start"												>> ./$FILENAME.log 2>&1
echo "[ PROFTP ]	"											>> ./$FILENAME.log 2>&1
echo "[ content of /etc/ftpusers ]"										>> ./$FILENAME.log 2>&1
	cat /etc/ftpusers											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ NCFTP ]	"												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/ftpd/ftpusers ]"									>> ./$FILENAME.log 2>&1
	cat /etc/ftpd/ftpusers											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ VSFTP ]	"												>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd.conf ]"										>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd.conf | grep userlist_enable								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/vsftpd.conf ]"									>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd/vsftpd.conf | grep userlist_enable							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd.userlist ]"									>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd.userlist										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/user_list ]"									>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd/user_list										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/vsftpd.userlist ]"								>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd/vsftpd.userlist										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/ftpusers ]"									>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd/ftpusers 										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ content of /etc/vsftpd/vsftpd.ftpusers ]"								>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd/vsftpd.ftpusers 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-63 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-64 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/at.deny ]"												>> ./$FILENAME.log 2>&1
	ls -al $AT_DENY												>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/at.allow ]"											>> ./$FILENAME.log 2>&1
	ls -al $AT_ALLOW											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-64 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-65 start"												>> ./$FILENAME.log 2>&1
echo "[ SNMP service ]"			 									>> ./$FILENAME.log 2>&1
	(ps -ef | grep snmpd | grep -v grep || echo SNMP no service) 						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SNMP port ]"												>> ./$FILENAME.log 2>&1
	(netstat -an | grep :161 || echo SNMP no port)								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-65 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-66 start"												>> ./$FILENAME.log 2>&1
echo "[ $SNMP_CONF ]"												>> ./$FILENAME.log 2>&1
	ls -al $SNMP_CONF											>> ./$FILENAME.log 2>&1
	(cat $SNMP_CONF  | grep community | grep -v '^#') 							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-66 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-67 start"												>> ./$FILENAME.log 2>&1
echo "[ motd ]"													>> ./$FILENAME.log 2>&1
	(cat /etc/motd)												>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/issue ]"												>> ./$FILENAME.log 2>&1
	cat /etc/issue												>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/security/login.cfg ]"										>> ./$FILENAME.log 2>&1
	cat /etc/security/login.cfg										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SSH BANNER ]"												>> ./$FILENAME.log 2>&1
echo "- $SSH_CONF"												>> ./$FILENAME.log 2>&1
	(cat $SSH_CONF | grep -i Banner || echo "no configs")							>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/issue.net ]" 											>> ./$FILENAME.log 2>&1
	cat /etc/issue.net											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ FTP BANNER ]"												>> ./$FILENAME.log 2>&1
echo "- $FTP_BANNER"												>> ./$FILENAME.log 2>&1
	(cat $FTP_BANNER | grep -i BANNER) 									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "- /etc/ftpd/ftpaccess(banner)"										>> ./$FILENAME.log 2>&1
	ls -al /etc/ftpd/ftpaccess 									 	>> ./$FILENAME.log 2>&1
	(`cat /etc/ftpd/ftpaccess | grep banner | awk '{print $2}'`)						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "- /etc/ftpd/ftpaccess(message)"										>> ./$FILENAME.log 2>&1
	(`cat /etc/ftpd/ftpaccess | grep message | awk '{print $2}'`)						>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "- /etc/ftpd/ftpaccess(version)"										>> ./$FILENAME.log 2>&1
	(cat /etc/ftpd/ftpaccess | grep greeting)								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ SMTP Banner ]"												>> ./$FILENAME.log 2>&1
	(cat $SMTP_CONF | grep -i GreetingMessage)								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ DNS BANNER ]"												>> ./$FILENAME.log 2>&1
    ls -al /etc/named.conf 									 		>> ./$FILENAME.log 2>&1
	(cat /etc/named.conf | grep version || echo DNS BANNER no setting)					>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-67 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-68 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/exports ]"												>> ./$FILENAME.log 2>&1
	ls -al $NFS_CONF											>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-68 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-69 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/mail/sfinishmail.cf ]"										>> ./$FILENAME.log 2>&1
if [ -f /etc/mail/sfinishmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sfinishmail.cf | grep PrivacyOptions						>> ./$FILENAME.log 2>&1
  else
    echo "no file(/etc/mail/sfinishmail.cf)"									>> ./$FILENAME.log 2>&1
fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-69 finish"											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### U-70 start"												>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		check=`grep -i servertokens $HTTPD_CONF | awk '{print $2}' | grep "Prod" | wc -l`
		if [ `grep -i servertokens $HTTPD_CONF | awk '{print $2}' | grep "Prod" | wc -l` -eq 1 ]; then
			echo "@ OK"										>> ./$FILENAME.log 2>&1
		else
			echo "Apache Web server ServerTokens has not been set"					>> ./$FILENAME.log 2>&1
		fi
		cat $HTTPD_CONF | grep -i servertokens								>> ./$FILENAME.log 2>&1
	fi
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-70 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "----- 4. Management of log and patch -----------------------------"					>> ./$FILENAME.log 2>&1
echo "********************************************************"							>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "##### U-71 start"												>> ./$FILENAME.log 2>&1
echo "[ Version ]"												>> ./$FILENAME.log 2>&1
uname -a													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
	rpm -qa													>> ./$FILENAME.patchlist.log
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-71 finish"											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### U-72 start"												>> ./$FILENAME.log 2>&1
echo " Manual Check : Interview " 										>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "##### U-72 finish"											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### U-73 start"												>> ./$FILENAME.log 2>&1
echo "[ /etc/syslog.conf ]"											>> ./$FILENAME.log 2>&1
	(cat $SYSLOG_CONF | grep -v "#"	)									>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "[ /etc/rsyslog.conf  ]"											>> ./$FILENAME.log 2>&1
	(cat /etc/rsyslog.conf | grep -v "#"	)								>> ./$FILENAME.log 2>&1
echo "+++++" 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo "##### U-73 finish"											>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1


echo "================== ETC ========================"								>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### process ###"												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	ps -ef | grep -v grep | grep -v ps | sort | uniq							>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### listen port ###"											>> ./$FILENAME.log 2>&1
	netstat -an												>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### xinetd.d ###"												>> ./$FILENAME.log 2>&1
    ls -al /etc/xinetd.d 											>> $FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "###/etc/login.defs ###"											>> ./$FILENAME.log 2>&1
	cat $PASSWD_CONF											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### /etc/pam.d/login ###"											>> ./$FILENAME.log 2>&1
	cat $LOGIN_CONF												>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### /etc/pam.d/common-password ###"									>> ./$FILENAME.log 2>&1
	cat /etc/pam.d/common-password										>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### /etc/pam.d/common-auth ###"										>> ./$FILENAME.log 2>&1
	cat /etc/pam.d/common-auth										>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### /etc/pam.d/system-auth ###"										>> ./$FILENAME.log 2>&1
	cat /etc/pam.d/system-auth										>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### /etc/xinetd.conf ###"											>> ./$FILENAME.log 2>&1
	cat /etc/xinetd.conf											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "### /etc/ssh/sshd_config ###"										>> ./$FILENAME.log 2>&1
	cat $SSH_CONF												>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### /etc/profile ###"											>> ./$FILENAME.log 2>&1
	cat $PROFILE												>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "############# /etc/syslog.conf"										>> ./$FILENAME.log 2>&1
	cat $SYSLOG_CONF											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### /etc/rsyslog.conf ###"										>> ./$FILENAME.log 2>&1
	cat /etc/rsyslog.conf											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### /etc/vsftpd/vsftd.conf ###"										>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd/vsftpd.conf ]"										>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd/vsftpd.conf 										>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo "[ /etc/vsftpd.conf ]"											>> ./$FILENAME.log 2>&1
	cat /etc/vsftpd.conf 											>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "############# /etc/mail/sfinishmail.cf"									>> ./$FILENAME.log 2>&1
	cat /etc/mail/sfinishmail.cf										>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "### U-17 ###"												>> ./$FILENAME.log 2>&1
   (cat U-17.txt) 												>> ./$FILENAME.log 2>&1
   rm -rf U-17.txt


echo "############# USER HOMEDIRECTORY"										>> ./$FILENAME.log 2>&1
	HOMEDIRS=`cat $PASSWD | awk -F: 'length($6) > 0 {print $6}' | sort -u`

         for dir in $HOMEDIRS
          do
	    echo "----------<" ${dir} ">----------"								>> ./$FILENAME.log 2>&1
            ls -al $dir 											>> ./$FILENAME.log 2>&1
         done
echo " " 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1

echo "##### Apache Conf. ###############"									>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
	if [ $APACHE_CHECK == "OFF" ]; then
		echo "APACHE is disabled"									>> ./$FILENAME.log 2>&1
	else
		cat $HTTPD_CONF | grep -v '#'									>> ./$FILENAME.log 2>&1
	fi
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1

echo "############# $SERVICES"											>> ./$FILENAME.log 2>&1
	cat $SERVICES												>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1
echo " " 													>> ./$FILENAME.log 2>&1
echo " "													>> ./$FILENAME.log 2>&1


echo "================== finish of Script ========================"						>> ./$FILENAME.log 2>&1
echo " "
date
date														>> ./$FILENAME.log 2>&1


exit 0