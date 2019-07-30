#!/bin/sh

#
# Linux Vulnerability Scanner by OPENSECURELAB
# 

HOSTNAME=`hostname`
LANG=C
export LANG
clear
BUILD_VER=1.17.01
LAST_UPDATE=2017.01.04
CREATE_FILE=`hostname`_Linux_`date +%y-%m-%d`.txt
echo " " > $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "###################################################################" >> $CREATE_FILE 2>&1
echo "     LINUX Vulnerability Check Version $BUILD_VER ($LAST_UPDATE)   " >> $CREATE_FILE 2>&1
echo "###################################################################" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

echo "###########################  LINUX Security Check-v${BUILD_VER}  #############################"
echo "###########################  LINUX Security Check-v${BUILD_VER}  #############################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "##################################  Start Time  #######################################"
date
echo "##################################  Start Time  #######################################" >> $CREATE_FILE 2>&1
date                                                                                           >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=========================== System Information Query Start ============================"
echo "=========================== System Information Query Start ============================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "###############################  Kernel Information  ##################################"
echo "###############################  Kernel Information  ##################################" >> $CREATE_FILE 2>&1
uname -a                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################## IP Information #####################################"
echo "################################## IP Information #####################################" >> $CREATE_FILE 2>&1
ifconfig -a                                                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################  Network Status(1) ###################################"
echo "################################  Network Status(1) ###################################" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED"                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Network Status(2) ##################################"
echo "################################   Network Status(2) ##################################" >> $CREATE_FILE 2>&1
netstat -nap | egrep -i "tcp|udp"                                                              >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#############################   Routing Information   #################################"
echo "#############################   Routing Information   #################################" >> $CREATE_FILE 2>&1
netstat -rn                                                                                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "################################   Process Status   ###################################"
echo "################################   Process Status   ###################################" >> $CREATE_FILE 2>&1
ps -ef                                                                                         >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "###################################   User Env   ######################################"
echo "###################################   User Env   ######################################" >> $CREATE_FILE 2>&1
env                                                                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "=========================== System Information Query End =============================="
echo "=========================== System Information Query End ==============================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "*************************************** START *****************************************"
echo "*************************************** START *****************************************" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "###########################        1. ���� ����        ################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-01 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.1 root ���� ���� ���� ���� #######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           1.1 root ���� ���� ���� ����            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����1: /etc/securetty ���Ͽ� pts/* ������ ������ ������ ���"                          >> $CREATE_FILE 2>&1 
echo "�� ����2: /etc/securetty ���Ͽ� pts/* ������ ���ų� �ּ�ó���� �Ǿ� �ְ�,"                >> $CREATE_FILE 2>&1 
echo "��        : /etc/pam.d/login���� auth required /lib/security/pam_securetty.so ���ο� �ּ�(#)�� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ����3: /etc/ssh/sshd_config ���Ͽ� permitrootlogin �ּ�ó���� �Ǿ� �ְų�, yes�� �Ǿ������� ���"                >> $CREATE_FILE 2>&1 
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
	else
		echo "�� Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/securetty ���� ����"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/securetty | grep "pts" | wc -l` -gt 0 ]
then
	cat /etc/securetty | grep "pts"                                                              >> $CREATE_FILE 2>&1
else
	echo "/etc/securetty ���Ͽ� pts/0~pts/x ������ �����ϴ�."                                    >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/pam.d/login ���� ����"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/pam.d/login | grep "pam_securetty.so"                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/ssh/sshd_config ���� ����"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config | grep -i "permitrootlogin"                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-01 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-02 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.2 �н����� ���⼺ ���� ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.2 �н����� ���⼺ ����              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ���� ���� Ư�����ڰ� ȥ�յ� 8�ڸ� �̻��� �н����尡 ������ ��� ��ȣ"                                        >> $CREATE_FILE 2>&1 
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  echo "�� /etc/passwd ����"                                                                   >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/passwd                                                                              >> $CREATE_FILE 2>&1
else
  echo "/etc/passwd ������ �����ϴ�."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
  echo "�� /etc/shadow ����"                                                                   >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/shadow                                                                              >> $CREATE_FILE 2>&1
else
  echo "/etc/shadow ������ �����ϴ�."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-02 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-03 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.3 ���� ��� �Ӱ谪 ���� ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            1.3 ���� ��� �Ӱ谪 ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/pam.d/system-auth ���Ͽ� �Ʒ��� ���� ������ ������ ��ȣ"                    >> $CREATE_FILE 2>&1
echo "��       : (auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root)" >> $CREATE_FILE 2>&1
echo "��       : (account required /lib/security/pam_tally.so no_magic_root reset)"             >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/pam.d/system-auth ���� ����(auth, account)"                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/pam.d/system-auth | grep -E "auth|account"                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-03 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-04 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.4 �н����� ���� ��ȣ #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.4 �н����� ���� ��ȣ               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �н����尡 /etc/shadow ���Ͽ� ��ȣȭ �Ǿ� ����ǰ� ������ ��ȣ"                  >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
	if [ `awk -F: '$2=="x"' /etc/passwd | wc -l` -eq 0 ]
	then
		echo "�� /etc/passwd ���Ͽ� �н����尡 ��ȣȭ �Ǿ� ���� �ʽ��ϴ�. (���)"                  >> $CREATE_FILE 2>&1
	else
		echo "�� /etc/passwd ���Ͽ� �н����尡 ��ȣȭ �Ǿ� �ֽ��ϴ�. (��ȣ)"                       >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "[����]"                                                                                >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat /etc/passwd | head -5                                                                    >> $CREATE_FILE 2>&1
	echo "���ϻ���..."                                                                           >> $CREATE_FILE 2>&1
else
	echo "�� /etc/passwd ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-04 END"                                                                                >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/passwd ����"                                                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  cat /etc/passwd                                                                              >> $CREATE_FILE 2>&1
else
	echo "/etc/shadow ������ �����ϴ�."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/shadow ����"                                                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
  cat /etc/shadow                                                                              >> $CREATE_FILE 2>&1
else
  echo "/etc/shadow ������ �����ϴ�."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-05 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.5 root �̿��� UID�� '0' ���� #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          1.5 root �̿��� UID�� '0' ����           ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: root �������� UID�� 0�̸� ��ȣ"                                                  >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                     >> $CREATE_FILE 2>&1
  else
    echo "�� /etc/passwd ������ �������� �ʽ��ϴ�."                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-05 END"                                                                                >> $CREATE_FILE 2>&1
echo "�� /etc/passwd ���� ����"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/passwd                                                                                >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1




echo "U-06 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.6 root ���� su ���� ##############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               1.6 root ���� su ����               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����1: /etc/pam.d/su ���� ������ �Ʒ��� ���� ��� ��ȣ"                                >> $CREATE_FILE 2>&1
echo "�� ����2: �Ʒ� ������ ���ų�, �ּ� ó���� �Ǿ� ���� ��� su ��� ������ ������ 4750 �̸� ��ȣ" >> $CREATE_FILE 2>&1
echo "��        : (auth  required  /lib/security/pam_wheel.so debug group=wheel) �Ǵ�"          >> $CREATE_FILE 2>&1
echo "��        : (auth  required  /lib/security/\$ISA/pam_wheel.so use_uid)"                   >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/pam.d/su ���� ����"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | wc -l` -eq 0 ]
	then
		echo "pam_wheel.so ���� ������ �����ϴ�."                                                  >> $CREATE_FILE 2>&1
	else
		cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust'                                  >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/pam.d/su ������ ã�� �� �����ϴ�."                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� su ���ϱ���"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `which su | grep -v 'no ' | wc -l` -eq 0 ]
then
	echo "su ��� ������ ã�� �� �����ϴ�."                                                      >> $CREATE_FILE 2>&1
else
	sucommand=`which su`;
	ls -alL $sucommand                                                                           >> $CREATE_FILE 2>&1
	sugroup=`ls -alL $sucommand | awk '{print $4}'`;
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� su ��ɱ׷�"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}' | wc -l` -gt 0 ]
	then
		pamsugroup=`cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}'`
		echo "- su��� �׷�(PAM���): `grep -E "^$pamsugroup" /etc/group`"                         >> $CREATE_FILE 2>&1
	else
		if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | egrep -v 'trust|#' | wc -l` -gt 0 ]
		then
			echo "- su��� �׷�(PAM���): `grep -E "^wheel" /etc/group`"                             >> $CREATE_FILE 2>&1
		fi
	fi
fi
echo "- su��� �׷�(�������): `grep -E "^$sugroup" /etc/group`"                               >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-06 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-07 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.7 �н����� �ּ� ���� ���� ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           1.7 �н����� �ּ� ���� ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �н����� �ּ� ���̰� 8�� �̻����� �����Ǿ� ������ ��ȣ"                          >> $CREATE_FILE 2>&1 
echo "��       : (PASS_MIN_LEN 8 �̻��̸� ��ȣ)"                                                >> $CREATE_FILE 2>&1 
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
then
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN"                                      >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-07 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-08 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.8 �н����� �ִ� ��� �Ⱓ ���� ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         1.8 �н����� �ִ� ��� �Ⱓ ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �н����� �ִ� ���Ⱓ�� 90�� ���Ϸ� �����Ǿ� ������ ��ȣ"                       >> $CREATE_FILE 2>&1 
echo "��       : (PASS_MAX_DAYS 90 �����̸� ��ȣ)"                                              >> $CREATE_FILE 2>&1 
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
then
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS"                                     >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-08 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1




echo "U-09 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.9 �н����� �ּ� ��� �Ⱓ ���� ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         1.9 �н����� �ּ� ��� �Ⱓ ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �н����� �ּ� ���Ⱓ�� 1�Ϸ� �����Ǿ� ������ ��ȣ"                             >> $CREATE_FILE 2>&1
echo "��       : (PASS_MIN_DAYS 1 �̻��̸� ��ȣ)"                                               >> $CREATE_FILE 2>&1 
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
then
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS"                                     >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-09 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-10 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.10 ���ʿ��� ���� ���� ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              1.10 ���ʿ��� ���� ����               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/passwd ���Ͽ� lp, uucp, nuucp ������ ��� ���ŵǾ� ������ ��ȣ"             >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "^lp|^uucp|^nuucp" | wc -l` -eq 0 ]
then
  echo "�� lp, uucp, nuucp ������ �������� �ʽ��ϴ�."                                          >> $CREATE_FILE 2>&1
else
  cat /etc/passwd | egrep "^lp|^uucp|^nuucp"                                                   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-10 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-11 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.11 ������ �׷쿡 �ּ����� ���� ���� ##############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################       1.11 ������ �׷쿡 �ּ����� ���� ����        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ������ ������ ���Ե� �׷쿡 ���ʿ��� ������ �������� �ʴ� ��� ��ȣ"             >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ������ ����"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                       >> $CREATE_FILE 2>&1
else
  echo "/etc/passwd ������ �����ϴ�."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ������ ������ ���Ե� �׷� Ȯ��"                                                       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
for group in `awk -F: '$3==0 { print $1}' /etc/passwd`
do
	cat /etc/group | grep "$group"                                                               >> $CREATE_FILE 2>&1
done
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-11 END"                                                                                >> $CREATE_FILE 2>&1
echo "[����] /etc/group ����"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/group                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-12 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.12 ������ �������� �ʴ� GID ���� #################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        1.12 ������ �������� �ʴ� GID ����         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �������� �������� �ʴ� �� �׷��� �߰ߵ��� ���� ��� ��ȣ"                        >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� �������� �������� �ʴ� �׷�"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `awk -F: '$4==null' /etc/group | wc -l` -eq 0 ]
then
	echo "�������� �������� �ʴ� �׷��� �߰ߵ��� �ʾҽ��ϴ�. (��ȣ)"                             >> $CREATE_FILE 2>&1
else
	awk -F: '$4==null' /etc/group                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-12 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-13 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.13 ������ UID ���� ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               1.13 ������ UID ����                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ������ UID�� ������ ������ �������� ���� ��� ��ȣ"                              >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ������ UID�� ����ϴ� ���� "                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       > total-equaluid.txt
for uid in `cat /etc/passwd | awk -F: '{print $3}'`
do
	cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }'                     > equaluid.txt
	if [ `cat equaluid.txt | wc -l` -gt 1 ]
	then
		cat equaluid.txt                                                                           >> total-equaluid.txt
	fi
done
if [ `sort -k 1 total-equaluid.txt | wc -l` -gt 1 ]
then
	sort -k 1 total-equaluid.txt | uniq -d                                                       >> $CREATE_FILE 2>&1
else
	echo "������ UID�� ����ϴ� ������ �߰ߵ��� �ʾҽ��ϴ�."                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-13 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf equaluid.txt
rm -rf total-equaluid.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-14 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.14 ����� Shell ���� #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              1.14 ����� Shell ����               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �α����� �ʿ����� ���� �ý��� ������ /bin/false(nologin) ���� �ο��Ǿ� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� �α����� �ʿ����� ���� �ý��� ���� Ȯ��"                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd ������ �����ϴ�."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-14 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-15 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.15 Session Timeout ���� ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.15 Session Timeout ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/profile ���� TMOUT=300 �Ǵ� /etc/csh.login ���� autologout=5 �� �����Ǿ� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "��       : (1) sh, ksh, bash ���� ��� /etc/profile ���� ������ �������"                 >> $CREATE_FILE 2>&1
echo "��       : (2) csh, tcsh ���� ��� /etc/csh.cshrc �Ǵ� /etc/csh.login ���� ������ �������" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� �α��� ���� TMOUT"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
if [ `set | egrep -i "TMOUT|autologout" | wc -l` -gt 0 ]
then
	set | egrep -i "TMOUT|autologout"                                                            >> $CREATE_FILE 2>&1
else
	echo "TMOUT �� �����Ǿ� ���� �ʽ��ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� TMOUT ���� Ȯ��"                                                                      >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
  echo "�� /etc/profile ����"                                                                  >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/profile | grep -i TMOUT | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/profile | grep -i TMOUT | grep -v "^#"                                            >> $CREATE_FILE 2>&1
  else
  	echo "TMOUT �� �����Ǿ� ���� �ʽ��ϴ�."                                                    >> $CREATE_FILE 2>&1
  fi
else
  echo "/etc/profile ������ �����ϴ�."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
then
  echo "�� /etc/csh.login ����"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.login | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
   	cat /etc/csh.login | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
  else
   	echo "autologout �� �����Ǿ� ���� �ʽ��ϴ�."                                               >> $CREATE_FILE 2>&1
  fi
else
  echo "/etc/csh.login ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.cshrc ]
then
  echo "�� /etc/csh.cshrc ����"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.cshrc | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/csh.cshrc | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
  else
  	echo "autologout �� �����Ǿ� ���� �ʽ��ϴ�."                                               >> $CREATE_FILE 2>&1
  fi
else
  echo "/etc/csh.cshrc ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-15 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#########################    2. ���� �� ���丮 ����    ##############################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-16 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.1 root Ȩ, �н� ���͸� ���� �� �н� ���� #######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################   2.1 root Ȩ, �н� ���͸� ���� �� �н� ����   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Path ������ ��.�� �� �� ���̳� �߰��� ���ԵǾ� ���� ���� ��� ��ȣ"                >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� PATH ���� Ȯ��"                                                                       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo $PATH                                                                                     >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-16 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-17 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.2 ���� �� ���͸� ������ ���� ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        2.2 ���� �� ���͸� ������ ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �����ڰ� �������� ���� ���� �� ���丮�� �������� ���� ��� ��ȣ"               >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� �����ڰ� �������� �ʴ� ���� (������ => ������ġ: ���)"                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc ]
then
  find /etc -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" > 1.17.txt
fi
if [ -d /var ]
then
find /var -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi
if [ -d /tmp ]
then
find /tmp -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi
if [ -d /home ]
then
find /home -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi
if [ -d /export ]
then
find /export -ls | awk '{print $5 " => " $11}' | egrep -v -i "(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z)" >> 1.17.txt
fi

if [ -s 1.17.txt ]
then
  cat 1.17.txt                                                                                 >> $CREATE_FILE 2>&1
else
  echo "�����ڰ� �������� �ʴ� ������ �߰ߵ��� �ʾҽ��ϴ�.(��ȣ)"                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-17 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.17.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-18 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.3 /etc/passwd ���� ������ �� ���� ���� ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.3 /etc/passwd ���� ������ �� ���� ����     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/passwd ������ �����ڰ� root �̰�, ������ 644 �̸� ��ȣ"                     >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
	ls -alL /etc/passwd                                                                          >> $CREATE_FILE 2>&1
else
	echo "�� /etc/passwd ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-18 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-19 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.4 /etc/shadow ���� ������ �� ���� ���� ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.4 /etc/shadow ���� ������ �� ���� ����     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/shadow ������ �����ڰ� root �̰�, ������ 400 �̸� ��ȣ"                     >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
	ls -alL /etc/shadow                                                                          >> $CREATE_FILE 2>&1
else
	echo "�� /etc/shadow ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-19 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-20 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.5 /etc/hosts ���� ������ �� ���� ���� ############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.5 /etc/hosts ���� ������ �� ���� ����      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/hosts ������ �����ڰ� root �̰�, ������ 600 �̸� ��ȣ"                      >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
then
	ls -alL /etc/hosts                                                                           >> $CREATE_FILE 2>&1
else
	echo "�� /etc/hosts ������ �����ϴ�."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-20 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-21 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.6 /etc/(x)inetd.conf ���� ������ �� ���� ���� ####################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.6 /etc/(x)inetd.conf ���� ������ �� ���� ����  #################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/(x)inetd.conf ���� �� /etc/xinetd.d/ ���� ��� ������ �����ڰ� root �̰�, ������ 600 �̸� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/xinetd.conf ����"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]
then
	ls -alL /etc/xinetd.conf                                                                     >> $CREATE_FILE 2>&1
else
	echo "/etc/xinetd.conf ������ �����ϴ�."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/xinetd.d/ ����"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
then
	ls -al /etc/xinetd.d/*                                                                       >> $CREATE_FILE 2>&1
else
	echo "/etc/xinetd.d ���͸��� �����ϴ�."                                                    >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/inetd.conf ����"                                                                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
then
	ls -alL /etc/inetd.conf                                                                      >> $CREATE_FILE 2>&1
else
	echo "/etc/inetd.conf ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-21 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-22 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.7 /etc/syslog.conf ���� ������ �� ���� ���� ######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.7 /etc/syslog.conf ���� ������ �� ���� ����   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/syslog.conf ������ ������ 644 �̸� ��ȣ"                                    >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	ls -alL /etc/syslog.conf                                                                     >> $CREATE_FILE 2>&1
else
	echo "�� /etc/syslog.conf ������ �����ϴ�."                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	ls -alL /etc/rsyslog.conf                                                                     >> $CREATE_FILE 2>&1
else
	echo "�� /etc/rsyslog.conf ������ �����ϴ�."                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-22 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-23 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.8 /etc/services ���� ������ �� ���� ���� #########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.8 /etc/services ���� ������ �� ���� ����    ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/services ������ ������ 644 �̸� ��ȣ"                                       >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
then
	ls -alL /etc/services                                                                        >> $CREATE_FILE 2>&1
else
	echo "�� /etc/services ������ �����ϴ�."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-23 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-24 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.9 SUID,SGID,Stick bit ���� ���� ���� #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      2.9 SUID,SGID,Stick bit ���� ���� ����      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ���ʿ��� SUID/SGID ������ �������� ���� ��� ��ȣ"                               >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

find /usr -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;        > 1.25.txt 2> /dev/null
find /bin -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;        >> 1.25.txt 2> /dev/null

if [ -s 1.25.txt ]
then
	cat 1.25.txt | egrep "sbin/dump|usr/bin/lpq-lpd|usr/bin/newgrp|sbin/resotre|usr/binlpr|usr/sbin/lpc|sbin/unix_chkpwd|usr/bin/lpr-lpd|usr/sbin/lpc-lpd|usr/bin/at|usr/bin/lprm|usr/bin/traceroute|usr/bin/lpq|usr/bin/lprm-lpd"       >> $CREATE_FILE 2>&1
else
	echo "�� SUID/SGID�� ������ ������ �߰ߵ��� �ʾҽ��ϴ�.(��ȣ)"                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-24 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.25.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-25 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.10 �����, �ý��� �������� �� ȯ������ ������ �� ���� ���� #######"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "############ 2.10 �����, �ý��� �������� �� ȯ������ ������ �� ���� ���� #############" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Ȩ���͸� ȯ�溯�� ���Ͽ� Ÿ����� ���� ������ ���ŵǾ� ������ ��ȣ"            >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� Ȩ���͸� ȯ�溯�� ����"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

for file in $FILES
do
  FILE=/$file
  if [ -f $FILE ]
  then
    ls -alL $FILE                                                                              >> $CREATE_FILE 2>&1
  fi
done

for dir in $HOMEDIRS
do
  for file in $FILES
  do
    FILE=$dir/$file
    if [ -f $FILE ]
    then
      ls -alL $FILE                                                                            >> $CREATE_FILE 2>&1
    fi
  done
done
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-25 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-26 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.11 world writable ���� ���� ######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          2.11 world writable ���� ����            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ���ʿ��� ������ �ο��� world writable ������ �������� ���� ��� ��ȣ"            >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -d /etc ]
then
  find /etc -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"         > world-writable.txt
fi
if [ -d /var ]
then
  find /var -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v "^l"         >> world-writable.txt
fi
if [ -d /usr ]
then
  find /usr -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}'| grep -v "^l"         >> world-writable.txt
fi
if [ -d /bin ]
then
  find /bin -perm -2 -ls | awk '{print $3 " : " $5 " : " $6 " : " $11}'| grep -v "^l"         >> world-writable.txt
fi

if [ -s world-writable.txt ]
then
  cat world-writable.txt                                                                       >> $CREATE_FILE 2>&1
else
  echo "�� World Writable ������ �ο��� ������ �߰ߵ��� �ʾҽ��ϴ�."                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-26 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf world-writable.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-27 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.12 /dev�� �������� �ʴ� device ���� ���� #########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.12 /dev�� �������� �ʴ� device ���� ����     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ���� : dev �� �������� ���� Device ������ �����ϰ�, �������� ���� Device�� ���� ���� ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "��        : (�Ʒ� ������ ����� major, minor Number�� ���� �ʴ� ������)"                  >> $CREATE_FILE 2>&1
echo "��        : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db�� Default�� ���� ����)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /dev -type f -exec ls -l {} \;                                                            > 1.32.txt

if [ -s 1.32.txt ]
then
	cat 1.32.txt                                                                                 >> $CREATE_FILE 2>&1
else
	echo "�� dev �� �������� ���� Device ������ �߰ߵ��� �ʾҽ��ϴ�."                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-27 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.32.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-28 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.13 HOME/.rhosts, hosts.equiv ��� ���� ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      2.13 HOME/.rhosts, hosts.equiv ��� ����     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: r-commands ���񽺸� ������� ������ ��ȣ"                                        >> $CREATE_FILE 2>&1
echo "��       : r-commands ���񽺸� ����ϴ� ��� HOME/.rhosts, hosts.equiv ����Ȯ��"          >> $CREATE_FILE 2>&1
echo "��       : (1) .rhosts ������ �����ڰ� �ش� ������ �������̰�, �۹̼� 600, ���뿡 + �� �����Ǿ� ���� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "��       : (2) /etc/hosts.equiv ������ �����ڰ� root �̰�, �۹̼� 600, ���뿡 + �� �����Ǿ� ���� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep ":$port " | grep -i "^tcp"                                                > 1.33.txt
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep ":$port " | grep -i "^tcp"                                                >> 1.33.txt
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	netstat -na | grep ":$port " | grep -i "^tcp"                                                >> 1.33.txt
fi

if [ -s 1.33.txt ]
then
	cat 1.33.txt | grep -v '^ *$'                                                                >> $CREATE_FILE 2>&1
else
	echo "�� r-command Service Disable"                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/hosts.equiv ���� ����"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.equiv ]
	then
		echo "(1) Permission: (`ls -al /etc/hosts.equiv`)"                                         >> $CREATE_FILE 2>&1
		echo "(2) ���� ����:"                                                                      >> $CREATE_FILE 2>&1
		echo "----------------------------------------"                                            >> $CREATE_FILE 2>&1
		if [ `cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$' | wc -l` -gt 0 ]
		then
			cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$'                                      >> $CREATE_FILE 2>&1
		else
			echo "���� ������ �����ϴ�."                                                             >> $CREATE_FILE 2>&1
		fi
	else
		echo "/etc/hosts.equiv ������ �����ϴ�."                                                   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ����� home directory .rhosts ���� ����"                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
FILES="/.rhosts"

for dir in $HOMEDIRS
do
	for file in $FILES
	do
		if [ -f $dir$file ]
		then
			echo " "                                                                                 > rhosts.txt
			echo "# $dir$file ���� ����:"                                                            >> $CREATE_FILE 2>&1
			echo "(1) Permission: (`ls -al $dir$file`)"                                              >> $CREATE_FILE 2>&1
			echo "(2) ���� ����:"                                                                    >> $CREATE_FILE 2>&1
			echo "----------------------------------------"                                          >> $CREATE_FILE 2>&1
			if [ `cat $dir$file | grep -v "#" | grep -v '^ *$' | wc -l` -gt 0 ]
			then
				cat $dir$file | grep -v "#" | grep -v '^ *$'                                           >> $CREATE_FILE 2>&1
			else
				echo "���� ������ �����ϴ�."                                                           >> $CREATE_FILE 2>&1
			fi
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		fi
	done
done
if [ ! -f rhosts.txt ]
then
	echo ".rhosts ������ �����ϴ�."                                                              >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
echo "U-28 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf rhosts.txt
rm -rf 1.33.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-29 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.14 ���� IP �� ��Ʈ ���� ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             2.14 ���� IP �� ��Ʈ ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/hosts.deny ���Ͽ� All Deny(ALL:ALL) ������ ��ϵǾ� �ְ�,"                  >> $CREATE_FILE 2>&1
echo "��       : /etc/hosts.allow ���Ͽ� ���� ��� IP�� ��ϵǾ� ������ ��ȣ"                   >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/hosts.allow ���� ����"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.allow ]
then
	if [ ! `cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$'                                       >> $CREATE_FILE 2>&1
	else
		echo "���� ������ �����ϴ�."                                                               >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/hosts.allow ������ �����ϴ�."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/hosts.deny ���� ����"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.deny ]
then
	if [ ! `cat /etc/hosts.deny | grep -v "#" | grep -ve '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.deny | grep -v "#" | grep -ve '^ *$'                                        >> $CREATE_FILE 2>&1
	else
		echo "���� ������ �����ϴ�."                                                               >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/hosts.deny ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo "U-29 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-30 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.15 host.lpd ���� ������ �� ���� ���� #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.15 host.lpd ���� ������ �� ���� ����    ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/host.lpd ������ �����ڰ� root �̰�, ������ 600 �̸� ��ȣ"                   >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/host.lpd ]
then
	ls -alL /etc/host.lpd                                                                        >> $CREATE_FILE 2>&1
else
	echo "�� /etc/host.lpd ������ �����ϴ�.(��ȣ)"                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-30 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-31 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.16 NIS ���� ��Ȱ��ȭ ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              2.16 NIS ���� ��Ȱ��ȭ             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: NIS, NIS+ ���񽺰� ���� ������ ���� ��쿡 ��ȣ"                                 >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "�� NIS, NIS+ Service Disable"                                                          >> $CREATE_FILE 2>&1
else
	ps -ef | egrep $SERVICE | grep -v "grep"                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-31 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-32 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.17 UMASK ���� ���� ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################                2.17 UMASK ���� ����               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: UMASK ���� 022 �̸� ��ȣ"                                                        >> $CREATE_FILE 2>&1
echo "��       : (1) sh, ksh, bash ���� ��� /etc/profile ���� ������ �������"                 >> $CREATE_FILE 2>&1
echo "��       : (2) csh, tcsh ���� ��� /etc/csh.cshrc �Ǵ� /etc/csh.login ���� ������ �������" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� �α��� ���� UMASK"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
umask                                                                                          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
	echo "�� /etc/profile ����(�ùٸ� ����: umask 022)"                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
	if [ `cat /etc/profile | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
		cat /etc/profile | grep -i umask | grep -v ^#                                              >> $CREATE_FILE 2>&1
	else
		echo "umask ������ �����ϴ�."                                                              >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/profile ������ �����ϴ�."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
then
  echo "�� /etc/csh.login ����"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.login | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
  	cat /etc/csh.login | grep -i umask | grep -v ^#                                            >> $CREATE_FILE 2>&1
  else
		echo "umask ������ �����ϴ�."                                                              >> $CREATE_FILE 2>&1
	fi
else
  echo "/etc/csh.login ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
then
  echo "�� /etc/csh.cshrc ����"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.cshrc | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
  	cat /etc/csh.cshrc | grep -i umask | grep -v ^#                                            >> $CREATE_FILE 2>&1
  else
		echo "umask ������ �����ϴ�."                                                              >> $CREATE_FILE 2>&1
	fi
else
  echo "/etc/csh.cshrc ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-32 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-33 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.18 Ȩ ���丮 ������ �� ���� ���� ###############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        2.18 Ȩ ���丮 ������ �� ���� ����       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Ȩ ���͸��� �����ڰ� /etc/passwd ���� ��ϵ� Ȩ ���͸� ����ڿ� ��ġ�ϰ�,"   >> $CREATE_FILE 2>&1
echo "��       : Ȩ ���͸��� Ÿ����� ��������� ������ ��ȣ"                                 >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ����� Ȩ ���͸�"                                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ -d $dir ]
	then
		ls -dal $dir | grep '\d.........'                                                          >> $CREATE_FILE 2>&1
	fi
done
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-33 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-34 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.19 Ȩ ���丮�� ������ ���丮�� ���� ���� #####################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.19 Ȩ ���丮�� ������ ���丮�� ���� ����   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Ȩ ���͸��� �������� �ʴ� ������ �߰ߵ��� ������ ��ȣ"                         >> $CREATE_FILE 2>&1
# Ȩ ���丮�� �������� �ʴ� ���, �Ϲ� ����ڰ� �α����� �ϸ� ������� ���� ���͸��� /�� �α��� �ǹǷ� ����,���Ȼ� ������ �߻���.
# ��) �ش� �������� ftp �α��� �� / ���͸��� �����Ͽ� �߿� ������ ����� �� ����.
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� Ȩ ���͸��� �������� ���� ����"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
	then
		awk -F: '$6=="'${dir}'" { print "�� ������(Ȩ���͸�):"$1 "(" $6 ")" }' /etc/passwd        >> $CREATE_FILE 2>&1
		echo " "                                                                                   > 1.29.txt
	fi
done

if [ ! -f 1.29.txt ]
then
	echo "Ȩ ���͸��� �������� ���� ������ �߰ߵ��� �ʾҽ��ϴ�. (��ȣ)"                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-34 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.29.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-35 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.20 ������ ���� �� ���丮 �˻� �� ���� ##########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.20 ������ ���� �� ���丮 �˻� �� ����      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ���丮 ���� ������ ������ Ȯ�� �� �˻� �Ͽ� , ���ʿ��� ���� ���� ��� ���� ���� ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /tmp -name ".*" -ls                                                                       >> $CREATE_FILE 2>&1
find /home -name ".*" -ls                                                                      >> $CREATE_FILE 2>&1
find /usr -name ".*" -ls                                                                       >> $CREATE_FILE 2>&1
find /var -name ".*" -ls                                                                       >> $CREATE_FILE 2>&1
echo "���� ����Ʈ���� ������ ���� Ȯ��"                                                               >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-35 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#############################     3. ���� ����     ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-36 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.1 finger ���� ��Ȱ��ȭ #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.1 finger ���� ��Ȱ��ȭ             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Finger ���񽺰� ��Ȱ��ȭ �Ǿ� ���� ��� ��ȣ"                                    >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -eq 0 ]
	then
		echo "�� Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
	fi
else
	if [ `netstat -na | grep ":79 " | grep -i "^tcp" | wc -l` -eq 0 ]
	then
		echo "�� Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":79 " | grep -i "^tcp"                                                 >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-36 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-37 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.2 Anonymous FTP ��Ȱ��ȭ #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.2 Anonymous FTP ��Ȱ��ȭ             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Anonymous FTP (�͸� ftp)�� ��Ȱ��ȭ ������ ��� ��ȣ"                            >> $CREATE_FILE 2>&1
echo "��       : (1)ftpd�� ����� ���: /etc/passwd ���ϳ� FTP �Ǵ� anonymous ������ �������� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "��       : (2)proftpd�� ����� ���: /etc/passwd ���ϳ� FTP ������ �������� ������ ��ȣ"  >> $CREATE_FILE 2>&1
echo "��       : (3)vsftpd�� ����� ���: vsftpd.conf ���Ͽ��� anonymous_enable=NO �����̸� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service����: ��Ʈ ���� X (Default 21�� ��Ʈ)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP ��Ʈ: ��Ʈ ���� X (Default 21�� ��Ʈ �����)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP ��Ʈ: VsFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP ��Ʈ: ��Ʈ ���� X (/etc/service ���Ͽ� ������ ��Ʈ�� �����)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP ��Ʈ: ProFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services ���Ͽ��� ��Ʈ Ȯ�� #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"                               >> $CREATE_FILE 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# vsftpd ���� ��Ʈ Ȯ�� ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi
################# proftpd ���� ��Ʈ Ȯ�� ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
else
	echo "�� FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� Anonymous FTP ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -s vsftpd.txt ]
then
	cat $vsfile | grep -i "anonymous_enable" | awk '{print "�� VsFTP ����: " $0}'                 >> $CREATE_FILE 2>&1
fi

if [ `cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l` -gt 0 ]
then
	echo "�� ProFTP, �⺻FTP ����:"                                                               >> $CREATE_FILE 2>&1
	cat /etc/passwd | egrep "^ftp:|^anonymous:"                                                  >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "�� ProFTP, �⺻FTP ����: /etc/passwd ���Ͽ� ftp �Ǵ� anonymous ������ �����ϴ�."        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-37 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-38 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.3 r �迭 ���� ��Ȱ��ȭ #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.3 r �迭 ���� ��Ȱ��ȭ             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: r-commands ���񽺸� ������� ������ ��ȣ"                                        >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��(���� ������ ��� �� ����)"                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > rcommand.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > rcommand.txt
	fi
fi

if [ `cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="exec" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > rcommand.txt
	fi
fi

if [ -f rcommand.txt ]
then
	rm -rf rcommand.txt
else
	echo "�� r-commands Service Disable"                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-38 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-39 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.4 cron ���� ������ �� ���Ѽ��� ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.4 cron ���� ������ �� ���Ѽ���          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: cron.allow �Ǵ� cron.deny ���� ������ 640 �̸��̸� ��ȣ"                         >> $CREATE_FILE 2>&1
echo "��       : (cron.allow �Ǵ� cron.deny ������ ���� ��� ��� ����ڰ� cron ����� ����� �� �����Ƿ� ���)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� cron.allow ���� ���� Ȯ��"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/cron.allow ]
then
	ls -alL /etc/cron.allow                                                                      >> $CREATE_FILE 2>&1
else
	echo "/etc/cron.allow ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� cron.deny ���� ���� Ȯ��"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/cron.deny ]
then
	ls -alL /etc/cron.deny                                                                       >> $CREATE_FILE 2>&1
else
	echo "/etc/cron.deny ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-39 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-40 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.5 Dos ���ݿ� ����� ���� ��Ȱ��ȭ ##############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.5 Dos ���ݿ� ����� ���� ��Ȱ��ȭ       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: DoS ���ݿ� ����� echo , discard , daytime , chargen ���񽺸� ������� �ʾ��� ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="echo" {print $1 "      " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp"                 >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp"                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="echo" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="discard" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="daytime" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="chargen" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > unnecessary.txt
	fi
fi

if [ -f unnecessary.txt ]
then
	rm -rf unnecessary.txt
else
	echo "���ʿ��� ���񽺰� �����ϰ� ���� �ʽ��ϴ�.(echo, discard, daytime, chargen)"            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-40 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-41 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.6 NFS ���� ��Ȱ��ȭ ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.6 NFS ���� ��Ȱ��ȭ               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ���ʿ��� NFS ���� ���� ������ ���ŵǾ� �ִ� ��� ��ȣ"                         >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� NFS Server Daemon(nfsd)Ȯ��"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
 else
   echo "�� NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� NFS Client Daemon(statd,lockd)Ȯ��"                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd" | wc -l` -gt 0 ] 
  then
    ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd"                    >> $CREATE_FILE 2>&1
  else
    echo "�� NFS Client(statd,lockd) Disable"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-41 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-42 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.7 NFS ���� ���� ##################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################                3.7 NFS ���� ����                 ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����1: NFS ���� ������ �������� ������ ��ȣ"                                           >> $CREATE_FILE 2>&1
echo "�� ����2: NFS ���� ������ �����ϴ� ��� /etc/exports ���Ͽ� everyone ���� ������ ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
# (��� ����) /tmp/test/share *(rw)
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� NFS Server Daemon(nfsd)Ȯ��"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
 else
   echo "�� NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/exports ���� ����"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
then
	if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/exports | grep -v "^#" | grep -v "^ *$"                                           >> $CREATE_FILE 2>&1
	else
		echo "���� ������ �����ϴ�."                                                               >> $CREATE_FILE 2>&1
	fi
else
  echo "/etc/exports ������ �����ϴ�."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-42 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-43 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.8 automountd ���� ################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.8 automountd ����                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: automountd ���񽺰� �������� ���� ��� ��ȣ"                                     >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� Automountd Daemon Ȯ��"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi" | wc -l` -gt 0 ] 
 then
   ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi"              >> $CREATE_FILE 2>&1
 else
   echo "�� Automountd Daemon Disable"                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-43 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-44 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.9 RPC ���� Ȯ�� ################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.9 RPC ���� Ȯ��                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ���ʿ��� rpc ���� ���񽺰� �������� ������ ��ȣ"                                 >> $CREATE_FILE 2>&1
echo "(rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

echo "�� ���ʿ��� RPC ���� ���� Ȯ��"                                                        >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
then
	if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]
	then
		echo "���ʿ��� RPC ���񽺰� �������� �ʽ��ϴ�."                                            >> $CREATE_FILE 2>&1
	else
		ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD                                             >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/xinetd.d ���丮�� �������� �ʽ��ϴ�."                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-44 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-45 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.10 NIS , NIS+ ���� ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.10 NIS , NIS+ ����                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: NIS, NIS+ ���񽺰� ���� ������ ���� ��쿡 ��ȣ"                                 >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�ش� �׸��� U-26 �׸� ���Ե� �׸��� �ش� ���� ����. (N/A)"                             >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-45 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-46 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.11 tftp, talk ���� ��Ȱ��ȭ ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.11 tftp, talk ���� ��Ȱ��ȭ          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: tftp, talk, ntalk ���񽺰� ���� ������ ���� ��쿡 ��ȣ"                         >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "  " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > 1.56.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > 1.56.txt
	fi
fi
if [ `cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "   " $2}' | grep "udp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^udp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^udp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > 1.56.txt
	fi
fi

if [ -f 1.56.txt ]
then
	rm -rf 1.56.txt
else
	echo "�� tftp, talk, ntalk Service Disable"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-46 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-47 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.12 Sendmail ���� ���� ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.12 Sendmail ���� ����               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: sendmail ������ 8.13.8 �̻��̸� ��ȣ"                                            >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > sendmail.txt
	fi
fi

if [ -f sendmail.txt ]
then
	rm -rf sendmail.txt
else
	echo "�� Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� sendmail ����Ȯ��"                                                                    >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
   then
     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ                                            >> $CREATE_FILE 2>&1
   else
     echo "/etc/mail/sendmail.cf ������ �����ϴ�."                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-47 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-48 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.13 ���� ���� ������ ���� #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.13 ���� ���� ������ ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: SMTP ���񽺸� ������� �ʰų� ������ ������ �����Ǿ� ���� ��� ��ȣ"             >> $CREATE_FILE 2>&1
echo "��       : (R$*         $#error $@ 5.7.1 $: "550 Relaying denied" �ش� ������ �ּ��� ���ŵǾ� ������ ��ȣ)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > sendmail.txt
	fi
fi

if [ -f sendmail.txt ]
then
	rm -rf sendmail.txt
else
	echo "�� Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/mail/sendmail.cf ������ �ɼ� Ȯ��"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"                           >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf ������ �����ϴ�."                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-48 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-49 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.14 �Ϲݻ������ Sendmail ���� ���� ###############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################       3.14 �Ϲݻ������ Sendmail ���� ����        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: SMTP ���񽺸� ������� �ʰų� ������ ������ �����Ǿ� ���� ��� ��ȣ"             >> $CREATE_FILE 2>&1
echo "��       : (restrictqrun �ɼ��� �����Ǿ� ���� ��� ��ȣ)"                                 >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/mail/services ���Ͽ��� ��Ʈ Ȯ��"                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > sendmail.txt
	fi
fi

if [ -f sendmail.txt ]
then
	rm -rf sendmail.txt
else
	echo "�� Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/mail/sendmail.cf ������ �ɼ� Ȯ��"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                                 >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf ������ �����ϴ�."                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-49 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-50 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.15 DNS ���� ���� ��ġ ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.15 DNS ���� ���� ��ġ               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: DNS ���񽺸� ������� �ʰų�, ��ȣ�� ������ ����ϰ� ���� ��쿡 ��ȣ"           >> $CREATE_FILE 2>&1
echo "��       : (��ȣ�� ����: 8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)"            >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
DNSPR=`echo $DNSPR | awk '{print $1}'`
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
then
	if [ -f $DNSPR ]
	then
    echo "BIND ���� Ȯ��"                                                                      >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
    $DNSPR -v | grep BIND                                                                      >> $CREATE_FILE 2>&1
  else
    echo "$DNSPR ������ �����ϴ�."                                                             >> $CREATE_FILE 2>&1
  fi
else
  echo "�� DNS Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-50 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-51 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.16 DNS Zone Transfer ���� ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.16 DNS Zone Transfer ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: DNS ���񽺸� ������� �ʰų� Zone Transfer �� ���ѵǾ� ���� ��� ��ȣ"           >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� DNS ���μ��� Ȯ�� " >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "�� DNS Service Disable"                                                                >> $CREATE_FILE 2>&1
else
	ps -ef | grep named | grep -v "grep"                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ls -al /etc/rc*.d/* | grep -i named | grep "/S" | wc -l` -gt 0 ]
then
	ls -al /etc/rc*.d/* | grep -i named | grep "/S"                                              >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
echo "�� /etc/named.conf ������ allow-transfer Ȯ��"                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/named.conf ]
then
	cat /etc/named.conf | grep 'allow-transfer'                                                  >> $CREATE_FILE 2>&1
else
	echo "/etc/named.conf ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/named.boot ������ xfrnets Ȯ��"                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/named.boot ]
then
	cat /etc/named.boot | grep "\xfrnets"                                                        >> $CREATE_FILE 2>&1
else
	echo "/etc/named.boot ������ �����ϴ�."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-51 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-52 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.17 Apache ���丮 ������ ���� ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         3.17 Apache ���丮 ������ ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: httpd.conf ������ Directory �κ��� Options �����ڿ� Indexes�� �����Ǿ� ���� ������ ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
############################### Ȩ���͸� ��� ���ϱ�(����) ##################################
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	APROC1=`ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq`
	APROC=`echo $APROC1 | awk '{print $1}'`

	if [ `$APROC -V | grep -i "root" | wc -l` -gt 0 ]
	then
		AHOME=`$APROC -V | grep -i "root" | awk -F"\"" '{print $2}'`
		ACFILE=`$APROC -V | grep -i "server_config_file" | awk -F"\"" '{print $2}'`
	else
		AHOME=/infosec_null
		ACFILE=infosec_null
	fi

	if [ -f $AHOME/$ACFILE ]
	then
		ACONF=$AHOME/$ACFILE
	else
		ACONF=$ACFILE
	fi
fi
################################ Ȩ���͸� ��� ���ϱ�(��) ###################################
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	if [ -f $ACONF ]
	then
		echo "�� Indexes ���� Ȯ��"                                                                >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                       >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#'                     >> $CREATE_FILE 2>&1
	else
		echo "�� Apache ���������� ã�� �� �����ϴ�.(��������)"                                    >> $CREATE_FILE 2>&1
	fi
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-52 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-53 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.18 Apache �� ���μ��� ���� ���� ##################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.18 Apache �� ���μ��� ���� ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �� ���μ��� ������ ���� ���� ��� ��ȣ(User root, Group root �� �ƴ� ���)"      >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "�� $ACONF ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "user" >> $CREATE_FILE 2>&1
	cat $ACONF | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "group" >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "�� httpd ���� ���� ���� Ȯ��"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	ps -ef | grep "httpd"                                                                        >> $CREATE_FILE 2>&1
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-53 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-54 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.19 Apache ���� ���丮 ���� ���� ################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.19 Apache ���� ���丮 ���� ����        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: httpd.conf ������ Directory �κ��� AllowOverride None ������ �ƴϸ� ��ȣ"        >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "�� $ACONF ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#'                 >> $CREATE_FILE 2>&1
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-54 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-55 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.20 Apache ���ʿ��� ���� ���� #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.20 Apache ���ʿ��� ���� ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /htdocs/manual �Ǵ� /apache/manual ���͸���,"                                  >> $CREATE_FILE 2>&1
echo "��       : /cgi-bin/test-cgi, /cgi-bin/printenv ������ ���ŵǾ� �ִ� ��� ��ȣ"           >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	if [ -d $AHOME/cgi-bin ]
	then
		echo "�� $AHOME/cgi-bin ����"                                                              >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		ls -ld $AHOME/cgi-bin/test-cgi                                                             >> $CREATE_FILE 2>&1
		ls -ld $AHOME/cgi-bin/printenv                                                             >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "�� $AHOME/cgi-bin ���͸��� ���ŵǾ� �ֽ��ϴ�.(��ȣ)"                               >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi

	if [ -d $AHOME/htdocs/manual ]
	then
		echo "�� $AHOME/htdocs/manual ����"                                                        >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		ls -ld $AHOME/htdocs/manual                                                                >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "�� $AHOME/htdocs/manual ���͸��� ���ŵǾ� �ֽ��ϴ�.(��ȣ)"                         >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi

	if [ -d $AHOME/manual ]
	then
		echo "�� $AHOME/manual ���� ����"                                                          >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		ls -ld $AHOME/manual                                                                       >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "�� $AHOME/manual ���͸��� ���ŵǾ� �ֽ��ϴ�.(��ȣ)"                                >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-55 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-56 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.21 Apache ��ũ ��� ���� #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.21 Apache ��ũ ��� ����            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: Options �����ڿ��� �ɺ� ��ũ�� �����ϰ� �ϴ� �ɼ��� FollowSymLinks�� ���ŵ� ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "�� $ACONF ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v '\#'                >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-56 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-57 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.22 Apache ���� ���ε� �� �ٿ�ε� ���� ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.22 Apache ���� ���ε� �� �ٿ�ε� ����     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �ý��ۿ� ���� ���� ���ε� �� �ٿ�ε忡 ���� �뷮�� ���ѵǾ� �ִ� ��� ��ȣ"     >> $CREATE_FILE 2>&1
echo "��       : <Directory ���>�� LimitRequestBody �����ڿ� ���ѿ뷮�� �����Ǿ� �ִ� ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "�� $ACONF ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#'              >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-57 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-58 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.23 Apache �� ���� ������ �и� ##################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         3.23 Apache �� ���� ������ �и�         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: DocumentRoot�� �⺻ ���͸�(~/apache/htdocs)�� �ƴ� ������ ���丮�� ������ ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "�� $ACONF ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-58 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-59 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.24 ssh �������� ��� #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              3.24 ssh �������� ���               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: SSH ���񽺰� Ȱ��ȭ �Ǿ� ������ ��ȣ"                                            >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���μ��� ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "�� SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
	else
		ps -ef | grep sshd | grep -v "grep"                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "�� ���� ��Ʈ Ȯ��"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " " > ssh-result.txt
ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		if [ `cat $file | grep ^Port | grep -v ^# | wc -l` -gt 0 ]
		then
			cat $file | grep ^Port | grep -v ^# | awk '{print "SSH ��������('${file}'): " $0 }'      >> ssh-result.txt
			port1=`cat $file | grep ^Port | grep -v ^# | awk '{print $2}'`
			echo " "                                                                                 > port1-search.txt
		else
			echo "SSH ��������($file): ��Ʈ ���� X (Default ����: 22��Ʈ ���)"                      >> ssh-result.txt
		fi
	fi
done
if [ `cat ssh-result.txt | grep -v "^ *$" | wc -l` -gt 0 ]
then
	cat ssh-result.txt | grep -v "^ *$"                                                          >> $CREATE_FILE 2>&1
else
	echo "SSH ��������: ���� ������ ã�� �� �����ϴ�."                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

# ���� ��Ʈ ����
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f port1-search.txt ]
then
	if [ `netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	then
		echo "�� SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
	fi
else
	if [ `netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	then
		echo "�� SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN"                              >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-59 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf port1-search.txt
rm -rf ssh-result.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-60 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.25 ftp ���� Ȯ�� ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.25 ftp ���� Ȯ��                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ftp ���񽺰� ��Ȱ��ȭ �Ǿ� ���� ��� ��ȣ"                                       >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service����: ��Ʈ ���� X (Default 21�� ��Ʈ)"                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services ���Ͽ��� ��Ʈ Ȯ�� #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"                               >> $CREATE_FILE 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
else
	echo "�� FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-60 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-61 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.26 ftp ���� shell ���� ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.26 ftp ���� shell ����              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ftp ���񽺰� ��Ȱ��ȭ �Ǿ� ���� ��� ��ȣ"                                       >> $CREATE_FILE 2>&1
echo "��       : ftp ���� ��� �� ftp ������ Shell�� �������� ���ϵ��� �����Ͽ��� ��� ��ȣ"  >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service����: ��Ʈ ���� X (Default 21�� ��Ʈ)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP ��Ʈ: ��Ʈ ���� X (Default 21�� ��Ʈ �����)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP ��Ʈ: VsFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP ��Ʈ: ��Ʈ ���� X (/etc/service ���Ͽ� ������ ��Ʈ�� �����)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP ��Ʈ: ProFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services ���Ͽ��� ��Ʈ Ȯ�� #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"                               >> $CREATE_FILE 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# vsftpd ���� ��Ʈ Ȯ�� ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi
################# proftpd ���� ��Ʈ Ȯ�� ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
else
	echo "�� FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ftp ���� �� Ȯ��(ftp ������ false �Ǵ� nologin ������ ��ȣ)"                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
then
	cat /etc/passwd | awk -F: '$1=="ftp"'                                                        >> $CREATE_FILE 2>&1
else
	echo "ftp ������ �������� ����.(��ȣ)"                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-61 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-62 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.27 Ftpusers ���� ������ �� ���� ���� #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.27 Ftpusers ���� ������ �� ���� ����       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ftpusers ������ �����ڰ� root�̰�, ������ 640 �̸��̸� ��ȣ"                     >> $CREATE_FILE 2>&1
echo "��       : [FTP ������ ����Ǵ� ����]"                                                    >> $CREATE_FILE 2>&1
echo "��       : (1)ftpd: /etc/ftpusers �Ǵ� /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "��       : (2)proftpd: /etc/ftpusers �Ǵ� /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "��       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (�Ǵ� /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service����: ��Ʈ ���� X (Default 21�� ��Ʈ)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP ��Ʈ: ��Ʈ ���� X (Default 21�� ��Ʈ �����)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP ��Ʈ: VsFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP ��Ʈ: ��Ʈ ���� X (/etc/service ���Ͽ� ������ ��Ʈ�� �����)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP ��Ʈ: ProFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services ���Ͽ��� ��Ʈ Ȯ�� #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"                               >> $CREATE_FILE 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# vsftpd ���� ��Ʈ Ȯ�� ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi
################# proftpd ���� ��Ʈ Ȯ�� ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
else
	echo "�� FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ftpusers ���� ������ �� ���� Ȯ��"                                                    >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       > ftpusers.txt
ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		ls -alL $file                                                                              >> ftpusers.txt
	fi
done
if [ `cat ftpusers.txt | wc -l` -gt 1 ]
then
	cat ftpusers.txt | grep -v "^ *$"                                                            >> $CREATE_FILE 2>&1
else
	echo "ftpusers ������ ã�� �� �����ϴ�. (FTP ���� ���� �� ���)"                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-62 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf ftpusers.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-63 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.28 Ftpusers ���� ���� ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              3.28 Ftpusers ���� ����              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ftp �� ������� �ʰų�, ftp ���� ftpusers ���Ͽ� root�� ���� ��� ��ȣ"        >> $CREATE_FILE 2>&1
echo "��       : [FTP ������ ����Ǵ� ����]"                                                    >> $CREATE_FILE 2>&1
echo "��       : (1)ftpd: /etc/ftpusers �Ǵ� /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "��       : (2)proftpd: /etc/ftpusers �Ǵ� /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "��       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (�Ǵ� /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service����:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service����: ��Ʈ ���� X (Default 21�� ��Ʈ)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP ��Ʈ: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP ��Ʈ: ��Ʈ ���� X (Default 21�� ��Ʈ �����)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP ��Ʈ: VsFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP ��Ʈ: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP ��Ʈ: ��Ʈ ���� X (/etc/service ���Ͽ� ������ ��Ʈ�� �����)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP ��Ʈ: ProFTP�� ��ġ�Ǿ� ���� �ʽ��ϴ�."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services ���Ͽ��� ��Ʈ Ȯ�� #################
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   > ftpenable.txt
	fi
else
	netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN"                               >> $CREATE_FILE 2>&1
	echo " "                                                                                     > ftpenable.txt
fi
################# vsftpd ���� ��Ʈ Ȯ�� ############################
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	then
		port=21
	else
		port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	fi
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi
################# proftpd ���� ��Ʈ Ȯ�� ###########################
if [ -s proftpd.txt ]
then
	port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	then
		netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> ftpenable.txt
	fi
fi

if [ -f ftpenable.txt ]
then
	rm -rf ftpenable.txt
else
	echo "�� FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ftpusers ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       > ftpusers.txt
ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		if [ `cat $file | grep "root" | grep -v "^#" | wc -l` -gt 0 ]
		then
			echo "�� $file ���ϳ���: `cat $file | grep "root" | grep -v "^#"` ������ ��ϵǾ� ����."  >> ftpusers.txt
			echo "check"                                                                             > check.txt
		else
			echo "�� $file ���ϳ���: root ������ ��ϵǾ� ���� ����."                                 >> ftpusers.txt
			echo "check"                                                                             > check.txt
		fi
	fi
done

if [ -f check.txt ]
then
	cat ftpusers.txt | grep -v "^ *$"                                                            >> $CREATE_FILE 2>&1
else
	echo "ftpusers ������ ã�� �� �����ϴ�. (FTP ���� ���� �� ���)"                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-63 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf ftpusers.txt
rm -rf check.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-64 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.29 at ���� ������ �� ���Ѽ��� ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.29 at ���� ������ �� ���Ѽ���          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: at.allow �Ǵ� at.deny ���� ������ 640 �̸��̸� ��ȣ"                             >> $CREATE_FILE 2>&1
echo "��       : (at.allow �Ǵ� at.deny ������ ���� ��� ��� ����ڰ� at ����� ����� �� �����Ƿ� ���)" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� at.allow ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/at.allow ]
then
	ls -alL /etc/at.allow                                                                        >> $CREATE_FILE 2>&1
else
	echo "/etc/at.allow ������ �����ϴ�."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� at.deny ���� ���� Ȯ��"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/at.deny ]
then
	ls -alL /etc/at.deny                                                                         >> $CREATE_FILE 2>&1
else
	echo "/etc/at.deny ������ �����ϴ�."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-64 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-65 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.30 SNMP ���� ���� ���� #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.30 SNMP ���� ���� ����             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: SNMP ���񽺸� ���ʿ��� �뵵�� ������� ���� ��� ��ȣ"                           >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
# SNMP���񽺴� ���۽� /etc/service ������ ��Ʈ�� ������� ����.
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]
then
	echo "�� SNMP Service Disable"                                                               >> $CREATE_FILE 2>&1
else
	echo "�� SNMP ���� Ȱ��ȭ ���� Ȯ��(UDP 161)"                                              >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	netstat -na | grep ":161 " | grep -i "^udp"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-65 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-66 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.31 snmp ���� Ŀ��Ƽ�Ͻ�Ʈ���� ���⼺ ���� ######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################   3.31 snmp ���� Ŀ��Ƽ�Ͻ�Ʈ���� ���⼺ ����   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: SNMP Community �̸��� public, private �� �ƴ� ��� ��ȣ"                         >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� SNMP ���� Ȱ��ȭ ���� Ȯ��(UDP 161)"                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]
then
	echo "�� SNMP Service Disable"                                                               >> $CREATE_FILE 2>&1
else
	netstat -na | grep ":161 " | grep -i "^udp"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� SNMP Community String ���� ��"                                                        >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/snmpd.conf ]
then
	echo "�� /etc/snmpd.conf ���� ����:"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /etc/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#"           >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi
if [ -f /etc/snmp/snmpd.conf ]
then
	echo "�� /etc/snmp/snmpd.conf ���� ����:"                                                     >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /etc/snmp/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#"      >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi
if [ -f /etc/snmp/conf/snmpd.conf ]
then
	echo "�� /etc/snmp/conf/snmpd.conf ���� ����:"                                                >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /etc/snmp/conf/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi
if [ -f /SI/CM/config/snmp/snmpd.conf ]
then
	echo "�� /SI/CM/config/snmp/snmpd.conf ���� ����:"                                            >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /SI/CM/config/snmp/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi

if [ -f snmpd.txt ]
then
	rm -rf snmpd.txt
else
	echo "snmpd.conf ������ �����ϴ�."                                                           >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
echo "U-66 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-67 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.32 �α׿� �� ��� �޽��� ���� ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.32 �α׿� �� ��� �޽��� ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: /etc/issue.net�� /etc/motd ���Ͽ� �α׿� ��� �޽����� �����Ǿ� ���� ��� ��ȣ"  >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/motd ���� ����: "                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/motd ]
then
	if [ `cat /etc/motd | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/motd | grep -v "^ *$"                                                             >> $CREATE_FILE 2>&1
	else
		echo "��� �޽��� ���� ������ �����ϴ�.(���)"                                             >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/motd ������ �����ϴ�."                                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/issue.net ���� ����: "                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                      >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                          >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                           >> $CREATE_FILE 2>&1
	else
		echo "�� Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/issue.net ���� ����:"                                                             >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ -f /etc/issue.net ]
then
	if [ `cat /etc/issue.net | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/issue.net | grep -v "^#" | grep -v "^ *$"                                         >> $CREATE_FILE 2>&1
	else
		echo "��� �޽��� ���� ������ �����ϴ�.(���)"                                             >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/issue.net ������ �����ϴ�."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-67 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-68 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.33 NFS ���� ���� ���� ���� #######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.33 NFS ���� ���� ���� ����            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: NFS ���� ������ �������� �ʰų�, /etc/exports ������ ������ 644 �����̸� ��ȣ"   >> $CREATE_FILE 2>&1
echo "��       : (/etc/exports ���� ������ NFS���� �̿��� �Ұ��������� ��ȣ)"                 >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� NFS Server Daemon(nfsd)Ȯ��"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
 else
   echo "�� NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/exports ���� ���� ����"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
  then
   ls -alL /etc/exports                                                                        >> $CREATE_FILE 2>&1
  else
   echo "/etc/exports ������ �����ϴ�.(��ȣ)"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-68 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-69 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.34 expn, vrfy ��ɾ� ���� ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.34 expn, vrfy ��ɾ� ����            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: SMTP ���񽺸� ������� �ʰų� noexpn, novrfy �ɼ��� �����Ǿ� ���� ��� ��ȣ"     >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/services ���Ͽ��� ��Ʈ Ȯ��"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��Ʈ Ȱ��ȭ ���� Ȯ��"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
		echo " "                                                                                   > sendmail.txt
	fi
fi

if [ -f sendmail.txt ]
then
	rm -rf sendmail.txt
else
	echo "�� Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� /etc/mail/sendmail.cf ������ �ɼ� Ȯ��"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                                 >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf ������ �����ϴ�."                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-69 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-70 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.35 Apache ������ ���� ���� #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.35 Apache ������ ���� ����           ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ServerTokens �����ڷ� ����� ���۵Ǵ� ������ ������ �� ����.(ServerTokens Prod ������ ��� ��ȣ)" >> $CREATE_FILE 2>&1
echo "��       : ServerTokens Prod ������ ���� ��� Default ����(ServerTokens Full)�� �����."  >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "�� $ACONF ���� ���� Ȯ��"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	if [ `cat $ACONF | grep -i "ServerTokens" | grep -v '\#' | wc -l` -gt 0 ]
	then
		cat $ACONF | grep -i "ServerTokens" | grep -v '\#'                                         >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "ServerTokens �����ڰ� �����Ǿ� ���� �ʽ��ϴ�.(���)"                                 >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi
else
	echo "�� Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-70 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#############################      4. ��ġ ����      ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-71 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 4.1 �ֽ� ������ġ �� ���� �ǰ���� ���� ############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     4.1 �ֽ� ������ġ �� ���� �ǰ���� ����      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: ��ġ ���� ��å�� �����Ͽ� �ֱ������� ��ġ�� �����ϰ� ���� ��� ��ȣ"             >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ���� ��ϵ� ����"                                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
rpm -qa |sort                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-71 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#############################      5. �α� ����      ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-72 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 5.1 �α��� ������ ���� �� ���� #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          5.1 �α��� ������ ���� �� ����          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: �αױ�Ͽ� ���� ������ ����, �м�, ����Ʈ �ۼ� �� ���� �̷������ �ִ� ��� ��ȣ" >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� ����� ���ͺ� �� ����Ȯ��"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "�� ���� �ֱ�� �α׸� �����ϰ� �ִ°�?"                                                  >> $CREATE_FILE 2>&1
echo "�� �α� ���˰���� ���� ��������� �����ϴ°�?"                                        >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-72 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-73 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 5.2 ��å�� ���� �ý��� �α� ���� ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         5.2 ��å�� ���� �ý��� �α� ����         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "�� ����: syslog �� �߿� �α� ������ ���� ������ �Ǿ� ���� ��� ��ȣ"                      >> $CREATE_FILE 2>&1
echo "�� ��Ȳ"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� SYSLOG ���� ���� Ȯ��"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep 'syslog' | grep -v 'grep' | wc -l` -eq 0 ]
then
	echo "�� SYSLOG Service Disable"                                                             >> $CREATE_FILE 2>&1
else
	ps -ef | grep 'syslog' | grep -v 'grep'                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� SYSLOG ���� Ȯ��"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	if [ `cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $CREATE_FILE 2>&1
	else
		echo "/etc/syslog.conf ���Ͽ� ���� ������ �����ϴ�.(�ּ�, ��ĭ ����)"                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/syslog.conf ������ �����ϴ�."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "�� RSYSLOG ���� Ȯ��"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $CREATE_FILE 2>&1
	else
		echo "/etc/rsyslog.conf ���Ͽ� ���� ������ �����ϴ�.(�ּ�, ��ĭ ����)"                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/rsyslog.conf ������ �����ϴ�."                                                     >> $CREATE_FILE 2>&1
fi
echo " " 
echo "U-73 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


rm -rf proftpd.txt
rm -rf vsftpd.txt



echo "***************************************** END *****************************************" >> $CREATE_FILE 2>&1
date                                                                                           >> $CREATE_FILE 2>&1
echo "***************************************** END *****************************************"

echo "�� �����۾��� �Ϸ�Ǿ����ϴ�. �����ϼ̽��ϴ�!"
echo "�� �����۾��� �Ϸ�Ǿ����ϴ�. �����ϼ̽��ϴ�!"   
