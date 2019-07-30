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
echo "###########################        1. 계정 관리        ################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-01 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.1 root 계정 원격 접속 제한 #######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           1.1 root 계정 원격 접속 제한            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준1: /etc/securetty 파일에 pts/* 설정이 있으면 무조건 취약"                          >> $CREATE_FILE 2>&1 
echo "■ 기준2: /etc/securetty 파일에 pts/* 설정이 없거나 주석처리가 되어 있고,"                >> $CREATE_FILE 2>&1 
echo "■        : /etc/pam.d/login에서 auth required /lib/security/pam_securetty.so 라인에 주석(#)이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 기준3: /etc/ssh/sshd_config 파일에 permitrootlogin 주석처리가 되어 있거나, yes로 되어있으면 취약"                >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
	else
		echo "☞ Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/securetty 파일 설정"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/securetty | grep "pts" | wc -l` -gt 0 ]
then
	cat /etc/securetty | grep "pts"                                                              >> $CREATE_FILE 2>&1
else
	echo "/etc/securetty 파일에 pts/0~pts/x 설정이 없습니다."                                    >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "④ /etc/pam.d/login 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/pam.d/login | grep "pam_securetty.so"                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "⑤ /etc/ssh/sshd_config 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config | grep -i "permitrootlogin"                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-01 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-02 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.2 패스워드 복잡성 설정 ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.2 패스워드 복잡성 설정              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 영문 숫자 특수문자가 혼합된 8자리 이상의 패스워드가 설정된 경우 양호"                                        >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  echo "① /etc/passwd 파일"                                                                   >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/passwd                                                                              >> $CREATE_FILE 2>&1
else
  echo "/etc/passwd 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
  echo "② /etc/shadow 파일"                                                                   >> $CREATE_FILE 2>&1
  echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
  cat /etc/shadow                                                                              >> $CREATE_FILE 2>&1
else
  echo "/etc/shadow 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-02 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-03 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.3 계정 잠금 임계값 설정 ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            1.3 계정 잠금 임계값 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/pam.d/system-auth 파일에 아래와 같은 설정이 있으면 양호"                    >> $CREATE_FILE 2>&1
echo "■       : (auth required /lib/security/pam_tally.so deny=5 unlock_time=120 no_magic_root)" >> $CREATE_FILE 2>&1
echo "■       : (account required /lib/security/pam_tally.so no_magic_root reset)"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ /etc/pam.d/system-auth 파일 설정(auth, account)"                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/pam.d/system-auth | grep -E "auth|account"                                            >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-03 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-04 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.4 패스워드 파일 보호 #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.4 패스워드 파일 보호               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드가 /etc/shadow 파일에 암호화 되어 저장되고 있으면 양호"                  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
	if [ `awk -F: '$2=="x"' /etc/passwd | wc -l` -eq 0 ]
	then
		echo "☞ /etc/passwd 파일에 패스워드가 암호화 되어 있지 않습니다. (취약)"                  >> $CREATE_FILE 2>&1
	else
		echo "☞ /etc/passwd 파일에 패스워드가 암호화 되어 있습니다. (양호)"                       >> $CREATE_FILE 2>&1
	fi
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "[참고]"                                                                                >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat /etc/passwd | head -5                                                                    >> $CREATE_FILE 2>&1
	echo "이하생략..."                                                                           >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/passwd 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-04 END"                                                                                >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "■ /etc/passwd 파일"                                                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  cat /etc/passwd                                                                              >> $CREATE_FILE 2>&1
else
	echo "/etc/shadow 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "■ /etc/shadow 파일"                                                                      >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
  cat /etc/shadow                                                                              >> $CREATE_FILE 2>&1
else
  echo "/etc/shadow 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-05 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.5 root 이외의 UID가 '0' 금지 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          1.5 root 이외의 UID가 '0' 금지           ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: root 계정만이 UID가 0이면 양호"                                                  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                     >> $CREATE_FILE 2>&1
  else
    echo "☞ /etc/passwd 파일이 존재하지 않습니다."                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-05 END"                                                                                >> $CREATE_FILE 2>&1
echo "☞ /etc/passwd 파일 내용"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/passwd                                                                                >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1




echo "U-06 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.6 root 계정 su 제한 ##############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               1.6 root 계정 su 제한               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준1: /etc/pam.d/su 파일 설정이 아래와 같을 경우 양호"                                >> $CREATE_FILE 2>&1
echo "■ 기준2: 아래 설정이 없거나, 주석 처리가 되어 있을 경우 su 명령 파일의 권한이 4750 이면 양호" >> $CREATE_FILE 2>&1
echo "■        : (auth  required  /lib/security/pam_wheel.so debug group=wheel) 또는"          >> $CREATE_FILE 2>&1
echo "■        : (auth  required  /lib/security/\$ISA/pam_wheel.so use_uid)"                   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/pam.d/su 파일 설정"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | wc -l` -eq 0 ]
	then
		echo "pam_wheel.so 설정 내용이 없습니다."                                                  >> $CREATE_FILE 2>&1
	else
		cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust'                                  >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/pam.d/su 파일을 찾을 수 없습니다."                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② su 파일권한"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `which su | grep -v 'no ' | wc -l` -eq 0 ]
then
	echo "su 명령 파일을 찾을 수 없습니다."                                                      >> $CREATE_FILE 2>&1
else
	sucommand=`which su`;
	ls -alL $sucommand                                                                           >> $CREATE_FILE 2>&1
	sugroup=`ls -alL $sucommand | awk '{print $4}'`;
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ su 명령그룹"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/pam.d/su ]
then
	if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}' | wc -l` -gt 0 ]
	then
		pamsugroup=`cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' | grep 'group' | awk -F"group=" '{print $2}' | awk -F" " '{print $1}'`
		echo "- su명령 그룹(PAM모듈): `grep -E "^$pamsugroup" /etc/group`"                         >> $CREATE_FILE 2>&1
	else
		if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | egrep -v 'trust|#' | wc -l` -gt 0 ]
		then
			echo "- su명령 그룹(PAM모듈): `grep -E "^wheel" /etc/group`"                             >> $CREATE_FILE 2>&1
		fi
	fi
fi
echo "- su명령 그룹(명령파일): `grep -E "^$sugroup" /etc/group`"                               >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-06 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-07 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.7 패스워드 최소 길이 설정 ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           1.7 패스워드 최소 길이 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소 길이가 8자 이상으로 설정되어 있으면 양호"                          >> $CREATE_FILE 2>&1 
echo "■       : (PASS_MIN_LEN 8 이상이면 양호)"                                                >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
then
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_LEN"                                      >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-07 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-08 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.8 패스워드 최대 사용 기간 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         1.8 패스워드 최대 사용 기간 설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최대 사용기간이 90일 이하로 설정되어 있으면 양호"                       >> $CREATE_FILE 2>&1 
echo "■       : (PASS_MAX_DAYS 90 이하이면 양호)"                                              >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
then
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MAX_DAYS"                                     >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-08 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1




echo "U-09 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.9 패스워드 최소 사용 기간 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         1.9 패스워드 최소 사용 기간 설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패스워드 최소 사용기간이 1일로 설정되어 있으면 양호"                             >> $CREATE_FILE 2>&1
echo "■       : (PASS_MIN_DAYS 1 이상이면 양호)"                                               >> $CREATE_FILE 2>&1 
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/login.defs ]
then
	grep -v '^ *#' /etc/login.defs | grep -i "PASS_MIN_DAYS"                                     >> $CREATE_FILE 2>&1
else
	echo "/etc/login.defs 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-09 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-10 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.10 불필요한 계정 제거 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              1.10 불필요한 계정 제거               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/passwd 파일에 lp, uucp, nuucp 계정이 모두 제거되어 있으면 양호"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | egrep "^lp|^uucp|^nuucp" | wc -l` -eq 0 ]
then
  echo "☞ lp, uucp, nuucp 계정이 존재하지 않습니다."                                          >> $CREATE_FILE 2>&1
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
echo "################## 1.11 관리자 그룹에 최소한의 계정 포함 ##############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################       1.11 관리자 그룹에 최소한의 계정 포함        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 관리자 계정이 포함된 그룹에 불필요한 계정이 존재하지 않는 경우 양호"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① 관리자 계정"                                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
  awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd                                       >> $CREATE_FILE 2>&1
else
  echo "/etc/passwd 파일이 없습니다."                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 관리자 계정이 포함된 그룹 확인"                                                       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
for group in `awk -F: '$3==0 { print $1}' /etc/passwd`
do
	cat /etc/group | grep "$group"                                                               >> $CREATE_FILE 2>&1
done
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-11 END"                                                                                >> $CREATE_FILE 2>&1
echo "[참고] /etc/group 파일"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/group                                                                                 >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-12 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.12 계정이 존재하지 않는 GID 금지 #################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        1.12 계정이 존재하지 않는 GID 금지         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 구성원이 존재하지 않는 빈 그룹이 발견되지 않을 경우 양호"                        >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 구성원이 존재하지 않는 그룹"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `awk -F: '$4==null' /etc/group | wc -l` -eq 0 ]
then
	echo "구성원이 존재하지 않는 그룹이 발견되지 않았습니다. (양호)"                             >> $CREATE_FILE 2>&1
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
echo "################## 1.13 동일한 UID 금지 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               1.13 동일한 UID 금지                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 동일한 UID로 설정된 계정이 존재하지 않을 경우 양호"                              >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 동일한 UID를 사용하는 계정 "                                                          >> $CREATE_FILE 2>&1
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
	echo "동일한 UID를 사용하는 계정이 발견되지 않았습니다."                                     >> $CREATE_FILE 2>&1
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
echo "################## 1.14 사용자 Shell 점검 #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              1.14 사용자 Shell 점검               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 로그인이 필요하지 않은 시스템 계정에 /bin/false(nologin) 쉘이 부여되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 로그인이 필요하지 않은 시스템 계정 확인"                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
  else
    echo "/etc/passwd 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-14 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-15 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 1.15 Session Timeout 설정 ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             1.15 Session Timeout 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/profile 에서 TMOUT=300 또는 /etc/csh.login 에서 autologout=5 로 설정되어 있으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"                 >> $CREATE_FILE 2>&1
echo "■       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 현재 로그인 계정 TMOUT"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
if [ `set | egrep -i "TMOUT|autologout" | wc -l` -gt 0 ]
then
	set | egrep -i "TMOUT|autologout"                                                            >> $CREATE_FILE 2>&1
else
	echo "TMOUT 이 설정되어 있지 않습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ TMOUT 설정 확인"                                                                      >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
  echo "① /etc/profile 파일"                                                                  >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/profile | grep -i TMOUT | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/profile | grep -i TMOUT | grep -v "^#"                                            >> $CREATE_FILE 2>&1
  else
  	echo "TMOUT 이 설정되어 있지 않습니다."                                                    >> $CREATE_FILE 2>&1
  fi
else
  echo "/etc/profile 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
then
  echo "② /etc/csh.login 파일"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.login | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
   	cat /etc/csh.login | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
  else
   	echo "autologout 이 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
  fi
else
  echo "/etc/csh.login 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.cshrc ]
then
  echo "③ /etc/csh.cshrc 파일"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.cshrc | grep -i autologout | grep -v "^#" | wc -l` -gt 0 ]
  then
  	cat /etc/csh.cshrc | grep -i autologout | grep -v "^#"                                     >> $CREATE_FILE 2>&1
  else
  	echo "autologout 이 설정되어 있지 않습니다."                                               >> $CREATE_FILE 2>&1
  fi
else
  echo "/etc/csh.cshrc 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
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
echo "#########################    2. 파일 및 디렉토리 관리    ##############################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-16 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.1 root 홈, 패스 디렉터리 권한 및 패스 설정 #######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################   2.1 root 홈, 패스 디렉터리 권한 및 패스 설정   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Path 설정에 “.” 이 맨 앞이나 중간에 포함되어 있지 않을 경우 양호"                >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ PATH 설정 확인"                                                                       >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo $PATH                                                                                     >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-16 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-17 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.2 파일 및 디렉터리 소유자 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        2.2 파일 및 디렉터리 소유자 설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 소유자가 존재하지 않은 파일 및 디렉토리가 존재하지 않을 경우 양호"               >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 소유자가 존재하지 않는 파일 (소유자 => 파일위치: 경로)"                               >> $CREATE_FILE 2>&1
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
  echo "소유자가 존재하지 않는 파일이 발견되지 않았습니다.(양호)"                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-17 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.17.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-18 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.3 /etc/passwd 파일 소유자 및 권한 설정 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.3 /etc/passwd 파일 소유자 및 권한 설정     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/passwd 파일의 소유자가 root 이고, 권한이 644 이면 양호"                     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/passwd ]
then
	ls -alL /etc/passwd                                                                          >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/passwd 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-18 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-19 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.4 /etc/shadow 파일 소유자 및 권한 설정 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.4 /etc/shadow 파일 소유자 및 권한 설정     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/shadow 파일의 소유자가 root 이고, 권한이 400 이면 양호"                     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/shadow ]
then
	ls -alL /etc/shadow                                                                          >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/shadow 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-19 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-20 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.5 /etc/hosts 파일 소유자 및 권한 설정 ############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     2.5 /etc/hosts 파일 소유자 및 권한 설정      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/hosts 파일의 소유자가 root 이고, 권한이 600 이면 양호"                      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/hosts ]
then
	ls -alL /etc/hosts                                                                           >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/hosts 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-20 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-21 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.6 /etc/(x)inetd.conf 파일 소유자 및 권한 설정 ####################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.6 /etc/(x)inetd.conf 파일 소유자 및 권한 설정  #################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/(x)inetd.conf 파일 및 /etc/xinetd.d/ 하위 모든 파일의 소유자가 root 이고, 권한이 600 이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/xinetd.conf 파일"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/xinetd.conf ]
then
	ls -alL /etc/xinetd.conf                                                                     >> $CREATE_FILE 2>&1
else
	echo "/etc/xinetd.conf 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/xinetd.d/ 파일"                                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
then
	ls -al /etc/xinetd.d/*                                                                       >> $CREATE_FILE 2>&1
else
	echo "/etc/xinetd.d 디렉터리가 없습니다."                                                    >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/inetd.conf 파일"                                                                 >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
then
	ls -alL /etc/inetd.conf                                                                      >> $CREATE_FILE 2>&1
else
	echo "/etc/inetd.conf 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-21 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-22 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.7 /etc/syslog.conf 파일 소유자 및 권한 설정 ######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.7 /etc/syslog.conf 파일 소유자 및 권한 설정   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/syslog.conf 파일의 권한이 644 이면 양호"                                    >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	ls -alL /etc/syslog.conf                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/syslog.conf 파일이 없습니다."                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	ls -alL /etc/rsyslog.conf                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/rsyslog.conf 파일이 없습니다."                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-22 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-23 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.8 /etc/services 파일 소유자 및 권한 설정 #########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.8 /etc/services 파일 소유자 및 권한 설정    ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/services 파일의 권한이 644 이면 양호"                                       >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/services ]
then
	ls -alL /etc/services                                                                        >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/services 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-23 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-24 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.9 SUID,SGID,Stick bit 설정 파일 점검 #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      2.9 SUID,SGID,Stick bit 설정 파일 점검      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 SUID/SGID 설정이 존재하지 않을 경우 양호"                               >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

find /usr -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;        > 1.25.txt 2> /dev/null
find /bin -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \;        >> 1.25.txt 2> /dev/null

if [ -s 1.25.txt ]
then
	cat 1.25.txt | egrep "sbin/dump|usr/bin/lpq-lpd|usr/bin/newgrp|sbin/resotre|usr/binlpr|usr/sbin/lpc|sbin/unix_chkpwd|usr/bin/lpr-lpd|usr/sbin/lpc-lpd|usr/bin/at|usr/bin/lprm|usr/bin/traceroute|usr/bin/lpq|usr/bin/lprm-lpd"       >> $CREATE_FILE 2>&1
else
	echo "☞ SUID/SGID로 설정된 파일이 발견되지 않았습니다.(양호)"                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-24 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.25.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-25 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 #######"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "############ 2.10 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 #############" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈디렉터리 환경변수 파일에 타사용자 쓰기 권한이 제거되어 있으면 양호"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 홈디렉터리 환경변수 파일"                                                             >> $CREATE_FILE 2>&1
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
echo "################## 2.11 world writable 파일 점검 ######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          2.11 world writable 파일 점검            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 권한이 부여된 world writable 파일이 존재하지 않을 경우 양호"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
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
  echo "☞ World Writable 권한이 부여된 파일이 발견되지 않았습니다."                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-26 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf world-writable.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-27 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.12 /dev에 존재하지 않는 device 파일 점검 #########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.12 /dev에 존재하지 않는 device 파일 점검     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준 : dev 에 존재하지 않은 Device 파일을 점검하고, 존재하지 않은 Device을 제거 했을 경우 양호" >> $CREATE_FILE 2>&1
echo "■        : (아래 나열된 결과는 major, minor Number를 갖지 않는 파일임)"                  >> $CREATE_FILE 2>&1
echo "■        : (.devlink_db_lock/.devfsadm_daemon.lock/.devfsadm_synch_door/.devlink_db는 Default로 존재 예외)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /dev -type f -exec ls -l {} \;                                                            > 1.32.txt

if [ -s 1.32.txt ]
then
	cat 1.32.txt                                                                                 >> $CREATE_FILE 2>&1
else
	echo "☞ dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다."                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-27 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.32.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-28 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.13 HOME/.rhosts, hosts.equiv 사용 금지 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      2.13 HOME/.rhosts, hosts.equiv 사용 금지     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $CREATE_FILE 2>&1
echo "■       : r-commands 서비스를 사용하는 경우 HOME/.rhosts, hosts.equiv 설정확인"          >> $CREATE_FILE 2>&1
echo "■       : (1) .rhosts 파일의 소유자가 해당 계정의 소유자이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (2) /etc/hosts.equiv 파일의 소유자가 root 이고, 퍼미션 600, 내용에 + 가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "☞ r-command Service Disable"                                                          >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/hosts.equiv 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.equiv ]
	then
		echo "(1) Permission: (`ls -al /etc/hosts.equiv`)"                                         >> $CREATE_FILE 2>&1
		echo "(2) 설정 내용:"                                                                      >> $CREATE_FILE 2>&1
		echo "----------------------------------------"                                            >> $CREATE_FILE 2>&1
		if [ `cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$' | wc -l` -gt 0 ]
		then
			cat /etc/hosts.equiv | grep -v "#" | grep -v '^ *$'                                      >> $CREATE_FILE 2>&1
		else
			echo "설정 내용이 없습니다."                                                             >> $CREATE_FILE 2>&1
		fi
	else
		echo "/etc/hosts.equiv 파일이 없습니다."                                                   >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "④ 사용자 home directory .rhosts 설정 내용"                                              >> $CREATE_FILE 2>&1
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
			echo "# $dir$file 파일 설정:"                                                            >> $CREATE_FILE 2>&1
			echo "(1) Permission: (`ls -al $dir$file`)"                                              >> $CREATE_FILE 2>&1
			echo "(2) 설정 내용:"                                                                    >> $CREATE_FILE 2>&1
			echo "----------------------------------------"                                          >> $CREATE_FILE 2>&1
			if [ `cat $dir$file | grep -v "#" | grep -v '^ *$' | wc -l` -gt 0 ]
			then
				cat $dir$file | grep -v "#" | grep -v '^ *$'                                           >> $CREATE_FILE 2>&1
			else
				echo "설정 내용이 없습니다."                                                           >> $CREATE_FILE 2>&1
			fi
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		fi
	done
done
if [ ! -f rhosts.txt ]
then
	echo ".rhosts 파일이 없습니다."                                                              >> $CREATE_FILE 2>&1
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
echo "################## 2.14 접속 IP 및 포트 제한 ##########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             2.14 접속 IP 및 포트 제한             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/hosts.deny 파일에 All Deny(ALL:ALL) 설정이 등록되어 있고,"                  >> $CREATE_FILE 2>&1
echo "■       : /etc/hosts.allow 파일에 접근 허용 IP가 등록되어 있으면 양호"                   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/hosts.allow 파일 설정"                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.allow ]
then
	if [ ! `cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.allow | grep -v "#" | grep -ve '^ *$'                                       >> $CREATE_FILE 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/hosts.allow 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/hosts.deny 파일 설정"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/hosts.deny ]
then
	if [ ! `cat /etc/hosts.deny | grep -v "#" | grep -ve '^ *$' | wc -l` -eq 0 ]
	then
		cat /etc/hosts.deny | grep -v "#" | grep -ve '^ *$'                                        >> $CREATE_FILE 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/hosts.deny 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo "U-29 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-30 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.15 host.lpd 파일 소유자 및 권한 설정 #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.15 host.lpd 파일 소유자 및 권한 설정    ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/host.lpd 파일의 소유자가 root 이고, 권한이 600 이면 양호"                   >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/host.lpd ]
then
	ls -alL /etc/host.lpd                                                                        >> $CREATE_FILE 2>&1
else
	echo "☞ /etc/host.lpd 파일이 없습니다.(양호)"                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-30 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-31 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.16 NIS 서비스 비활성화 ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              2.16 NIS 서비스 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: NIS, NIS+ 서비스가 구동 중이지 않을 경우에 양호"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "☞ NIS, NIS+ Service Disable"                                                          >> $CREATE_FILE 2>&1
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
echo "################## 2.17 UMASK 설정 관리 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################                2.17 UMASK 설정 관리               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: UMASK 값이 022 이면 양호"                                                        >> $CREATE_FILE 2>&1
echo "■       : (1) sh, ksh, bash 쉘의 경우 /etc/profile 파일 설정을 적용받음"                 >> $CREATE_FILE 2>&1
echo "■       : (2) csh, tcsh 쉘의 경우 /etc/csh.cshrc 또는 /etc/csh.login 파일 설정을 적용받음" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 현재 로그인 계정 UMASK"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------"                                        >> $CREATE_FILE 2>&1
umask                                                                                          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/profile ]
then
	echo "① /etc/profile 파일(올바른 설정: umask 022)"                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
	if [ `cat /etc/profile | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
		cat /etc/profile | grep -i umask | grep -v ^#                                              >> $CREATE_FILE 2>&1
	else
		echo "umask 설정이 없습니다."                                                              >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/profile 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
then
  echo "② /etc/csh.login 파일"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.login | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
  	cat /etc/csh.login | grep -i umask | grep -v ^#                                            >> $CREATE_FILE 2>&1
  else
		echo "umask 설정이 없습니다."                                                              >> $CREATE_FILE 2>&1
	fi
else
  echo "/etc/csh.login 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ -f /etc/csh.login ]
then
  echo "③ /etc/csh.cshrc 파일"                                                                >> $CREATE_FILE 2>&1
  echo "------------------------------------------------"                                      >> $CREATE_FILE 2>&1
  if [ `cat /etc/csh.cshrc | grep -i umask | grep -v ^# | wc -l` -gt 0 ]
	then
  	cat /etc/csh.cshrc | grep -i umask | grep -v ^#                                            >> $CREATE_FILE 2>&1
  else
		echo "umask 설정이 없습니다."                                                              >> $CREATE_FILE 2>&1
	fi
else
  echo "/etc/csh.cshrc 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-32 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-33 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.18 홈 디렉토리 소유자 및 권한 설정 ###############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        2.18 홈 디렉토리 소유자 및 권한 설정       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈 디렉터리의 소유자가 /etc/passwd 내에 등록된 홈 디렉터리 사용자와 일치하고,"   >> $CREATE_FILE 2>&1
echo "■       : 홈 디렉터리에 타사용자 쓰기권한이 없으면 양호"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 사용자 홈 디렉터리"                                                                   >> $CREATE_FILE 2>&1
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
echo "################## 2.19 홈 디렉토리로 지정한 디렉토리의 존재 관리 #####################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################  2.19 홈 디렉토리로 지정한 디렉토리의 존재 관리   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않으면 양호"                         >> $CREATE_FILE 2>&1
# 홈 디렉토리가 존재하지 않는 경우, 일반 사용자가 로그인을 하면 사용자의 현재 디렉터리가 /로 로그인 되므로 관리,보안상 문제가 발생됨.
# 예) 해당 계정으로 ftp 로그인 시 / 디렉터리로 접속하여 중요 정보가 노출될 수 있음.
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 홈 디렉터리가 존재하지 않은 계정"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`
for dir in $HOMEDIRS
do
	if [ ! -d $dir ]
	then
		awk -F: '$6=="'${dir}'" { print "● 계정명(홈디렉터리):"$1 "(" $6 ")" }' /etc/passwd        >> $CREATE_FILE 2>&1
		echo " "                                                                                   > 1.29.txt
	fi
done

if [ ! -f 1.29.txt ]
then
	echo "홈 디렉터리가 존재하지 않은 계정이 발견되지 않았습니다. (양호)"                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-34 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf 1.29.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-35 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 2.20 숨겨진 파일 및 디렉토리 검색 및 제거 ##########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################    2.20 숨겨진 파일 및 디렉토리 검색 및 제거      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 디렉토리 내에 숨겨진 파일을 확인 및 검색 하여 , 불필요한 파일 존재 경우 삭제 했을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
find /tmp -name ".*" -ls                                                                       >> $CREATE_FILE 2>&1
find /home -name ".*" -ls                                                                      >> $CREATE_FILE 2>&1
find /usr -name ".*" -ls                                                                       >> $CREATE_FILE 2>&1
find /var -name ".*" -ls                                                                       >> $CREATE_FILE 2>&1
echo "위에 리스트에서 숨겨진 파일 확인"                                                               >> $CREATE_FILE 2>&1
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
echo "#############################     3. 서비스 관리     ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-36 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.1 finger 서비스 비활성화 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.1 finger 서비스 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Finger 서비스가 비활성화 되어 있을 경우 양호"                                    >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="finger" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -eq 0 ]
	then
		echo "☞ Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":$port " | grep -i "^tcp"                                              >> $CREATE_FILE 2>&1
	fi
else
	if [ `netstat -na | grep ":79 " | grep -i "^tcp" | wc -l` -eq 0 ]
	then
		echo "☞ Finger Service Disable"                                                           >> $CREATE_FILE 2>&1
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
echo "################## 3.2 Anonymous FTP 비활성화 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.2 Anonymous FTP 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Anonymous FTP (익명 ftp)를 비활성화 시켰을 경우 양호"                            >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd를 사용할 경우: /etc/passwd 파일내 FTP 또는 anonymous 계정이 존재하지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd를 사용할 경우: /etc/passwd 파일내 FTP 계정이 존재하지 않으면 양호"  >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd를 사용할 경우: vsftpd.conf 파일에서 anonymous_enable=NO 설정이면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services 파일에서 포트 확인 #################
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
################# vsftpd 에서 포트 확인 ############################
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
################# proftpd 에서 포트 확인 ###########################
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
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ Anonymous FTP 설정 확인"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -s vsftpd.txt ]
then
	cat $vsfile | grep -i "anonymous_enable" | awk '{print "● VsFTP 설정: " $0}'                 >> $CREATE_FILE 2>&1
fi

if [ `cat /etc/passwd | egrep "^ftp:|^anonymous:" | wc -l` -gt 0 ]
then
	echo "● ProFTP, 기본FTP 설정:"                                                               >> $CREATE_FILE 2>&1
	cat /etc/passwd | egrep "^ftp:|^anonymous:"                                                  >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "● ProFTP, 기본FTP 설정: /etc/passwd 파일에 ftp 또는 anonymous 계정이 없습니다."        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-37 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-38 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.3 r 계열 서비스 비활성화 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.3 r 계열 서비스 비활성화             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: r-commands 서비스를 사용하지 않으면 양호"                                        >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="login" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="shell" {print $1 "   " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="exec" {print $1 "    " $2}' | grep "tcp"                   >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인(서비스 중지시 결과 값 없음)"                             >> $CREATE_FILE 2>&1
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
	echo "☞ r-commands Service Disable"                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-38 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-39 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.4 cron 파일 소유자 및 권한설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.4 cron 파일 소유자 및 권한설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: cron.allow 또는 cron.deny 파일 권한이 640 미만이면 양호"                         >> $CREATE_FILE 2>&1
echo "■       : (cron.allow 또는 cron.deny 파일이 없는 경우 모든 사용자가 cron 명령을 사용할 수 있으므로 취약)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① cron.allow 파일 권한 확인"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/cron.allow ]
then
	ls -alL /etc/cron.allow                                                                      >> $CREATE_FILE 2>&1
else
	echo "/etc/cron.allow 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② cron.deny 파일 권한 확인"                                                             >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/cron.deny ]
then
	ls -alL /etc/cron.deny                                                                       >> $CREATE_FILE 2>&1
else
	echo "/etc/cron.deny 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-39 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-40 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.5 Dos 공격에 취약한 서비스 비활성화 ##############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.5 Dos 공격에 취약한 서비스 비활성화       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DoS 공격에 취약한 echo , discard , daytime , chargen 서비스를 사용하지 않았을 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
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
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "불필요한 서비스가 동작하고 있지 않습니다.(echo, discard, daytime, chargen)"            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-40 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-41 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.6 NFS 서비스 비활성화 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.6 NFS 서비스 비활성화               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 NFS 서비스 관련 데몬이 제거되어 있는 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② NFS Client Daemon(statd,lockd)확인"                                                   >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd" | wc -l` -gt 0 ] 
  then
    ps -ef | egrep "statd|lockd" | egrep -v "grep|emi|statdaemon|dsvclockd"                    >> $CREATE_FILE 2>&1
  else
    echo "☞ NFS Client(statd,lockd) Disable"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-41 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-42 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.7 NFS 접근 통제 ##################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################                3.7 NFS 접근 통제                 ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준1: NFS 서버 데몬이 동작하지 않으면 양호"                                           >> $CREATE_FILE 2>&1
echo "■ 기준2: NFS 서버 데몬이 동작하는 경우 /etc/exports 파일에 everyone 공유 설정이 없으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
# (취약 예문) /tmp/test/share *(rw)
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/exports 파일 설정"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
then
	if [ `cat /etc/exports | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/exports | grep -v "^#" | grep -v "^ *$"                                           >> $CREATE_FILE 2>&1
	else
		echo "설정 내용이 없습니다."                                                               >> $CREATE_FILE 2>&1
	fi
else
  echo "/etc/exports 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-42 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-43 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.8 automountd 제거 ################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.8 automountd 제거                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: automountd 서비스가 동작하지 않을 경우 양호"                                     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① Automountd Daemon 확인"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi" | wc -l` -gt 0 ] 
 then
   ps -ef | egrep 'automount|autofs' | grep -v "grep" | egrep -v "statdaemon|emi"              >> $CREATE_FILE 2>&1
 else
   echo "☞ Automountd Daemon Disable"                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-43 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-44 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.9 RPC 서비스 확인 ################################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.9 RPC 서비스 확인                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 불필요한 rpc 관련 서비스가 존재하지 않으면 양호"                                 >> $CREATE_FILE 2>&1
echo "(rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

echo "☞ 불필요한 RPC 서비스 동작 확인"                                                        >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -d /etc/xinetd.d ]
then
	if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]
	then
		echo "불필요한 RPC 서비스가 존재하지 않습니다."                                            >> $CREATE_FILE 2>&1
	else
		ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD                                             >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다."                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-44 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-45 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.10 NIS , NIS+ 점검 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.10 NIS , NIS+ 점검                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: NIS, NIS+ 서비스가 구동 중이지 않을 경우에 양호"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "해당 항목은 U-26 항목에 포함된 항목을 해당 사항 없음. (N/A)"                             >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-45 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-46 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.11 tftp, talk 서비스 비활성화 ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.11 tftp, talk 서비스 비활성화          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: tftp, talk, ntalk 서비스가 구동 중이지 않을 경우에 양호"                         >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="tftp" {print $1 "   " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="talk" {print $1 "   " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="ntalk" {print $1 "  " $2}' | grep "udp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "☞ tftp, talk, ntalk Service Disable"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-46 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-47 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.12 Sendmail 버전 점검 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.12 Sendmail 버전 점검               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: sendmail 버전이 8.13.8 이상이면 양호"                                            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ sendmail 버전확인"                                                                    >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
   then
     grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ                                            >> $CREATE_FILE 2>&1
   else
     echo "/etc/mail/sendmail.cf 파일이 없습니다."                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-47 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-48 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.13 스팸 메일 릴레이 제한 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.13 스팸 메일 릴레이 제한             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■       : (R$*         $#error $@ 5.7.1 $: "550 Relaying denied" 해당 설정에 주석이 제거되어 있으면 양호)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied"                           >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-48 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-49 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.14 일반사용자의 Sendmail 실행 방지 ###############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################       3.14 일반사용자의 Sendmail 실행 방지        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■       : (restrictqrun 옵션이 설정되어 있을 경우 양호)"                                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/mail/services 파일에서 포트 확인"                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                                 >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-49 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-50 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.15 DNS 보안 버전 패치 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.15 DNS 보안 버전 패치               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나, 양호한 버전을 사용하고 있을 경우에 양호"           >> $CREATE_FILE 2>&1
echo "■       : (양호한 버전: 8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)"            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
DNSPR=`ps -ef | grep named | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
DNSPR=`echo $DNSPR | awk '{print $1}'`
if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
then
	if [ -f $DNSPR ]
	then
    echo "BIND 버전 확인"                                                                      >> $CREATE_FILE 2>&1
    echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
    $DNSPR -v | grep BIND                                                                      >> $CREATE_FILE 2>&1
  else
    echo "$DNSPR 파일이 없습니다."                                                             >> $CREATE_FILE 2>&1
  fi
else
  echo "☞ DNS Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-50 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-51 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.16 DNS Zone Transfer 설정 ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.16 DNS Zone Transfer 설정             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DNS 서비스를 사용하지 않거나 Zone Transfer 가 제한되어 있을 경우 양호"           >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① DNS 프로세스 확인 " >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "☞ DNS Service Disable"                                                                >> $CREATE_FILE 2>&1
else
	ps -ef | grep named | grep -v "grep"                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ls -al /etc/rc*.d/* | grep -i named | grep "/S" | wc -l` -gt 0 ]
then
	ls -al /etc/rc*.d/* | grep -i named | grep "/S"                                              >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
echo "② /etc/named.conf 파일의 allow-transfer 확인"                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/named.conf ]
then
	cat /etc/named.conf | grep 'allow-transfer'                                                  >> $CREATE_FILE 2>&1
else
	echo "/etc/named.conf 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/named.boot 파일의 xfrnets 확인"                                                  >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/named.boot ]
then
	cat /etc/named.boot | grep "\xfrnets"                                                        >> $CREATE_FILE 2>&1
else
	echo "/etc/named.boot 파일이 없습니다."                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-51 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-52 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.17 Apache 디렉토리 리스팅 제거 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         3.17 Apache 디렉토리 리스팅 제거          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 Options 지시자에 Indexes가 설정되어 있지 않으면 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
############################### 홈디렉터리 경로 구하기(시작) ##################################
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
################################ 홈디렉터리 경로 구하기(끝) ###################################
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	if [ -f $ACONF ]
	then
		echo "☞ Indexes 설정 확인"                                                                >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                       >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
		cat $ACONF | egrep -i "<Directory |Indexes|</Directory" | grep -v '\#'                     >> $CREATE_FILE 2>&1
	else
		echo "☞ Apache 설정파일을 찾을 수 없습니다.(수동점검)"                                    >> $CREATE_FILE 2>&1
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-52 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-53 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.18 Apache 웹 프로세스 권한 제한 ##################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.18 Apache 웹 프로세스 권한 제한          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 웹 프로세스 권한을 제한 했을 경우 양호(User root, Group root 가 아닌 경우)"      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "user" >> $CREATE_FILE 2>&1
	cat $ACONF | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir" | grep -i "group" >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo "☞ httpd 데몬 동작 계정 확인"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	ps -ef | grep "httpd"                                                                        >> $CREATE_FILE 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-53 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-54 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.19 Apache 상위 디렉토리 접근 금지 ################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################        3.19 Apache 상위 디렉토리 접근 금지        ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: httpd.conf 파일의 Directory 부분의 AllowOverride None 설정이 아니면 양호"        >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "<Directory |AllowOverride|</Directory" | grep -v '\#'                 >> $CREATE_FILE 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-54 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-55 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.20 Apache 불필요한 파일 제거 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.20 Apache 불필요한 파일 제거          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /htdocs/manual 또는 /apache/manual 디렉터리와,"                                  >> $CREATE_FILE 2>&1
echo "■       : /cgi-bin/test-cgi, /cgi-bin/printenv 파일이 제거되어 있는 경우 양호"           >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	if [ -d $AHOME/cgi-bin ]
	then
		echo "☞ $AHOME/cgi-bin 파일"                                                              >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		ls -ld $AHOME/cgi-bin/test-cgi                                                             >> $CREATE_FILE 2>&1
		ls -ld $AHOME/cgi-bin/printenv                                                             >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "☞ $AHOME/cgi-bin 디렉터리가 제거되어 있습니다.(양호)"                               >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi

	if [ -d $AHOME/htdocs/manual ]
	then
		echo "☞ $AHOME/htdocs/manual 파일"                                                        >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		ls -ld $AHOME/htdocs/manual                                                                >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "☞ $AHOME/htdocs/manual 디렉터리가 제거되어 있습니다.(양호)"                         >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi

	if [ -d $AHOME/manual ]
	then
		echo "☞ $AHOME/manual 파일 설정"                                                          >> $CREATE_FILE 2>&1
		echo "------------------------------------------------------------------------------"      >> $CREATE_FILE 2>&1
		ls -ld $AHOME/manual                                                                       >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "☞ $AHOME/manual 디렉터리가 제거되어 있습니다.(양호)"                                >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-55 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-56 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.21 Apache 링크 사용 금지 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.21 Apache 링크 사용 금지            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: Options 지시자에서 심블릭 링크를 가능하게 하는 옵션인 FollowSymLinks가 제거된 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v '\#'                >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-56 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-57 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.22 Apache 파일 업로드 및 다운로드 제한 ###########################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.22 Apache 파일 업로드 및 다운로드 제한     ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 시스템에 따라 파일 업로드 및 다운로드에 대한 용량이 제한되어 있는 경우 양호"     >> $CREATE_FILE 2>&1
echo "■       : <Directory 경로>의 LimitRequestBody 지시자에 제한용량이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "<Directory |LimitRequestBody|</Directory" | grep -v '\#'              >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-57 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-58 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.23 Apache 웹 서비스 영역의 분리 ##################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         3.23 Apache 웹 서비스 영역의 분리         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: DocumentRoot를 기본 디렉터리(~/apache/htdocs)가 아닌 별도의 디렉토리로 지정한 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	cat $ACONF | egrep -i "DocumentRoot " | grep -v '\#'                                         >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-58 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-59 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.24 ssh 원격접속 허용 #############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              3.24 ssh 원격접속 허용               ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SSH 서비스가 활성화 되어 있으면 양호"                                            >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① 프로세스 데몬 동작 확인"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
	else
		ps -ef | grep sshd | grep -v "grep"                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "② 서비스 포트 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " " > ssh-result.txt
ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		if [ `cat $file | grep ^Port | grep -v ^# | wc -l` -gt 0 ]
		then
			cat $file | grep ^Port | grep -v ^# | awk '{print "SSH 설정파일('${file}'): " $0 }'      >> ssh-result.txt
			port1=`cat $file | grep ^Port | grep -v ^# | awk '{print $2}'`
			echo " "                                                                                 > port1-search.txt
		else
			echo "SSH 설정파일($file): 포트 설정 X (Default 설정: 22포트 사용)"                      >> ssh-result.txt
		fi
	fi
done
if [ `cat ssh-result.txt | grep -v "^ *$" | wc -l` -gt 0 ]
then
	cat ssh-result.txt | grep -v "^ *$"                                                          >> $CREATE_FILE 2>&1
else
	echo "SSH 설정파일: 설정 파일을 찾을 수 없습니다."                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1

# 서비스 포트 점검
echo "③ 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f port1-search.txt ]
then
	if [ `netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
	else
		netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN"                          >> $CREATE_FILE 2>&1
	fi
else
	if [ `netstat -na | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	then
		echo "☞ SSH Service Disable"                                                              >> $CREATE_FILE 2>&1
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
echo "################## 3.25 ftp 서비스 확인 ###############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################               3.25 ftp 서비스 확인                ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services 파일에서 포트 확인 #################
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
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-60 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-61 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.26 ftp 계정 shell 제한 ###########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################             3.26 ftp 계정 shell 제한              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 서비스가 비활성화 되어 있을 경우 양호"                                       >> $CREATE_FILE 2>&1
echo "■       : ftp 서비스 사용 시 ftp 계정의 Shell을 접속하지 못하도록 설정하였을 경우 양호"  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services 파일에서 포트 확인 #################
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
################# vsftpd 에서 포트 확인 ############################
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
################# proftpd 에서 포트 확인 ###########################
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
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ ftp 계정 쉘 확인(ftp 계정에 false 또는 nologin 설정시 양호)"                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
then
	cat /etc/passwd | awk -F: '$1=="ftp"'                                                        >> $CREATE_FILE 2>&1
else
	echo "ftp 계정이 존재하지 않음.(양호)"                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-61 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-62 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.27 Ftpusers 파일 소유자 및 권한 설정 #############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################      3.27 Ftpusers 파일 소유자 및 권한 설정       ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftpusers 파일의 소유자가 root이고, 권한이 640 미만이면 양호"                     >> $CREATE_FILE 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services 파일에서 포트 확인 #################
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
################# vsftpd 에서 포트 확인 ############################
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
################# proftpd 에서 포트 확인 ###########################
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
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ ftpusers 파일 소유자 및 권한 확인"                                                    >> $CREATE_FILE 2>&1
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
	echo "ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-62 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
rm -rf ftpusers.txt
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-63 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.28 Ftpusers 파일 설정 ############################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################              3.28 Ftpusers 파일 설정              ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ftp 를 사용하지 않거나, ftp 사용시 ftpusers 파일에 root가 있을 경우 양호"        >> $CREATE_FILE 2>&1
echo "■       : [FTP 종류별 적용되는 파일]"                                                    >> $CREATE_FILE 2>&1
echo "■       : (1)ftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                                >> $CREATE_FILE 2>&1
echo "■       : (2)proftpd: /etc/ftpusers 또는 /etc/ftpd/ftpusers"                             >> $CREATE_FILE 2>&1
echo "■       : (3)vsftpd: /etc/vsftpd/ftpusers, /etc/vsftpd/user_list (또는 /etc/vsftpd.ftpusers, /etc/vsftpd.user_list)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
then
	cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
else
	echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)"                                  >> $CREATE_FILE 2>&1
fi
if [ -s vsftpd.txt ]
then
	if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	else
		echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)"                               >> $CREATE_FILE 2>&1
	fi
else
	echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다."                                        >> $CREATE_FILE 2>&1
fi
if [ -s proftpd.txt ]
then
	if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	then
		cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}'    >> $CREATE_FILE 2>&1
	else
		echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트를 사용중)"              >> $CREATE_FILE 2>&1
	fi
else
	echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다."                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
################# /etc/services 파일에서 포트 확인 #################
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
################# vsftpd 에서 포트 확인 ############################
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
################# proftpd 에서 포트 확인 ###########################
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
	echo "☞ FTP Service Disable"                                                                >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ ftpusers 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       > ftpusers.txt
ServiceDIR="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd.ftpusers /etc/vsftpd/user_list /etc/vsftpd.user_list"
for file in $ServiceDIR
do
	if [ -f $file ]
	then
		if [ `cat $file | grep "root" | grep -v "^#" | wc -l` -gt 0 ]
		then
			echo "● $file 파일내용: `cat $file | grep "root" | grep -v "^#"` 계정이 등록되어 있음."  >> ftpusers.txt
			echo "check"                                                                             > check.txt
		else
			echo "● $file 파일내용: root 계정이 등록되어 있지 않음."                                 >> ftpusers.txt
			echo "check"                                                                             > check.txt
		fi
	fi
done

if [ -f check.txt ]
then
	cat ftpusers.txt | grep -v "^ *$"                                                            >> $CREATE_FILE 2>&1
else
	echo "ftpusers 파일을 찾을 수 없습니다. (FTP 서비스 동작 시 취약)"                           >> $CREATE_FILE 2>&1
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
echo "################## 3.29 at 파일 소유자 및 권한설정 ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.29 at 파일 소유자 및 권한설정          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: at.allow 또는 at.deny 파일 권한이 640 미만이면 양호"                             >> $CREATE_FILE 2>&1
echo "■       : (at.allow 또는 at.deny 파일이 없는 경우 모든 사용자가 at 명령을 사용할 수 있으므로 취약)" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① at.allow 파일 권한 확인"                                                              >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/at.allow ]
then
	ls -alL /etc/at.allow                                                                        >> $CREATE_FILE 2>&1
else
	echo "/etc/at.allow 파일이 없습니다."                                                        >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② at.deny 파일 권한 확인"                                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/at.deny ]
then
	ls -alL /etc/at.deny                                                                         >> $CREATE_FILE 2>&1
else
	echo "/etc/at.deny 파일이 없습니다."                                                         >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-64 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-65 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.30 SNMP 서비스 구동 점검 #########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.30 SNMP 서비스 구동 점검             ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SNMP 서비스를 불필요한 용도로 사용하지 않을 경우 양호"                           >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
# SNMP서비스는 동작시 /etc/service 파일의 포트를 사용하지 않음.
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]
then
	echo "☞ SNMP Service Disable"                                                               >> $CREATE_FILE 2>&1
else
	echo "☞ SNMP 서비스 활성화 여부 확인(UDP 161)"                                              >> $CREATE_FILE 2>&1
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
echo "################## 3.31 snmp 서비스 커뮤티니스트링의 복잡성 설정 ######################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################   3.31 snmp 서비스 커뮤티니스트링의 복잡성 설정   ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SNMP Community 이름이 public, private 이 아닐 경우 양호"                         >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① SNMP 서비스 활성화 여부 확인(UDP 161)"                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `netstat -na | grep ":161 " | grep -i "^udp" | wc -l` -eq 0 ]
then
	echo "☞ SNMP Service Disable"                                                               >> $CREATE_FILE 2>&1
else
	netstat -na | grep ":161 " | grep -i "^udp"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② SNMP Community String 설정 값"                                                        >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/snmpd.conf ]
then
	echo "● /etc/snmpd.conf 파일 설정:"                                                          >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /etc/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#"           >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi
if [ -f /etc/snmp/snmpd.conf ]
then
	echo "● /etc/snmp/snmpd.conf 파일 설정:"                                                     >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /etc/snmp/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#"      >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi
if [ -f /etc/snmp/conf/snmpd.conf ]
then
	echo "● /etc/snmp/conf/snmpd.conf 파일 설정:"                                                >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /etc/snmp/conf/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi
if [ -f /SI/CM/config/snmp/snmpd.conf ]
then
	echo "● /SI/CM/config/snmp/snmpd.conf 파일 설정:"                                            >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------"                                >> $CREATE_FILE 2>&1
	cat /SI/CM/config/snmp/snmpd.conf | grep -E -i "public|private|com2sec|community" | grep -v "^#" >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
	echo " "                                                                                     > snmpd.txt
fi

if [ -f snmpd.txt ]
then
	rm -rf snmpd.txt
else
	echo "snmpd.conf 파일이 없습니다."                                                           >> $CREATE_FILE 2>&1
	echo " "                                                                                     >> $CREATE_FILE 2>&1
fi
echo "U-66 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-67 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.32 로그온 시 경고 메시지 제공 ####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.32 로그온 시 경고 메시지 제공          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: /etc/issue.net과 /etc/motd 파일에 로그온 경고 메시지가 설정되어 있을 경우 양호"  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/motd 파일 설정: "                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/motd ]
then
	if [ `cat /etc/motd | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/motd | grep -v "^ *$"                                                             >> $CREATE_FILE 2>&1
	else
		echo "경고 메시지 설정 내용이 없습니다.(취약)"                                             >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/motd 파일이 없습니다."                                                            >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/issue.net 파일 설정: "                                                           >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "● /etc/services 파일에서 포트 확인"                                                      >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp"                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "● 서비스 포트 활성화 여부 확인"                                                          >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ `cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
then
	port=`cat /etc/services | awk -F" " '$1=="telnet" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	if [ `netstat -na | grep ":$port " | grep -i "^tcp" | wc -l` -gt 0 ]
	then
		netstat -na | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN"                           >> $CREATE_FILE 2>&1
	else
		echo "☞ Telnet Service Disable"                                                           >> $CREATE_FILE 2>&1
	fi
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "● /etc/issue.net 파일 설정:"                                                             >> $CREATE_FILE 2>&1
echo "-------------------------------------------------------------"                           >> $CREATE_FILE 2>&1
if [ -f /etc/issue.net ]
then
	if [ `cat /etc/issue.net | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/issue.net | grep -v "^#" | grep -v "^ *$"                                         >> $CREATE_FILE 2>&1
	else
		echo "경고 메시지 설정 내용이 없습니다.(취약)"                                             >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/issue.net 파일이 없습니다."                                                       >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-67 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-68 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.33 NFS 설정 파일 접근 권한 #######################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################           3.33 NFS 설정 파일 접근 권한            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: NFS 서버 데몬이 동작하지 않거나, /etc/exports 파일의 권한이 644 이하이면 양호"   >> $CREATE_FILE 2>&1
echo "■       : (/etc/exports 파일 없으면 NFS서비스 이용이 불가능함으로 양호)"                 >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① NFS Server Daemon(nfsd)확인"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep" | wc -l` -gt 0 ] 
 then
   ps -ef | grep "nfsd" | egrep -v "statdaemon|automountd|emi" | grep -v "grep"                >> $CREATE_FILE 2>&1
 else
   echo "☞ NFS Service Disable"                                                               >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② /etc/exports 파일 권한 설정"                                                          >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/exports ]
  then
   ls -alL /etc/exports                                                                        >> $CREATE_FILE 2>&1
  else
   echo "/etc/exports 파일이 없습니다.(양호)"                                                  >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-68 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1



echo "U-69 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.34 expn, vrfy 명령어 제한 ########################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################            3.34 expn, vrfy 명령어 제한            ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: SMTP 서비스를 사용하지 않거나 noexpn, novrfy 옵션이 설정되어 있을 경우 양호"     >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① /etc/services 파일에서 포트 확인"                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
cat /etc/services | awk -F" " '$1=="smtp" {print $1 "   " $2}' | grep "tcp"                    >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② 서비스 포트 활성화 여부 확인"                                                         >> $CREATE_FILE 2>&1
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
	echo "☞ Sendmail Service Disable"                                                           >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "③ /etc/mail/sendmail.cf 파일의 옵션 확인"                                               >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/mail/sendmail.cf ]
  then
    grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions                                 >> $CREATE_FILE 2>&1
  else
    echo "/etc/mail/sendmail.cf 파일이 없습니다."                                              >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-69 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1





echo "U-70 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 3.35 Apache 웹서비스 정보 숨김 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          3.35 Apache 웹서비스 정보 숨김           ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: ServerTokens 지시자로 헤더에 전송되는 정보를 설정할 수 있음.(ServerTokens Prod 설정인 경우 양호)" >> $CREATE_FILE 2>&1
echo "■       : ServerTokens Prod 설정이 없는 경우 Default 설정(ServerTokens Full)이 적용됨."  >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
if [ `ps -ef | grep "httpd" | grep -v "ns-httpd" | grep -v "grep" | awk '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -gt 0 ]
then
	echo "☞ $ACONF 파일 설정 확인"                                                              >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------------------------"        >> $CREATE_FILE 2>&1
	if [ `cat $ACONF | grep -i "ServerTokens" | grep -v '\#' | wc -l` -gt 0 ]
	then
		cat $ACONF | grep -i "ServerTokens" | grep -v '\#'                                         >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	else
		echo "ServerTokens 지시자가 설정되어 있지 않습니다.(취약)"                                 >> $CREATE_FILE 2>&1
		echo " "                                                                                   >> $CREATE_FILE 2>&1
	fi
else
	echo "☞ Apache Service Disable"                                                             >> $CREATE_FILE 2>&1
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
echo "#############################      4. 패치 관리      ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-71 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 4.1 최신 보안패치 및 벤더 권고사항 적용 ############################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################     4.1 최신 보안패치 및 벤더 권고사항 적용      ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있을 경우 양호"             >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 현재 등록된 서비스"                                                                   >> $CREATE_FILE 2>&1
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
echo "#############################      5. 로그 관리      ##################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1


echo "U-72 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 5.1 로그의 정기적 검토 및 보고 #####################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################          5.1 로그의 정기적 검토 및 보고          ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: 로그기록에 대해 정기적 검토, 분석, 리포트 작성 및 보고가 이루어지고 있는 경우 양호" >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "☞ 담당자 인터뷰 및 증적확인"                                                            >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
echo "① 일정 주기로 로그를 점검하고 있는가?"                                                  >> $CREATE_FILE 2>&1
echo "② 로그 점검결과에 따른 결과보고서가 존재하는가?"                                        >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "U-72 END"                                                                                >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "=======================================================================================" >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1

echo "U-73 START"                                                                              >> $CREATE_FILE 2>&1
echo "################## 5.2 정책에 따른 시스템 로깅 설정 ###################################"
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "##################         5.2 정책에 따른 시스템 로깅 설정         ##################" >> $CREATE_FILE 2>&1
echo "#######################################################################################" >> $CREATE_FILE 2>&1
echo "■ 기준: syslog 에 중요 로그 정보에 대한 설정이 되어 있을 경우 양호"                      >> $CREATE_FILE 2>&1
echo "■ 현황"                                                                                  >> $CREATE_FILE 2>&1
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "① SYSLOG 데몬 동작 확인"                                                                >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ `ps -ef | grep 'syslog' | grep -v 'grep' | wc -l` -eq 0 ]
then
	echo "☞ SYSLOG Service Disable"                                                             >> $CREATE_FILE 2>&1
else
	ps -ef | grep 'syslog' | grep -v 'grep'                                                      >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② SYSLOG 설정 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/syslog.conf ]
then
	if [ `cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/syslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $CREATE_FILE 2>&1
	else
		echo "/etc/syslog.conf 파일에 설정 내용이 없습니다.(주석, 빈칸 제외)"                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/syslog.conf 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
fi
echo " "                                                                                       >> $CREATE_FILE 2>&1
echo "② RSYSLOG 설정 확인"                                                                     >> $CREATE_FILE 2>&1
echo "------------------------------------------------------------------------------"          >> $CREATE_FILE 2>&1
if [ -f /etc/rsyslog.conf ]
then
	if [ `cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$" | wc -l` -gt 0 ]
	then
		cat /etc/rsyslog.conf | grep -v "^#" | grep -v "^ *$"                                       >> $CREATE_FILE 2>&1
	else
		echo "/etc/rsyslog.conf 파일에 설정 내용이 없습니다.(주석, 빈칸 제외)"                      >> $CREATE_FILE 2>&1
	fi
else
	echo "/etc/rsyslog.conf 파일이 없습니다."                                                     >> $CREATE_FILE 2>&1
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

echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"
echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"   
