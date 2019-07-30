#!/bin/sh -u

OS=`uname`


if [ $OS = Linux ]
then
    alias echo='echo -e'
fi

HOSTNAME=`hostname`

LANG=C
export LANG

clear


echo "********************************************************************"
echo "*                EGISIT Server(Linux) Checklist               *"
echo "********************************************************************"
echo "*       Copyright 2017 EGISIT Co. Ltd. All right Reserved     *"
echo "*                                                                   *"
echo "*                                                                   *"
echo "*                                                                   *"
echo "*                                                                   *"
echo "********************************************************************"
echo " "

echo " " >> $HOSTNAME.txt 2>&1
chmod 400 $HOSTNAME.txt
echo "#Checking System Time : `date`"
echo "#Start Time : `date`" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "Information gathering Start"
echo
echo "=================== System Information Query Start ====================="
echo "=================== System Information Query Start =====================" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "# uname -a "
echo "# uname -a " >> $HOSTNAME.txt 2>&1
uname -a >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "# ifconfig -a "
if [ $OS = 'HP-UX' ]
then
	echo "ifconfig `lanscan -v | grep "lan" | awk -F' ' '{print $5}' | uniq`" >> $HOSTNAME.txt 2>&1
	ifconfig `lanscan -v | grep "lan" | awk -F' ' '{print $5}' | uniq` >> $HOSTNAME.txt 2>&1
else
	echo "# ifconfig -a " >> $HOSTNAME.txt 2>&1
	ifconfig -a >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

# Process Information
echo "###  Process Information "
echo "###  Process Information " >> $HOSTNAME.txt 2>&1
ps -ef | grep -v grep | grep -v ps | cut -c47-80 | sort | uniq > tmp0.txt 2>&1
cat tmp0.txt >> $HOSTNAME.txt 2>&1
rm tmp0.txt
echo " " >> $HOSTNAME.txt 2>&1 

echo "# netstat -an"
echo "# netstat -an " >> $HOSTNAME.txt 2>&1
netstat -an >> $HOSTNAME.txt 2>&1
echo "[End] " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "# netstat -rn "
echo "# netstat -rn " >> $HOSTNAME.txt 2>&1
netstat -rn >> $HOSTNAME.txt 2>&1
echo "[End] " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "# ps -ef "
echo "# ps -ef " >> $HOSTNAME.txt 2>&1
ps -ef | grep -v grep >> $HOSTNAME.txt 2>&1
echo "[End]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "# ps -ef | egrep httpd|sendmail|named|nfsd|dmi|snmpd "
echo "# ps -ef | egrep httpd|sendmail|named|nfsd|dmi|snmpd " >> $HOSTNAME.txt 2>&1
ps -ef | egrep "httpd|sendmail|named|nfsd|dmi|snmpd" | grep -v grep>> $HOSTNAME.txt 2>&1
echo "[End]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "# env "
echo "# env " >> $HOSTNAME.txt 2>&1
env >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "======================= System Information Query End ========================"
echo "======================= System Information Query End ========================" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo "========================== 진단 시작 =========================" >> $HOSTNAME.txt 2>&1
echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-1] root 계정 원격 접속 제한"  
echo "[U-1] root 계정 원격 접속 제한"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/securetty 에 pts/0 ~ pts/x 설정이 제거 되어 있거나 주석처리 되어 있을 경우" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 위의 설정 적용 후 auth required /lib/security/pam_securetty.so 라인을 주석(#)제거 또는 신규 추가하였으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "22번, 23번 포트 오픈 확인" >> $HOSTNAME.txt 2>&1
echo "netstat -na | grep LISTEN | grep tcp | grep 22"    >> $HOSTNAME.txt 2>&1
netstat -na | grep LISTEN | grep tcp | grep 22    >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "netstat -na | grep LISTEN | grep tcp | grep 23"    >> $HOSTNAME.txt 2>&1
netstat -na | grep LISTEN | grep tcp | grep 23    >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "#cat /etc/securetty" >> $HOSTNAME.txt 2>&1
cat /etc/securetty >> $HOSTNAME.txt 2>&1
echo ". " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo "cat /etc/pam.d/login" >> $HOSTNAME.txt 2>&1
echo "auth	required	/lib/security/pam_securetty.so	// 주석(#)제거 또는 신규 삽입" >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
cat /etc/pam.d/login >> $HOSTNAME.txt 2>&1
echo ". " >> $HOSTNAME.txt 2>&1
echo "SSH 옵션 확인"  >> $HOSTNAME.txt 2>&1
echo "cat /etc/ssh/sshd_config | grep PermitRootLogin" >> $HOSTNAME.txt 2>&1
cat /etc/ssh/sshd_config | grep "PermitRootLogin" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[U-1] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-2] 패스워드 복잡성"
echo "[U-2] 패스워드 복잡성"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: MANUAL(Using LC6 or John the ripper) " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 패스워드를 영문숫자 혼합을 사용하지 않고 간단하게 설정하였으면 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "암호화 방식 확인"  >> $HOSTNAME.txt 2>&1 
echo "authconfig --test | grep password" >> $HOSTNAME.txt 2>&1 
authconfig --test | grep password   >> $HOSTNAME.txt 2>&1 
echo "#cat /etc/shadow" >> $HOSTNAME.txt 2>&1
cat /etc/shadow >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/passwd" >> $HOSTNAME.txt 2>&1
cat /etc/passwd  >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-2] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-2] 패스워드 복잡성 TIP >> $HOSTNAME.txt 2>&1
echo "md5 = $ 1 $ 으로 시작"  	                  			                 >> $HOSTNAME.txt 2>&1
echo "sha256 = $ 5 $ 으로 시작"                          			            >> $HOSTNAME.txt 2>&1
echo "sha512 = $ 6 $ 으로 시작"  												 >> $HOSTNAME.txt 2>&1 
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                        >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-3] 계정 잠금 임계값 설정"  
echo "[U-3] 계정 잠금 임계값 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/pam.d/system-auth 파일 에 auth  required  pam_tally[2].so  onerr=fail  deny=5  unlock_time=120  no_magic_root  reset" >> $HOSTNAME.txt 2>&1
echo "          account  required  pam_tally[2].so  no_magic_root 이 설정되어 있으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "사용하는 pam_tally 버전확인" >> $HOSTNAME.txt 2>&1 
echo "find / -name "*pam_tally*"" >> $HOSTNAME.txt 2>&1 
find / -name "*pam_tally*"        >> $HOSTNAME.txt 2>&1 
echo " " >> $HOSTNAME.txt 2>&1
echo "현재 잠금 상태 확인" >>  $HOSTNAME.txt 2>&1 
echo "pam_tally"  >> $HOSTNAME.txt 2>&1 
pam_tally >> $HOSTNAME.txt 2>&1 
echo "." >> $HOSTNAME.txt 2>&1
echo "pam_tally2" >> $HOSTNAME.txt 2>&1 
pam_tally2 >> $HOSTNAME.txt 2>&1 
echo "." >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "telnet 임계값 설정파일 확인" >> $HOSTNAME.txt 2>&1 
echo "cat /etc/pam.d/remote" >> $HOSTNAME.txt 2>&1 
cat /etc/pam.d/remote >> $HOSTNAME.txt 2>&1 
echo " " >> $HOSTNAME.txt 2>&1
echo "ssh 임계값 설정파일 확인" >> $HOSTNAME.txt 2>&1 
echo "cat /etc/pamd.d/sshd" >> $HOSTNAME.txt 2>&1 
cat /etc/pam.d/sshd  >> $HOSTNAME.txt 2>&1 

echo " " >> $HOSTNAME.txt 2>&1 
echo "system-auth 확인 " >> $HOSTNAME.txt 2>&1 

		echo "cat /etc/pam.d/system-auth" >> $HOSTNAME.txt 2>&1
		cat /etc/pam.d/system-auth  >> $HOSTNAME.txt 2>&1
		echo "#cat /etc/pam.d/common-auth" >> $HOSTNAME.txt 2>&1
		cat /etc/pam.d/common-auth  >> $HOSTNAME.txt 2>&1
		echo "------ " >> $HOSTNAME.txt 2>&1
			
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-3] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-3] 계정 잠금 임계값 설정 TIP 												>> $HOSTNAME.txt 2>&1
echo 계정 임계값을 설정하려면 pam_tally.so 라는 라이브러리를 사용하는데 리눅스 버전에 따라서 >> $HOSTNAME.txt 2>&1 
echo pam_tally.so[구버전]  pam_tally2.so[신버전] 에 설치되어있으므로 해당 버전에 맞도록 설정해야한다. >> $HOSTNAME.txt 2>&1 
echo telnet 의 경우 /etc/pam.d/remote 에 설정을 한다.                                                  >> $HOSTNAME.txt 2>&1 
echo ssh 의 경우 /etc/pamd.d/sshd 에 설정을 한다.                                                    >> $HOSTNAME.txt 2>&1 
echo ftp 의 경우 /etc/pamd.d/ftp 에 설정을 한다.[SFTP경우 ssh정책을따름]        >> $HOSTNAME.txt 2>&1
echo 위 파일에 다음과 같은 설정을 해주어야한다.                        >> $HOSTNAME.txt 2>&1 
echo 예시] vi /etc/pam.d/sshd                                          >> $HOSTNAME.txt 2>&1             
echo 예시] auth  required  pam_tally.so  onerr=fail  deny=5  unlock_time=1800  no_magic_root  reset  >> $HOSTNAME.txt 
echo 예시] account  required  pam_tally.so  no_magic_root            >> $HOSTNAME.txt 2>&1 
echo 위의 예시에서 pam_tally2를 사용한다면 pam_tally2.so 를 명시한다.   >> $HOSTNAME.txt 2>&1 
echo onerr=fail  : 오류가 발생하면 접근 차단                            >> $HOSTNAME.txt 2>&1
echo deny=5 : 5번의 임계값을 가짐 [이후 계정 잠김]                      >> $HOSTNAME.txt 2>&1
echo unlock_time=120 : 계정 잠김 후 2분 이후 잠김 해제 				>> $HOSTNAME.txt 2>&1
echo no_magic_root : root 계정은 잠기지 않도록 설정                        >> $HOSTNAME.txt 2>&1
echo reset : 로그인이 성공하면 badcount 값 reset됨                           >> $HOSTNAME.txt 2>&1
echo 잠금설정을 강제로 초기화 하고싶다면 다음과같이 설정한다                 >> $HOSTNAME.txt 2>&1
echo pam_tally2 사용시 = pam_tally2 -u [username] -r                        >> $HOSTNAME.txt 2>&1
echo pam_tally 사용시 = faillog -u [username] -r 												>> $HOSTNAME.txt 2>&1
echo 해당항목들을 설정파일에서 찾을수 없다면 취약함                             >> $HOSTNAME.txt 2>&1
echo 운용중인 서버에서 이 정책을 반영할경우 주의해야 하는건 설정을 잘못하면 root 계정 및 일반계정이 잠김으로 >> $HOSTNAME.txt 2>&1
echo 엔지니어와 함께 정책을 반영하고 최소 한개의 세션은 root 권한으로 접속을 유지시킨뒤 작업완료 여부를 확인한후 적용한다 >> $HOSTNAME.txt 2>&1 
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                               >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-4] 패스워드 파일 보호"
echo "[U-4] 패스워드 파일 보호" >> $HOSTNAME.txt 2>&1
echo "[CHECK] 패스워드 저장을 /etc/shadow 파일에 저장하면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "ls -alL /etc/passwd /etc/shadow" >> $HOSTNAME.txt 2>&1
ls -alL /etc/passwd /etc/shadow >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/passwd" >> $HOSTNAME.txt 2>&1
cat /etc/passwd >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "[U-4] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-4] 패스워드 파일 보호 TIP 												>> $HOSTNAME.txt 2>&1
echo 패스워드 해쉬값이 /etc/passwd 존재한다면 취약함            >> $HOSTNAME.txt 2>&1
echo 또한 /etc/shadow 파일의 권한이 그외사용자가 읽거나 쓰기가 가능해도 취약함  >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                               >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-5] root 이외의 UID가 '0' 금지"  
echo "[U-5] root 이외의 UID가 '0' 금지"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: if exists(UID = 0) except root THEN VUL" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: root계정과 동일한 UID를 갖는 계정이 존재하지 않을 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

#echo "#awk -F: '$3==0 || $4==0 { print $1 " -> UID=" $3 "  GID=" $4 }' /etc/passwd" >> $HOSTNAME.txt 2>&1
awk -F: '$3==0  { print $1 " -> UID=" $3 }' /etc/passwd >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-5] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-5] root 이외의 UID가 '0' 금지 TIP 												>> $HOSTNAME.txt 2>&1
echo root 이외에 UID가 0인 user가 출력되면 취약함             >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                               >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-6] root 계정 su 제한"  
echo "[U-6] root 계정 su 제한"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/pam.d/su 파일에 auth required /lib/security/pam_wheel.so debug group=wheel 라인이 추가되어있으면 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: PAM모듈을 사용하지 않을 경우 su 명령어를 사용할 그룹을 생성하고, /bin/su 파일의 권한을 4750으로 제한 및 소유그룹이 특정그룹으로 지정되어 있으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/pam.d/su ]
  then
    echo "/etc/pam.d/su 파일" >> $HOSTNAME.txt 2>&1
    cat /etc/pam.d/su >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/pam.d/su 파일이 없습니다. " >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "/bin/su 파일" >> $HOSTNAME.txt 2>&1
if [ `ls -al /bin/su | wc -l` -eq 0 ]
 then
   echo "/bin/su 파일이 없습니다. " >> $HOSTNAME.txt 2>&1
 else
   ls -al /bin/su >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/group 파일 wheel그룹에 등록된 사용자 확인" >> $HOSTNAME.txt 2>&1
cat /etc/group | grep wheel >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-6] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1




echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-6] root 계정 su 제한 TIP												>> $HOSTNAME.txt 2>&1

echo su를 제한하기위해서는 다음조건이 충족되어야한다.                           >> $HOSTNAME.txt 2>&1
echo 기본적으로 리눅스운영체제에는  /etc/pam.d/su 파일에 pam_wheel.so    >> $HOSTNAME.txt 2>&1
echo 설정값이 주석처리되어있음 이부분을 주석해재 한후 wheel 그룹에 su를  >> $HOSTNAME.txt 2>&1
echo 사용할 user를 등록하면 wheel 그룹에 등록된 사용자만 su 명령을 사용할수 있게됨  >> $HOSTNAME.txt 2>&1
echo 룰이 정상적으로 적용되면 비인가자가 su 를 사용하여 정상적인 패스워드를 입력해도 패스워드가 틀렸다는 메세지 가 출력되므로  >> $HOSTNAME.txt 2>&1
echo 사용자 본인은 패스워드가 틀린지 알게된다.  >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                          				     >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-7] 패스워드 최소 길이 설정"  
echo "[U-7] 패스워드 최소 길이 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 패스워드 최소길이가 9보다 작으면 취약 " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 취약점 분석평가 기준에는 8글자 이상이면 양호하나, 국정원 실태평가 기준이 9글자 이상이므로, 8글자로 설정되어 있으면 양호 판정을 내리나, 9글자 이상으로 설정하도록 권고 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: : " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
PASSMINLEN=`grep PASS_MIN_LEN /etc/login.defs | grep -v "^#" | awk '{ print $2 }'`
if [ $PASSMINLEN ] 
	then
		if [ $PASSMINLEN -lt 9 ]
			then 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MIN_LEN /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
			else 
				echo "#grep PASS_MIN_LEN /etc/login.defs" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "양호" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MIN_LEN /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "설정값이 없습니다." >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-7] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-8] 패스워드 최대 사용 기간 설정"  
echo "[U-8] 패스워드 최대 사용 기간 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 최대 사용기간이 90보다 크면 취약 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: : " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

PASSMAXDAYS=`grep PASS_MAX_DAYS /etc/login.defs | grep -v "^#" | awk '{ print $2 }'`
if [ $PASSMAXDAYS ] 
	then
		if [ $PASSMAXDAYS -gt 90 ]
			then 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MAX_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MAX_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
			else 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MAX_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MAX_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "양호" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#grep PASS_MAX_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
		grep PASS_MAX_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "설정값이 없습니다.취약" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-8] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-9] 패스워드 최소 사용기간 설정"
echo "[U-9] 패스워드 최소 사용기간 설정 작성 필요"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 패스워드 최소 사용기간이 0 이면 취약 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: : " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

PASSMINDAYS=`grep PASS_MIN_DAYS /etc/login.defs | grep -v "^#" | awk '{ print $2 }'`
if [ $PASSMINDAYS ] 
	then
		if [ $PASSMINDAYS -eq 0 ]
			then 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MIN_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
			else 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MIN_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "양호" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#grep PASS_MIN_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
		grep PASS_MIN_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "설정값이 없습니다." >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-9] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
 
echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-10] 불필요한 계정 제거"
echo "[U-10] 불필요한 계정 제거"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 미사용 계정 및 의심스러운 계정 존재 여부 확인 && 사용하지 않는 Default 계정 점검(ex: adm, lp, sync, shutdown, halt, news, uucp, operator, games, gopher, nfsnobody, squid" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 로그인 실패 기록 점검을 통한 미사용 계정 및 의심스러운 계정 확인" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo "계정 확인" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/passwd" >> $HOSTNAME.txt 2>&1
cat /etc/passwd >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "Default 계정 점검" >> $HOSTNAME.txt 2>&1
echo "cat /etc/passwd | egrep \"adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid\"" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | egrep "adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "접속 로그 확인" >> $HOSTNAME.txt 2>&1
echo "#cat /var/log/loginlog" >> $HOSTNAME.txt 2>&1
cat /var/log/loginlog >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "su 로그 확인" >> $HOSTNAME.txt 2>&1
echo "#cat /var/log/sulog" >> $HOSTNAME.txt 2>&1
cat /var/log/sulog >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[수면계정확인]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
lastlog >> $HOSTNAME.txt 2>&1
echo "로그인 실패 기록 점검" >> $HOSTNAME.txt 2>&1
echo "#cat /var/log/secure | grep "failed"" >> $HOSTNAME.txt 2>&1
cat /var/log/secure | grep "failed" | sort >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-10] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-10] 불필요한 계정 제거 TIP												>> $HOSTNAME.txt 2>&1
echo 리눅스에는 최초 OS설치당시부터 존재하는 계정들은 시스템계정들이므로        >> $HOSTNAME.txt 2>&1
echo 쉘이 부여되어있지 않다.     												>> $HOSTNAME.txt 2>&1
echo 원격접속이 가능한 쉘이 부여된 계정[UID500이상]을 중점적으로 확인한다.   >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                          				     >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-11] 관리자 그룹에 최소한의 계정 포함"
echo "[U-11] 관리자 그룹에 최소한의 계정 포함"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: MANUAL CHECK " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 관리자의 그룹에 많은 계정을 했을 경우 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#cat /etc/group | grep "root"" >> $HOSTNAME.txt 2>&1
cat /etc/group | grep "root" >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-11] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-12] 계정이 존재하지 않는 GID 금지"  
echo "[U-12] 계정이 존재하지 않는 GID 금지"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 존재하지 않은 계정에 GID 설정을 했을 경우 취약" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 구성원이 존재하지 않는 그룹이 존재하면 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/group" >> $HOSTNAME.txt 2>&1
cat /etc/group >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "#cat /etc/passwd" >> $HOSTNAME.txt 2>&1
awk -F: '{ print $1 " -> GID=" $4 }' /etc/passwd >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-12] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-13] 동일한 UID 금지"  
echo "[U-13] 동일한 UID 금지"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 동일한 UID가 존재시 취약 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#awk -F: '{print \$1 " = " \$3}' /etc/passwd" >> $HOSTNAME.txt 2>&1
awk -F: '{print $1 " = " $3}' /etc/passwd >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-13] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-14] 사용자 Shell 점검"
echo "[U-14] 사용자 Shell 점검" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 로그인이 필요 없는 계정은 쉘을 /bin/false(/bin/nologin) 설정 했을 경우" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 로그인이 불필요한 계정의 쉘이 설정되어 있지 않으면(쉘 부분 공란) 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
awk -F: '{print $1 " = " $7}' /etc/passwd >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/passwd ]
  then
    cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/passwd 파일이 없습니다." >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "참고: /etc/shadow 확인" >> $HOSTNAME.txt 2>&1
cat /etc/shadow >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-14] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-14] 사용자 Shell 점검 TIP												>> $HOSTNAME.txt 2>&1
echo 리눅스에서 아무쉘도 부여하지 않아도 계정으로 접속이 가능하므로  /bin/false ,  /no shell , bin/nologin   설정이 필요함    >> $HOSTNAME.txt 2>&1
echo 예1] news:x:9:13:news:/etc/news: [패스워드 설정시 접속이가능함]                                               >> $HOSTNAME.txt 2>&1
echo 예2] news:x:9:13:news:/etc/news:/sbin/nologin [패스워드 설정해도 접속이불가능함]                                 >> $HOSTNAME.txt 2>&1
echo 엑셀에 복사하여 텍스트마법사를 활용     >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                          				     >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-15] Session Timeout 설정"  
echo "[U-15] Session Timeout 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] 설정값이 없거나 TMOUT설정이 600보다 크면 취약" >> $HOSTNAME.txt 2>&1
echo "[CHECK] Csh 사용시 autologout 옵션이 10보다 크면 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "sh, ksh, bash 사용시" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/profile | egrep -i 'TMOUT|TIMEOUT'" >> $HOSTNAME.txt 2>&1
cat /etc/profile | egrep -i "TMOUT|TIMEOUT" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /.profile | egrep -i 'TMOUT|TIMEOUT'" >> $HOSTNAME.txt 2>&1
cat /.profile | egrep -i "TMOUT|TIMEOUT" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat ~/.bash_profile | egrep -i 'TMOUT|TIMEOUT'" >> $HOSTNAME.txt 2>&1
cat ~/.bash_profile | egrep -i "TMOUT|TIMEOUT" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "참고: csh 사용시" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/csh.login | grep autologout" >> $HOSTNAME.txt 2>&1
cat /etc/csh.login | grep autologout >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/csh.cshrc | grep autologout" >> $HOSTNAME.txt 2>&1
cat /etc/csh.cshrc | grep autologout >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-15] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-16] root 홈, 패스 디렉터리 권한 및 패스 설정"  
echo "[U-16] root 홈, 패스 디렉터리 권한 및 패스 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: . 또는 ..이 맨 앞 또는 중간에  존재하면 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#echo \$PATH" >> $HOSTNAME.txt 2>&1
echo $PATH  >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-16] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-16] Session Timeout 설정 TIP												>> $HOSTNAME.txt 2>&1
echo PATH 경로설정중 “.”이 맨 앞 또는 중간에 선언되어 있을 경우 관리자가 실제 의도한 경로의 정상적인 파일이 아닌 공격자가   >> $HOSTNAME.txt 2>&1
echo 생성한 파일을 실행할 수 있는 위험이 있다.“.”의 위치를 맨 뒤로 설정되어있지 않을경우 취약함  >> $HOSTNAME.txt 2>&1
echo 현재 디렉토리를 지칭하는 “.”는 PATH 내의 맨 뒤에 위치하도록 설정되어있어야함               >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-17] 파일 및 디렉터리 소유자 설정(시간오래 걸림)"  
echo "[U-17] 파일 및 디렉터리 소유자 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 결과값이 나오면 취약  " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#find /etc \( -nouser -o -nogroup \) -xdev -exec ls -al {} \;"  >> $HOSTNAME.txt 2>&1
find /etc \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#find /tmp \( -nouser -o -nogroup \) -xdev -exec ls -al {} \;" >> $HOSTNAME.txt 2>&1 
find /tmp \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#find /bin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \;" >> $HOSTNAME.txt 2>&1 
find /bin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#find /sbin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \;" >> $HOSTNAME.txt 2>&1 
find /sbin \( -nouser -o -nogroup \) -xdev -exec ls -al {} \; 2> /dev/null >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-17] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-17] 파일 및 디렉터리 소유자 설정											>> $HOSTNAME.txt 2>&1
echo /etc /tmp /bin /sbin 디렉터리중 파일의 소유자가 없거나 그룹이 존재하지 않는파일을 찾아줌    >> $HOSTNAME.txt 2>&1
echo 예1] srwxrwxr-x 1  503  503 0 Dec  7  2010 mapping-tofaz_lkj [소유자, 그룹이 없는 파일]  >> $HOSTNAME.txt 2>&1
echo -xdev 옵션은 해당경로외에는 찾지 않는옵션 예 find / -xdev 는 전체를 검색하는게 아닌 / 만 검색하는것임    >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-18]  /etc/passwd 파일 소유자"  
echo "[U-18]  /etc/passwd 파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root또는 bin등 시스템 계정 , 444(644)미만 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#ls -alL /etc/passwd" >> $HOSTNAME.txt 2>&1
ls -alL /etc/passwd >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/passwd | grep "...-.--.--.*.*" | wc -l` -eq 1 ]
	then
		echo "양호" >> $HOSTNAME.txt 2>&1
	else
		echo "퍼미션이 444(644)가 아닙니다." >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-18] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-19]  /etc/shadow 파일 소유자 및 권한설정"  
echo "[U-19]  /etc/shadow 파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root, 400(600) -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#ls -al /etc/shadow" >> $HOSTNAME.txt 2>&1
ls -al /etc/shadow >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-19] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-20] /etc/hosts 파일 소유자 및 권한 설정"  
echo "[U-20] /etc/hosts 파일 소유자 및 권한 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root또는 bin등 시스템 계정, 600 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/hosts ] 
	then
		echo "ls -l /etc/hosts" >> $HOSTNAME.txt 2>&1
		ls -l /etc/hosts >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/hosts | grep ".r.-------.*.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "취약" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/hosts 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-20] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-20]  /etc/hosts 파일 소유자 및 권한 설정 TIP											>> $HOSTNAME.txt 2>&1
echo 미래창조과학부의 가이드라인기준은 소유자 root에 파일퍼미션은 600 이다.    >> $HOSTNAME.txt 2>&1
echo 단 이항목을 조치하면 오라클 DB 접속이 불가한 경우 다수발생 특정 솔루션과 연동부분을 확인해야함    >> $HOSTNAME.txt 2>&1
echo 대안책으로는 644까지는 문제가 없으나 미래창조과학부 판단기준은 600이 양호임                         >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-21]  /etc/(x)inetd.conf 파일 소유자 및 권한 설정"  
echo "[U-21]  /etc/(x)inetd.conf 파일 소유자 및 권한 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root또는 bin등 시스템 계정, 권한 600 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf ]
	then 
		echo "ls -alL /etc/inetd.conf" >> $HOSTNAME.txt 2>&1
		ls -alL /etc/inetd.conf >> $HOSTNAME.txt 2>&1
		
		echo " " >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/inetd.conf | grep ".r.-------.*.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "취약" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/inetd.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/xinetd.conf ]
	then
		echo "#ls -alL /etc/xinetd.conf" >> $HOSTNAME.txt 2>&1
		ls -alL /etc/xinetd.conf >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/xinetd.conf | grep ".r.-------.*.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "취약" >> $HOSTNAME.txt 2>&1
		fi
		
	else
		echo "/etc/xinetd.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-21] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-21]  /etc/[x]inetd.conf 파일 소유자 및 권한 설정 TIP											>> $HOSTNAME.txt 2>&1
echo 미래창조과학부의 가이드라인기준은 소유자 root에 파일퍼미션은 600 이다.    >> $HOSTNAME.txt 2>&1
echo REDHAT 계열은 기본설치시 xinetd 가 미설치 되어있을수도 있음 /etc/xinetd.conf 가 존재하지 않는다면 미설치된것임 N/A처리함    >> $HOSTNAME.txt 2>&1
echo "---------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-22] /etc/syslog.conf 파일 소유자 및 권한설정"  
echo "[U-22] /etc/syslog.conf 파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root또는 bin등 시스템 계정, 644 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/syslog.conf ]
	then
		echo "#ls -lL /etc/syslog.conf" >> $HOSTNAME.txt 2>&1
		ls -lL /etc/syslog.conf  >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/syslog.conf | grep "...-.--.--.*.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "취약" >> $HOSTNAME.txt 2>&1
		fi
		
	else
		echo "/etc/syslog.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
fi
if [ -f /etc/rsyslog.conf ]
	then
		echo "#ls -lL /etc/rsyslog.conf" >> $HOSTNAME.txt 2>&1
		ls -lL /etc/rsyslog.conf  >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/rsyslog.conf | grep "...-.--.--.*.*" | wc -l` -eq 1 ]
	then
		echo "양호" >> $HOSTNAME.txt 2>&1
	else
		echo "취약" >> $HOSTNAME.txt 2>&1
		fi
		
		
	else
		echo "/etc/rsyslog.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-22] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-22] /etc/syslog.conf 파일 소유자 및 권한설정 TIP											>> $HOSTNAME.txt 2>&1
echo 미래창조과학부의 가이드라인기준은 소유자 root에 파일퍼미션은 644 이다.                         >> $HOSTNAME.txt 2>&1
echo 경우에 따라 상위버전인 rsyslog.conf 를 사용할수도있음                                      >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-23]  /etc/services 파일 소유자 및 권한설정"  
echo "[U-23]  /etc/services 파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root또는 bin등 시스템 계정, Permission:644 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/services ]
	then
		echo "#ls -lL /etc/services" >> $HOSTNAME.txt 2>&1
		ls -lL /etc/services >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/services | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
	then
		echo "양호" >> $HOSTNAME.txt 2>&1
	else
		echo "취약" >> $HOSTNAME.txt 2>&1
		fi
		
		
	else
		echo "/etc/services 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-23] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-23] /etc/services 파일 소유자 및 권한설정 TIP											>> $HOSTNAME.txt 2>&1
echo 미래창조과학부의 가이드라인기준은 소유자 root에 파일퍼미션은 644 이다.    >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-24]  SUID, SGID, Sticky bit 설정 파일 점검"  
echo "[U-24]  SUID, SGID, Sticky bit 설정 파일 점검"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 불필요하게 설정된 SUID, SGID파일 점검 " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 관리자 리뷰를 통한 양호 취약 판단. 불가할시 주요파일의 권한(4750- 일반사용자 권한 없음) 설정 상태로 양호 취약 판단" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "find /  -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al  {}  \;" >> $HOSTNAME.txt 2>&1
find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \; >> $HOSTNAME.txt 2>&1
echo "### End. " >> $HOSTNAME.txt 2>&1

echo "주요파일 점검" >> $HOSTNAME.txt 2>&1
echo "주요파일 : /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc" >> $HOSTNAME.txt 2>&1 
echo "주요파일 : /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute " >> $HOSTNAME.txt 2>&1
echo "주요파일 : /usr/bin/lpq /usr/bin/lprm-lpd " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
FILECHECK="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

for check in $FILECHECK
do
	
if [ -f $check ]
	then
		echo "#ls -la $check" >> $HOSTNAME.txt 2>&1
		ls -la $check >> $HOSTNAME.txt 2>&1
	else
		echo "$check 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi
done

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-24] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-24] SUID, SGID, Sticky bit 설정 파일 점검 TIP											>> $HOSTNAME.txt 2>&1
echo 주요파일에 대한 권한 변경 시 제공하는 서비스에 영향을 미칠 수 있으며, 변경 시 신중하게 진행해야 함 >> $HOSTNAME.txt 2>&1
echo 링크가[lrwxrwxrwx] 연결된 파일은 SUID 설정을 할수 없으므로 대상에서 제외시킴                >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------- "  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-25]  사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"  
echo "[U-25]  사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: Owner : root또는 bin과 같은 시스템 계정 && 644 이하 일 경우 양호 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/profile ]
	then 
		echo "ls -l /etc/profile" >> $HOSTNAME.txt 2>&1
		ls -l /etc/profile >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
			if [ `ls -alL /etc/profile | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
				then
					echo "양호" >> $HOSTNAME.txt 2>&1
				else
					echo "취약" >> $HOSTNAME.txt 2>&1
			fi
		
	else
		echo "/etc/profile 파일이 존재하지 않습니다" >> $HOSTNAME.txt 2>&1
fi

if [ -f /.profile ]
	then 
		echo "ls -l /.profile" >> $HOSTNAME.txt 2>&1
		ls -l /etc/.profile >> $HOSTNAME .txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
			if [ `ls -alL /.profile | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
				then
					echo "양호" >> $HOSTNAME.txt 2>&1
				else
					echo "취약" >> $HOSTNAME.txt 2>&1
			fi
		
	else
		echo "/.profile 파일이 존재하지 않습니다" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-25] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-25] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정											>> $HOSTNAME.txt 2>&1
echo 미래창조과학부의 가이드라인기준은 소유자 root에 파일퍼미션은 644 이다.    >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-26]  world writable 파일 점검"  
echo "[U-26]  world writable 파일 점검"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: world writable 파일(777권한)이 존재하지 않거나 해당 설정 이유가 확인 가능하면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: "										 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "모든사용자가 쓰기 가능한 파일점검"									 >> $HOSTNAME.txt 2>&1 
echo "find / -xdev -perm -2 -ls" 											 >> $HOSTNAME.txt 2>&1
find / -xdev -perm -2 -ls | grep -v 'lrwxrwxrwx' | grep -v 'srwxrwxrwx' | grep -v 'srw-rw-rw-' | tail -15000    >> $HOSTNAME.txt 2>&1


echo "." >> $HOSTNAME.txt 2>&1
echo "[U-26] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-26] world writable 파일 점검 TIP											>> $HOSTNAME.txt 2>&1
echo world writable 파일은 누구나 변경가능한 파일을 뜻함 [쓰기] 권한이  모든사용자게에 포함된파일     >> $HOSTNAME.txt 2>&1
echo 단 파일의 타입이 link[lrwxrwxrwx] , soket[srwxrwxrwx] 파일은 제외한다[진단에 의미가없음 구조상 파일권한이 동일함]         >> $HOSTNAME.txt 2>&1
echo 파일 리스트는 파일 사이즈를 고려하여  15000라인까지 제한함                                                         >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-27]  /dev에 존재하지 않는 device 파일 점검"  
echo "[U-27]  /dev에 존재하지 않는 device 파일 점검"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: dev 에 존재하지 않은 device 파일을 점검하고, 존재하지 않은 device 을 제거 했을 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "find /dev -type f -exec ls -l {} \;" >> $HOSTNAME.txt 2>&1
find /dev -type f -exec ls -l {} \; >> $HOSTNAME.txt 2>&1


echo "." >> $HOSTNAME.txt 2>&1
echo "[U-27] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-27] /dev에 존재하지 않는 device 파일 점검 TIP                  >> $HOSTNAME.txt 2>&1
echo  Major Number는 많은 디바이스 드라이버 중에 하나를 구분하기 위해 쓰임   >> $HOSTNAME.txt 2>&1
echo  Minor Number는 디바이스 드라이버에서 특정한 디바이스를 가르킨다.					>> $HOSTNAME.txt 2>&1
echo  왼쪽숫자는 Major Number 이며 우축숫자는 Minor Number 이다. 					>> $HOSTNAME.txt 2>&1
echo  미래창조과학부 가이드라인에서는 이 Major, Ninor Number 을 가지고 있지 않는 파일은 잘못된  파일 혹은 사용하지 않는  >> $HOSTNAME.txt 2>&1
echo  불필요한 파일일 가능성이 높으므로 확인후  제거할것을 권고                        >> $HOSTNAME.txt 2>&1
echo 예제] -rw-r--r-- 1 root root 80 Feb  9 20:24 /dev/.udev/db/block:loop1           >> $HOSTNAME.txt 2>&1
echo 예제] 날짜 feb 월을 기준으로 왼쪽에 있는숫자가 Number 이며 하나만표시되면 Major Number 이다.    >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-28] \$HOME/.rhosts, hosts.equiv 사용 금지"  
echo "[U-28] \$HOME/.rhosts, hosts.equiv 사용 금지" >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  rsh, rlogin, rexec등을 사용하지 않으면 양호, 부득이한 경우 권한을 600으로 설정 및 특정 호스트만 사용가능하도록 설정하면 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  해당 파일이 존재하지 않아도 양호 처리" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.equiv ] 
then
	echo "#ls -l /etc/hosts.equiv" >> $HOSTNAME.txt 2>&1
	ls -l /etc/hosts.equiv >> $HOSTNAME.txt 2>&1
	
		if [ `ls -alL /etc/hosts.equiv | grep ".r.-------.*root.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "취약" >> $HOSTNAME.txt 2>&1
		fi
	
	echo "#cat /etc/hosts.equiv" >> $HOSTNAME.txt 2>&1
	cat /etc/hosts.equiv >> $HOSTNAME.txt 2>&1
else
	echo "#/etc/hosts.equiv 파일이 존재하지 않음" >> $HOSTNAME.txt 2>&1
	echo "양호" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/passwd 에 등록된 계정의 홈디렉토리 .rhosts 파일 점검" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
for dir in $HOMEDIRS
do
	
if [ -f $dir/.rhosts ]
	then
		echo "#ls -la $dir/.rhosts" >> $HOSTNAME.txt 2>&1
		ls -la $dir/.rhosts >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#cat $dir/.rhosts" >> $HOSTNAME.txt 2>&1
		cat $dir/.rhosts >> $HOSTNAME.txt
		echo " " >> $HOSTNAME.txt
	else
		echo "$dir/.rhosts 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi

done
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-28] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-28]  \$HOME/.rhosts, hosts.equiv 사용 금지											   >> $HOSTNAME.txt 2>&1
echo 미래창조과학부의 가이드라인기준은 소유자 root에 파일퍼미션은 600 이다. 				       >> $HOSTNAME.txt 2>&1
echo 또한 hosts.equiv 파일내의 + 가 포함되지 않도록해야한다. 								   >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################" >> $HOSTNAME.txt 2>&1
echo "[U-29] 접속 IP 및 포트 제한"  
echo "[U-29] 접속 IP 및 포트 제한"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/hosts.deny 파일 all deny 적용 확인 및 /etc/hosts.allow 파일에 접근 가능 서비스 및 IP가 설정되어 있으면 양호 " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 별도의 서버 접근제어 솔루션 운영 시 양호 처리 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

# TCP Wrapper configuration
echo "#rpm -qa | grep tcpd" >> $HOSTNAME.txt 2>&1
rpm -qa | grep tcpd >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.allow ] 
then
echo "#ls -la /etc/hosts.allow" >> $HOSTNAME.txt 2>&1
ls -la /etc/hosts.allow  >> $HOSTNAME.txt 2>&1  
echo " " >> $HOSTNAME.txt 2>&1  
fi

echo "#ls -la /etc/hosts.deny" >> $HOSTNAME.txt 2>&1
ls -la /etc/hosts.deny  >> $HOSTNAME.txt 2>&1  
echo " " >> $HOSTNAME.txt 2>&1  

echo "#cat /etc/hosts.allow" >> $HOSTNAME.txt 2>&1
cat /etc/hosts.allow >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1  

echo "#cat /etc/hosts.deny" >> $HOSTNAME.txt 2>&1
cat /etc/hosts.deny >> $HOSTNAME.txt 2>&1  
echo " " >> $HOSTNAME.txt 2>&1  

file=`which tcpd`
if [ -f $file ]
then
echo "#ls -la " $file >> $HOSTNAME.txt 2>&1
ls -la $file >> $HOSTNAME.txt 2>&1
else
echo $file "존재하지 않습니다." >> $HOSTNAME.txt 2>&1
fi   
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-29] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-29] 접속 IP 및 포트 제한 TIP                  >> $HOSTNAME.txt 2>&1
echo  xinetd는 기본적으로 tcp-wrapper을 내장하고있음    >> $HOSTNAME.txt 2>&1
echo  tcpd라는 tcp_wrapper의 데몬에 의해 접속 제어를 받게됨     >> $HOSTNAME.txt 2>&1
echo  tcpd - /etc/hosts.allow : 접속허용 정책 					>> $HOSTNAME.txt 2>&1
echo         /etc/hosts.deny  : 접속실패 정책                  >> $HOSTNAME.txt 2>&1
echo  즉 tcpd가 설치되지 않았거나 디렉터리가 존재하지 않는다면 tcp-wrapper을 사용하지 않는것임		>> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-30]  hosts.lpd 파일 소유자 및 권한설정"  
echo "[U-30]  hosts.lpd 파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 소유주 root또는 bin과 같은 시스템 계정  && 600 권한이면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.lpd ] 
	then
		echo "#ls -al /etc/hosts.lpd" >> $HOSTNAME.txt 2>&1
		ls -al /etc/hosts.lpd >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
			if [ `ls -alL /etc/hosts.lpd | grep ".r.-------.*.*" | wc -l` -eq 1 ]
				then
					echo "양호" >> $HOSTNAME.txt 2>&1
				else
					echo "취약" >> $HOSTNAME.txt 2>&1
			fi
		
	else
		echo "/etc/hosts.lpd 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-30] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-30] hosts.lpd 파일 소유자 및 권한설정 TIP                  >> $HOSTNAME.txt 2>&1
echo  hosts.lpd = 프린터서버에서 클라이언트를 지정하는파일     >> $HOSTNAME.txt 2>&1
echo 미래창조과학부 권고사항 소유자 root 퍼미션 600                 >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-31]  NIS서비스 비활성화"  
echo "[U-31]  NIS서비스 비활성화"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: NIS disable이거나 결과가 없으면 양호" >> $HOSTNAME.txt 2>&1	
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

echo "NIS 서비스 구동여부"   >> $HOSTNAME.txt 2>&1
ps -ef | grep yp | grep -v "grep"	>> $HOSTNAME.txt 2>&1


if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "NIS, NIS+ 서비스가 비실행중입니다." >> $HOSTNAME.txt 2>&1
   else
    ps -ef | egrep $SERVICE | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


echo "." >> $HOSTNAME.txt 2>&1
echo "[U-31] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-32]  UMASK 설정 관리"  
echo "[U-32]  UMASK 설정 관리"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  umask 설정값이 022(644권한) 이하로 설정된 경우 양호 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "Umsk 확인" >> $HOSTNAME.txt 2>&1
umask >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-32] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-33]  홈 디렉토리 소유자 및 권한 설정"  
echo "[U-33]  홈 디렉토리 소유자 및 권한 설정"  >> $HOSTNAME.txt 2>&1 
echo "[CHECK]:  홈 디렉터리 소유자가 해당 계정이고, 일반 사용자 쓰기 권한이 제거된 경우 양호 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "CENTOS, REDHOT 계열 UID 500이상 확인"     >> $HOSTNAME.txt 2>&1 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 && $3 > 500 || $3 == 500 {print $6}' | grep -wv "\/" | sort -u`
     
         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $HOSTNAME.txt 2>&1
         done
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "기타 리눅스 계열 UID 100이상 확인" >> $HOSTNAME.txt 2>&1 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 && $3 > 100 || $3 == 100 {print $6}' | grep -wv "\/" | sort -u`
         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $HOSTNAME.txt 2>&1
         done


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "# /etc/passwd 내용" >> $HOSTNAME.txt 2>&1
cat /etc/passwd >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-33] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-33] 홈 디렉토리 소유자 및 권한 설정 TIP                  >> $HOSTNAME.txt 2>&1
echo UID가 500을 넘어가는 계정을 중점 확인[그이하는 시스템 계정]     >> $HOSTNAME.txt 2>&1
echo 홈디렉터리가 존재하는 계정중 소유자, 퍼미션확인 그외사용자가 쓰기 권한을 가지면 안됨    >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------#"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-34]  홈 디렉토리로 지정한 디렉토리 존재 관리"  
echo "[U-34]  홈 디렉토리로 지정한 디렉토리 존재 관리"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 홈 디렉토리에 지정한 디렉토리가 있는지 확인하고, 불법적인 거나 의심스러운 디렉토리가 있을 경우 삭제 했을 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
for U29 in `cat /etc/passwd | awk -F: 'length($6) > 0 && $3 > 500 || $3 == 500 { print $1 }'`
	do
		if [ -d `cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'` ]
			then
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
				echo "점검 ID : $U29" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				TMP_HOMEDIR=`cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'`
				TMP_HOMEDIR2=`cat /etc/passwd | grep $U29 | awk -F: '{ print $3 }'`
				echo "홈 디렉토리 : $TMP_HOMEDIR" >> $HOSTNAME.txt 2>&1
				echo "계정의 UID : $TMP_HOMEDIR2" >> $HOSTNAME.txt 2>&1
			   	echo " " >> $HOSTNAME.txt 2>&1
				echo "/etc/passwd에 설정된 디렉토리 $TMP_HOMEDIR 존재.양호" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
			else
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
				echo "점검 ID : $U29" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				TMP_HOMEDIR=`cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'`
				echo "홈 디렉토리 : $TMP_HOMEDIR" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "/etc/passwd에 설정된 디렉토리 $TMP_HOMEDIR 없음.취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
		fi
done
echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-34] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-35]  숨겨진 파일 및 디렉토리 검색 및 제거"  
echo "[U-35]  숨겨진 파일 및 디렉토리 검색 및 제거"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  의심스런 숨겨진 파일 및 디렉토리가 없을시 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  관리자 리뷰 후 양호, 취약 판단 불가할시 N/A 처리" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "find / -xdev -name ".. " -ls" >> $HOSTNAME.txt 2>&1
find / -xdev -name ".. " -ls  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "find / -name ".*" -ls" >> $HOSTNAME.txt 2>&1
find / -xdev -name ".*" -ls  >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-35] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-35] 숨겨진 파일 및 디렉토리 검색 및 제거 TIP                  >> $HOSTNAME.txt 2>&1
echo 의심스러운 숨겨진 파일을 찾는다.                                  >> $HOSTNAME.txt 2>&1
echo 리눅스나 유닉스에서는 파일의 최초생성날짜는 기록되지 않는다.                                    >> $HOSTNAME.txt 2>&1
echo 최근 날짜에서 변동된 파일 및 소유자 그룹 권한이 알수없는 사용자가 포함된 파일 위주로 분석       >> $HOSTNAME.txt 2>&1  
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-36] Finger 서비스 비활성화"  
echo "[U-36] Finger 서비스 비활성화"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: Finger 항목이 Disable되어 있거나 결과값이 없을 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ls -alL /etc/xinetd.d | egrep finger | wc -l` -gt 0 ]
  then
     ls -alL /etc/xinetd.d/finger >> $HOSTNAME.txt 2>&1
	 echo "#cat/etc/xinetd.d/finger | grep -i "disable""	 >> $HOSTNAME.txt 2>&1
	 echo "." >> $HOSTNAME.txt 2>&1
     cat /etc/xinetd.d/finger | grep -i "disable" >> $HOSTNAME.txt 2>&1
     echo "   " >> $HOSTNAME.txt 2>&1
  else
      echo "xinetd.d에 finger파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi

echo "netstat -na | grep tcp | grep 79 | grep LISTEN"  [79번포트 확인] >> $HOSTNAME.txt 2>&1
netstat -na | grep tcp | grep 79 | grep LISTEN         >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "chkconfig --list [서비스 구동상태확인]"                                 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
chkconfig --list                                     >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-36] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-36] Finger 서비스 비활성화[TIP]                                       >> $HOSTNAME.txt 2>&1
echo finger-server가 구동되면 TCP 79번 포트가 오픈되며                        >> $HOSTNAME.txt 2>&1
echo /etc/xinetd.d/finger 파일이 생성된다                                    >> $HOSTNAME.txt 2>&1
echo 해당 항목은 finger-server 가 구동되었는지를 뭍는 질문이기때문에          >> $HOSTNAME.txt 2>&1
echo 79번포트의 상태와 /etc/xinetd.d/finger 파일의 존재여부를 확인해야함 			 >> $HOSTNAME.txt 2>&1
echo /etc/xinetd.d/finger 파일의 DISABLE = YES로 설정되어있다면 양호함                           >> $HOSTNAME.txt 2>&1
echo 항목의 취지는 원격지에서 finger root@192.168.232.135 와 같은 명령으로                       >> $HOSTNAME.txt 2>&1
echo 원격지에서 79번포트를 이용하여 계정정보를 탐색할수있는 행위를 차단하기위함                  >> $HOSTNAME.txt 2>&1
echo 즉 finger 포트인 79번 포트의 LISTEN을 차단해야함                                            >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-37] Anonymous FTP 비활성화" 
echo "[U-37] Anonymous FTP 비활성화" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : anonymous FTP 접속을 차단한 경우 양호, /etc/passwd 파일에 ftp 계정 존재시 취약" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : vsFTPD의 경우 anonymous_enable 옵션이 NO로 설정되면 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : TCP 21번 포트가 오픈되지 않았을 경우 N/A처리" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "netstat -na | grep tcp | grep 21 | grep LISTEN"  [21번포트 확인] >> $HOSTNAME.txt 2>&1
netstat -na | grep tcp | grep 21 | grep LISTEN         >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "일반 FTP 및 ProFTP 확인 (ftp 계정유무 확인)" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/passwd | grep ftp" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | grep ftp >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "vsFTP 확인" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/vsftpd/vsftpd.conf" >> $HOSTNAME.txt 2>&1
cat /etc/vsftpd/vsftpd.conf  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/vsftpd.conf" >> $HOSTNAME.txt 2>&1
cat /etc/vsftpd.conf >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-37] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-38]  r계열 서비스 비활성화"  
echo "[U-38]  r계열 서비스 비활성화"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] :rsh, rlogin, rexec (shell, login, exec) 서비스가 비활성화 되어있거나 결과값이 없을경우에 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
SERVICE_INETD="rsh|rlogin|rexec"

echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/xinetd.d 내용 " >> $HOSTNAME.txt 2>&1
echo "------------------ " >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $HOSTNAME.txt 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $HOSTNAME.txt 2>&1
         echo "   " >> $HOSTNAME.txt 2>&1
        done
  else
      echo "xinetd.d에 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/inet 내용 " >> $HOSTNAME.txt 2>&1
echo "------------------ " >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/inet | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/inet | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV 파일" >> $HOSTNAME.txt 2>&1
         cat /etc/inet/$VVV >> $HOSTNAME.txt 2>&1
         echo "   " >> $HOSTNAME.txt 2>&1
        done
  else
      echo "inet에 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/xinetd.d or inetd.conf의 설정 " >> $HOSTNAME.txt 2>&1

SERVICE_INETD="shell|login|exec"

if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


if [ -d /etc/xinetd.d ]
  then
   SERVICE_INETD="rsh|rlogin|rexec"
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | awk '{print $9}'`
        do
        if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "취약" >> $HOSTNAME.txt 2>&1
          else
           echo "양호" >> $HOSTNAME.txt 2>&1
        fi
        done
    else
      echo "양호" >> $HOSTNAME.txt 2>&1
    fi
 elif [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
     then
        echo "양호"    >> $HOSTNAME.txt 2>&1
     else
        echo "취약"    >> $HOSTNAME.txt 2>&1
    fi
  else
     echo "양호"        >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "chkconfig --list [서비스상태확인]"		>> $HOSTNAME.txt 2>&1
chkconfig --list					 >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1

echo "추가 확인 : 512(rexec), 513(rlogin), 514(rsh) 포트 오픈 확인" >> $HOSTNAME.txt 2>&1
echo "#netstat -an | grep tcp | grep 512 | grep listen" >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 512 | grep listen >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#netstat -an | grep tcp | grep 513 | grep listen" >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 513 | grep listen >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#netstat -an | grep tcp | grep 514 | grep listen" >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 514 | grep listen >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-38] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-38] r계열 서비스 비활성화[TIP]                                                         >> $HOSTNAME.txt 2>&1
echo rsh-server 을 설치하게되면 /etc/xinetd.d/rsh , rlogin, rexe 가 설치되며                   >> $HOSTNAME.txt 2>&1
echo 구동시 포트가 각각 오픈된다 포트번호는 아래와 같다.                                       >> $HOSTNAME.txt 2>&1
echo TCP 512번포트 = rexec 서비스[etc/xinetd.d/rexec                                           >> $HOSTNAME.txt 2>&1
echo TCP 513번포트 = rlogin 서비스[etc/xinetd.d/rlogin               			       >> $HOSTNAME.txt 2>&1
echo TCP 514번포트 = rsh 서비스[etc/xinetd.d/rsh                                               >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-39]  cron파일 소유자 및 권한 설정"  
echo "[U-39]  cron파일 소유자 및 권한  설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : cron.allow 및 cron.deny 파일의 권한이 640미만으로 설정되어 있으면 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : cron.allow파일이 존재할 경우 cron.deny 파일은 없어도 무방" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#ls -al /etc/cron.allow" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
ls -al /etc/cron.allow >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#ls -al /etc/cron.deny" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
ls -al /etc/cron.deny >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-39] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-40]  DoS 공격에 취약한 서비스 비활성화"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] :echo, discard, daytime, chargen 서비스가 비활성화 되어있거나 결과값이 없을경우에 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]"                                                                               >> $HOSTNAME.txt 2>&1
echo " "											       >> $HOSTNAME.txt 2>&1
echo "DOS_INETD=echo|discard|daytime|chargen"							       >> $HOSTNAME.txt 2>&1
echo " "												>> $HOSTNAME.txt 2>&1
DOS_INETD="echo|discard|daytime|chargen"

echo "#ls -ail /etc/xinetd.d"                                                                             >> $HOSTNAME.txt 2>&1
if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d | egrep $DOS_INETD | wc -l` -eq 0 ]
      then
        echo " /etc/xinetd.d 디렉토리에 DOS공격에 취약한 서비스가 없음" >> $HOSTNAME.txt 2>&1
      else
        ls -alL /etc/xinetd.d | egrep $DOS_INETD >> $HOSTNAME.txt 2>&1
    fi
  else
     echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/inetd.conf ]
  then
	echo "# cat /etc/inetd.conf | grep -v '^ *#' | egrep $DOS_INETD" >> $HOSTNAME.txt 2>&1
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $DOS_INETD >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/inetd.conf 파일이 존재하지 않음 " >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "7 9 13 19번 포트 LISTEN상태확인"			>> $HOSTNAME.txt 2>&1
netstat -na | grep ":7 " | grep LISTEN | grep tcp           >> $HOSTNAME.txt 2>&1
netstat -na | grep ":9 " | grep LISTEN | grep tcp           >> $HOSTNAME.txt 2>&1
netstat -na | grep ":13 " | grep LISTEN | grep tcp          >> $HOSTNAME.txt 2>&1
netstat -na | grep ":19 " | grep LISTEN | grep tcp          >> $HOSTNAME.txt 2>&1
echo "/etc/services 내용 " >> $HOSTNAME.txt 2>&1
echo "----------------------------------- " >> $HOSTNAME.txt 2>&1
cat /etc/services | egrep $DOS_INETD >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-40] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1





echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"			      >> $HOSTNAME.txt 2>&1
echo [U-40] DoS 공격에 취약한 서비스 비활성화[TIP]								      >> $HOSTNAME.txt 2>&1
echo "먼저 해당서비스를 설치하려면 rsh-server 패키지를설치해야하며 서비스를 구동하게되면 각각의 "                     >> $HOSTNAME.txt 2>&1
echo "포트들이 오픈되게 되는데 이포트를 통해 DOS 공격을 시도될수있다.PORT가 오픈되지 않으면 DOS공격을 할수없음"       >> $HOSTNAME.txt 2>&1
echo "먼저 가장먼저 봐야할것은 서비스 포트가 오픈되어있는지 확인후 서비스구동여부를 확인한다. "                       >> $HOSTNAME.txt 2>&1
echo "/etc/xinetd.d/경로에서 파일을 DISABLE 설정하던가 /etc/service 에서 서비스를 주석처리하여 차단해도된다"          >> $HOSTNAME.txt 2>&1
echo "중요한것은 포트가 구동되어있으면 안된다."									      >> $HOSTNAME.txt 2>&1
echo "echo      = TCP와 UDP 소통을 위해 7번포트를 사용하며 이것은 디버깅 및 측량 도구로 구현되었으며"			>> $HOSTNAME.txt 2>&1
echo "수신한 데이터를 송신한 호스트로 돌려 보내는 작업을 수행, 따라서 서비스 거부 공격 가능성이 매우높음"                   >> $HOSTNAME.txt 2>&1
echo "daytime	= time과 같은 기능을 수행하지만 사람이 읽기 쉬운 형태로 제공하는 것이 다름, 이서비스는 13번포트에서 실행 "   >> $HOSTNAME.txt 2>&1                                                  
echo "chargen    = 19번 포트에서 동작하며 tcp와udp를 사용함 tcp에서 동작하는 동안 연결을 기다리다가 연결이되면 연결을 요청한" >> $HOSTNAME.txt 2>&1
echo " 곳에서 연결을 끊을 때까지 데이터 스트림을 계속 송신한다. udp 상에서 동작할 경우에는 데이터 그램이 수신되기를 "        >> $HOSTNAME.txt 2>&1
echo "기다린다. 하나의 데이터그램이 수신되면0~512개 문자로 이루어진 데이터 그램으로 응답한다. 서비스 거부 공격에 자주 사용"  >> $HOSTNAME.txt 2>&1
echo "discard    = 9번 포트를 통해서 TCP 및 UDP 에서 동작 이것은 디버깅 도구로서 개발되었다. 서비스 용도는 수신하는 모든 데이터를 버리는 것이다."    >> $HOSTNAME.txt 2>&1                                                                             >> $HOSTNAME.txt 2>&1
echo "/etc/service 에서 서비스를 주석처리하였다면 반드시 xinetd 서비스를 재시작해야 포트가 내려간다."			  >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"                         >> $HOSTNAME.txt 2>&1
echo " "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-41]  NFS 서비스 비활성화"  
echo "[U-41]  NFS 서비스 비활성화"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "프로세스 구동상태확인"			   >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep mountd | grep -v grep"			   >> $HOSTNAME.txt 2>&1
ps -ef | grep mountd | grep -v grep				   >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep nfsd | grep -v grep [nfs서버]"			   >> $HOSTNAME.txt 2>&1
ps -ef | grep nfsd | grep -v grep					  >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep statd | grep -v grep"			  >> $HOSTNAME.txt 2>&1
ps -ef | grep statd | grep -v grep					  >> $HOSTNAME.txt 2>&1
echo "nfs 서비스포트 확인"			 >> $HOSTNAME.txt 2>&1
echo "netstat -na | grep :2049 | grep LISTEN"   >> $HOSTNAME.txt 2>&1
netstat -na | grep :2049 | grep LISTEN		 >> $HOSTNAME.txt 2>&1
echo "rpcinfo 확인"				>> $HOSTNAME.txt 2>&1
rpcinfo -p localhost				>> $HOSTNAME.txt 2>&1

echo "[U-41] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-42]  NFS 접근통제"  
echo "[U-42]  NFS 접근통제" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : NFS 사용시 everyone 공유를 제한한 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep "nfs" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
 then
  if [ -f /etc/exports ]
   then
    grep -v '^ *#' /etc/exports  >> $HOSTNAME.txt 2>&1
   else
    echo "/etc/exports 파일이 존재하지 않음"  >> $HOSTNAME.txt 2>&1
  fi
 else
  echo "NFS 서비스가 비실행중입니다." >> $HOSTNAME.txt 2>&1
fi


echo " " >> $HOSTNAME.txt 2>&1


if [ `ps -ef | egrep "nfs" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "양호" >> $HOSTNAME.txt 2>&1
 else
  if [ -f /etc/exports ]
    then
     if [ `cat /etc/exports | grep everyone | grep -v "^ *#" | wc -l` -eq 0 ]
       then
         echo "양호" >> $HOSTNAME.txt 2>&1
       else
         echo "취약" >> $HOSTNAME.txt 2>&1
     fi
    else
     echo "/etc/exports 파일이 없습니다."  >> $HOSTNAME.txt 2>&1
  fi
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "############ 아래 내용 참고 ##############" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/dfs/dfstab" >> $HOSTNAME.txt 2>&1
cat /etc/dfs/dfstab >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-42] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-43]  automountd 제거"  
echo "[U-43]  automountd 제거"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : automountd이 나오지 않으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo "  " >> $HOSTNAME.txt 2>&1
echo "automountd 확인 " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep automountd | egrep -v "grep|rpc|statdaemon|emi" | grep -v grep | wc -l` -eq 0 ]
  then
    echo "automount 데몬이 없습니다." >> $HOSTNAME.txt 2>&1
  else
     ps -ef | grep automountd | egrep -v "grep|rpc|statdaemon|emi" | grep -v grep >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


if [ `ps -ef | grep automountd | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "양호" >> $HOSTNAME.txt 2>&1
  else
     echo "취약" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "automount 프로세스 확인"   >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep automount | grep -v grep"   >> $HOSTNAME.txt 2>&1
ps -ef | grep automount | grep -v grep         >> $HOSTNAME.txt 2>&1
echo "[U-43] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-43]  automountd 제거[TIP]                                                         >> $HOSTNAME.txt 2>&1
echo automountd를 구동하기위해선 autofs 패키지를 설치해야한다.                    >> $HOSTNAME.txt 2>&1
echo automountd 가 구동되어있다면 대게 rpc서비스와 nfs 서비스와 필수적으로 관련되기때문에 해당프로세스가 구동되어있을 확률이높다. >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-44] RPC 서비스 확인"
echo "[U-44] RPC 서비스 확인" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 불필요한 rpc 관련 서비스가 존재하지 않으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "SERVICE_INETD=rpc.sprayd|rpc.rstatd|rpc.rexd|rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd|rpc.rwalld|rpc.rusersd
" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
SERVICE_INETD="rpc.sprayd|rpc.rstatd|rpc.rexd|rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd|rpc.rwalld|rpc.rusersd
"

if [ -d /etc/xinetd.d ]
  then
    if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -eq 0 ]
      then
        echo " /etc/xinetd.d 디렉토리에 불필요한 서비스가 없음" >> $HOSTNAME.txt 2>&1
      else
        ls -alL /etc/xinetd.d | egrep $SERVICE_INETD >> $HOSTNAME.txt 2>&1
    fi
  else
     echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/inetd.conf ]
  then
	echo "# cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD" >> $HOSTNAME.txt 2>&1
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/inetd.conf 파일이 존재하지 않음 " >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1


echo " " > rpc.txt

SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|rusersd|walld|sprayd|rstatd|rpc.nisd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd|rexd"

if [ -d /etc/xinetd.d ]
  then
   if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
       for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD`
        do
        if [ `cat $VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
          then
           echo "취약" >> rpc.txt
          else
           echo "양호" >> rpc.txt
        fi
        done
    else
      echo "양호" >> rpc.txt
    fi
fi

if [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
              then
                 echo "양호" >> rpc.txt
              else
                 echo "취약" >> rpc.txt
    fi
fi


if [ `cat rpc.txt | grep "취약" | wc -l` -eq 0 ]
 then
  echo "양호" >> $HOSTNAME.txt 2>&1
 else
  echo "취약" >> $HOSTNAME.txt 2>&1
fi

rm -rf rpc.txt

echo "프로새스 내용 확인 " >> $HOSTNAME.txt 2>&1
echo "ls -ail /etc/xinetd.d"  >> $HOSTNAME.txt 2>&1
ls -alL /etc/xinetd.d  >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-44] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-44] RPC 서비스 확인[TIP]                                                                     >> $HOSTNAME.txt 2>&1
echo 리눅스는 inetd.conf파일에 설정되어있는 방식과 /etc/xinetd.d/ 디렉토리안에 파일형태로 설정되어있는 2가지 방식이 존재한다.  >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-45]  NIS, NIS+ 점검"  
echo "[U-45]  NIS, NIS+ 점검 작성 필요"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: NIS disable이거나 결과가 없으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "NIS, NIS+ 서비스가 비실행중입니다." >> $HOSTNAME.txt 2>&1
   else
    echo "#ps -ef | egrep \$SERVICE | grep -v grep" >> $HOSTNAME.txt 2>&1
    ps -ef | egrep $SERVICE | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
     then
        echo "양호" >> $HOSTNAME.txt 2>&1
     else
        echo "취약" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "구동프로세스 찾기[ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd]"  >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep 프로세스명 | grep -v grep"  >> $HOSTNAME.txt 2>&1
ps -ef | grep ypserv | grep -v grep   >> $HOSTNAME.txt 2>&1
ps -ef | grep ypbind | grep -v grep   >> $HOSTNAME.txt 2>&1
ps -ef | grep ypxfrd | grep -v grep    >> $HOSTNAME.txt 2>&1
ps -ef | grep rpc.yppasswdd | grep -v grep >> $HOSTNAME.txt 2>&1
ps -ef | grep rpc.ypupdated | grep -v grep >> $HOSTNAME.txt 2>&1
ps -ef | grep rpc.nisd  | grep -v grep    >> $HOSTNAME.txt 2>&1
echo "[U-45] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-46] Tftp, Talk 활성화 여부"  
echo "[U-46] Tftp, Talk 활성화 여부"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: tftp , tallk 서비스를 비활성화 시켰을 경우 양호  " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "Tftp 확인" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/inetd.conf ]
	then
		echo "#grep tftp /etc/inetd.conf" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		grep tftp /etc/inetd.conf >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#ps -ef | grep tftp | grep -v grep" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		ps -ef | grep tftp | grep -v grep >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/inetd.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1
echo " " >>$HOSTNAME.txt 2>&1
fi
if [ -f /etc/xinetd.conf ]
	then
		echo "#grep tftp /etc/xinetd.conf" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		grep tftp /etc/xinetd.conf >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
			echo "#ps -ef | grep tftp | grep -v grep" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			ps -ef | grep tftp | grep -v grep >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/xinetd.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1	
	echo " " >> $HOSTNAME.txt 2>&1			
fi
echo "tftp 프로세스 및 구동 상태 확인"  >> $HOSTNAME.txt 2>&1
echo "ls -al /etc/xinetd.d | grep tftp"              >> $HOSTNAME.txt 2>&1
ls -al /etc/xinetd.d | grep tftp                   >> $HOSTNAME.txt 2>&1
echo "netstat -al | grep tftp"			  >> $HOSTNAME.txt 2>&1
netstat -al | grep tftp				>> $HOSTNAME.txt 2>&1
echo "netstat -na | grep :69 | grep udp"	 >> $HOSTNAME.txt 2>&1
netstat -na | grep :69 | grep udp                  >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "Talk 확인" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf ]
	then
		echo "#grep talk /etc/inetd.conf" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		grep talk /etc/inetd.conf >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#ps -ef | grep tftp | grep -v grep" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		ps -ef | grep talk | grep -v grep >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/inetd.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
echo " " >>$HOSTNAME.txt 2>&1
fi

if [ -f /etc/xinetd.conf ]
	then
		echo "#grep talk /etc/xinetd.conf" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		grep talk /etc/xinetd.conf >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
			echo "#ps -ef | grep talk | grep -v grep" >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
			ps -ef | grep talk | grep -v grep >> $HOSTNAME.txt 2>&1
			echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/xinetd.conf 파일이 없습니다" >> $HOSTNAME.txt 2>&1	
		echo " " >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1

echo "talk 프로세스 및 구동 상태 확인"  >> $HOSTNAME.txt 2>&1
echo "ls -al /etc/xinetd.d | grep talk"              >> $HOSTNAME.txt 2>&1
ls -al /etc/xinetd.d | grep talk                   >> $HOSTNAME.txt 2>&1
echo "netstat -al | grep talk"			  >> $HOSTNAME.txt 2>&1
netstat -al | grep talk				>> $HOSTNAME.txt 2>&1
echo "netstat -na | grep :517 | grep udp"	 >> $HOSTNAME.txt 2>&1
netstat -na | grep :517 | grep udp                  >> $HOSTNAME.txt 2>&1




echo "[U-46] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-47] Sendmail 버전 점검"
echo "[U-47] Sendmail 버전 점검"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : sendmail 버전 확인 후 최신버전과 비교(2013년5월기준 최신버전 8.13.8 이상 권고)" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE] : " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "sendmail 프로세스 확인" >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "Sendmail 서비스가 비실행중입니다.양호" >> $HOSTNAME.txt 2>&1
  touch sendmail_tmp 
 else
  ps -ef | grep sendmail | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
if [ -f sendmail_tmp ]
	then
	echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "sendmail 버전확인" >> $HOSTNAME.txt 2>&1
		if [ -f /etc/mail/sendmail.cf ]
			then
				grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $HOSTNAME.txt 2>&1
			else
				echo "/etc/mail/sendmail.cf 파일 없음" >> $HOSTNAME.txt 2>&1
		fi
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "sendmail 설치여부 및 설정파일 확인"   >> $HOSTNAME.txt 2>&1
echo "rpm -qa sendmail"                     >> $HOSTNAME.txt 2>&1
rpm -qa sendmail                            >> $HOSTNAME.txt 2>&1
echo "ls -al /etc/mail | grep "sendmail""   >> $HOSTNAME.txt 2>&1
ls -al /etc/mail | grep "sendmail"  >> $HOSTNAME.txt 2>&1
echo "netstat -na | grep LISTEN | grep tcp | grep :25"    >> $HOSTNAME.txt 2>&1
netstat -na | grep LISTEN | grep tcp | grep :25          >> $HOSTNAME.txt 2>&1
echo "postfix 메일서버 구동여부"                           >> $HOSTNAME.txt 2>&1
echo "rpm -qa postfix"                                       >> $HOSTNAME.txt 2>&1
rpm -qa postfix                                               >> $HOSTNAME.txt 2>&1

echo "[U-47] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-47] Sendmail 버전 점검[TIP]                                                                     >> $HOSTNAME.txt 2>&1
echo Sendmail이 설치되지 않았는데 25번포트를 LISTEN하고 있다면 CentOS6, REDHOT 최신버전은 sendmail이 아닌 postfix 라는 메일서비스를 사용함   >> $HOSTNAME.txt 2>&1
echo postfix 는 구조자체가 Sendmail과 다르므로 Sendmail 항목과 맞춰서 진단하기는 곤란함  N/A처리함      >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-48]  스팸 메일 릴레이 제한"  
echo "[U-48]  스팸 메일 릴레이 제한"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 스팸 메일 릴레이 방지 설정을 한 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/mail/access 정책확인" >> $HOSTNAME.txt 2>&1 

if [ -f sendmail_tmp ]
	then
		echo "Sendmail 서비스가 비실행 중입니다" >> $HOSTNAME.txt
		echo " " >> $HOSTNAME.txt
	else
		if [ -f /etc/mail/access ]
			then
				echo "#cat /etc/mail/access" >> $HOSTNAME.txt 2>&1
				cat /etc/mail/access >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
			else
				echo "/etc/mail/access 파일이 없습니다.취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
fi
	
echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/mail/sendmail.cf 정책설정확인" 											>> $HOSTNAME.txt 2>&1 
echo "/etc/mail/sendmail.cf | egrep REJECT|OK|RELAY" >> $HOSTNAME.txt 2>&1
cat /etc/mail/sendmail.cf | egrep "REJECT|OK|RELAY" >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "."													 >> $HOSTNAME.txt 2>&1
echo "아래 /etc/mail/sendmail.cf 파일내에 라인에 Addr=127.0.0.1 구문이 없거나 0.0.0.0으로 되어있다면  모든 IP를 허용함으로 취약함 "					 >> $HOSTNAME.txt 2>&1
echo "cat /etc/mail/sendmail.cf | grep O DaemonPortOptions"							>> $HOSTNAME.txt 2>&1
cat /etc/mail/sendmail.cf | grep "O DaemonPortOptions"								  >> $HOSTNAME.txt 2>&1
echo "[U-48] End"												>> $HOSTNAME.txt 2>&1
echo " "													 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo [U-48]  스팸 메일 릴레이 제한[TIP]											>> $HOSTNAME.txt 2>&1
echo "일부 relay 를 풀어 주기 위해서 sendamil.cf 를 변경 하는 사람들이 있는데 이럴 경우 spammer 들의 표적이 되어  "		>> $HOSTNAME.txt 2>&1
echo "다른 메일 서버로 부터 reject 을 당할수가 있으니 sendmail.cf 를 변경하여 전체 relay 를 푸면 안됨."	 >> $HOSTNAME.txt 2>&1
echo "OK = [host에서지정된] 메일의 모든것을 허용[relay]한다. "									>> $HOSTNAME.txt 2>&1
echo "RELAY = [host에서지정된]메일의 수신/발신을 허용한다."									>> $HOSTNAME.txt 2>&1
echo "REJECT = [host에서지정된]메일의 수신/발신을 거부한다."									>> $HOSTNAME.txt 2>&1
echo "DISCARD = /etc/sendmail.cf에 시정된 $#discard mailer에 지정된곳으로 메일을 폐기함.(발신자는 메일일 발신된것으로 알게됨."  >> $HOSTNAME.txt 2>&1
echo "501 <message> 지정된 user@host 와 발신자의 주소가 전체 혹은 부분적으로 일치할 경우 이메일을 받지 않는다. "			 >> $HOSTNAME.txt 2>&1
echo "553 <message> 발신자의 주소에 호스트명이 없을 경우 메일을 받지 않는다."							>> $HOSTNAME.txt 2>&1
echo "550 <message> 지정된 도메인과 관련된 메일을 받지 않는다."									>> $HOSTNAME.txt 2>&1
echo "보통 아주 간단한 예로서 111.111.111.111 이라는 pc 에서 메일을 발송하기를 원한다면"					 >> $HOSTNAME.txt 2>&1
echo "111.111.111.111		RELAY"												 >> $HOSTNAME.txt 2>&1
echo "라는 한줄을 설정해 주는 것으로 메일을 발송을 할수 있다."									 >> $HOSTNAME.txt 2>&1
echo "예제]  cyberspammer.com        REJECT"											 >> $HOSTNAME.txt 2>&1
echo "예제]  sendmail.org            OK"  										 >> $HOSTNAME.txt 2>&1
echo "예제]  128.32                  RELAY"											 >> $HOSTNAME.txt 2>&1
echo "예제]  localhost.localdomain   RELAY"											 >> $HOSTNAME.txt 2>&1
echo "예제]  localhost               RELAY"											 >> $HOSTNAME.txt 2>&1
echo "예제]   127.0.0.1              RELAY"											 >> $HOSTNAME.txt 2>&1
echo "예제]  linux.rootman.org                     REJECT"                                >> $HOSTNAME.txt 2>&1
echo "예제]  linux.rootman.org                     501 Oh.. No.. linux.rootman.org"                                             >> $HOSTNAME.txt 2>&1
echo "예제]  linux.rootman.org                     571 You are spammer.. "                                                     >> $HOSTNAME.txt 2>&1
echo "/etc/mail/access 에서 RELAY 설정을 마친 후에는 access.db 를 갱신해 줘야 한다."						 >> $HOSTNAME.txt 2>&1
echo "makemap hash /etc/mail/access < /etc/mail/access"									   >> $HOSTNAME.txt 2>&1
echo "명령을 실행하여 갱신을 할수가 있다. access 파일을 수정시에는 sendmail을 재시작 할"					   >> $HOSTNAME.txt 2>&1
echo "필요는 없으며 makemap 을 이용하여 access.db 만 갱신해 주면 바로 적용이 된다."						  >> $HOSTNAME.txt 2>&1
echo "DB에 정상적으로 저장되었는지 확인하는 명령어는 다음과 같다 strings access.db | grep 192"					 >> $HOSTNAME.txt 2>&1
echo "---------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-49]  일반사용자의 Sendmail 실행 방지"  
echo "[U-49]  일반사용자의 Sendmail 실행 방지"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : sendmail 설정 파일이 PrivacyOptions=authwarnings,restrictqrun 으로 설정되어 있으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
	then
		echo "Sendmail 서비스가 비실행 중입니다.양호" >> $HOSTNAME.txt 2>&1
	else
		echo "#/etc/mail/sendmail.cf 파일의 옵션 확인" >> $HOSTNAME.txt 2>&1
			if [ -f /etc/mail/sendmail.cf ]
				then
					    if [ `cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn|restrictqrun" | grep -v "grep" | wc -l ` -eq 1 ]
							then
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn|restrictqrun" | grep -v "grep" >> $HOSTNAME.txt 2>&1
								echo " " >> $HOSTNAME.txt 2>&1
							else
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn|restrictqrun" | grep -v "grep" >> $HOSTNAME.txt 2>&1	
								echo "취약" >> $HOSTNAME.txt 2>&1
						fi
				else
					echo "/etc/mail/sendmail.cf 파일 없음." >> $HOSTNAME.txt 2>&1
					echo " " >> $HOSTNAME.txt 2>&1
			fi
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-49] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-50] DNS 보안 버전 패치"  
echo "[U-50] DNS 보안 버전 패치"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 다음 이외의 BIND 버전을 사용하면 취약(8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: DNS서비스가 동작하지 않을 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#ps -ef | grep named | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep named | grep -v grep >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "#named -v" >> $HOSTNAME.txt 2>&1
named -v >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-50] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-51]  DNS ZoneTransfer 설정"  
echo "[U-51]  DNS ZoneTransfer 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : zone 영역 전송이 특정 호스트로 제한 (allow-transfer { IP; }) 되어 있거나 options xfrnets IP가 설정되어 있다면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "<DNS 프로세스 확인> " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "DNS가 비실행중입니다." >> $HOSTNAME.txt 2>&1
  else
    ps -ef | grep named | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/named.conf 파일의 allow-transfer 확인" >> $HOSTNAME.txt 2>&1
   if [ -f /etc/named.conf ]
     then
      cat /etc/named.conf | grep 'allow-transfer' >> $HOSTNAME.txt 2>&1
     else
      echo "/etc/named.conf 파일 없음" >> $HOSTNAME.txt 2>&1
   fi

echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/named.boot 파일의 xfrnets 확인" >> $HOSTNAME.txt 2>&1
   if [ -f /etc/named.boot ]
     then
       cat /etc/named.boot | grep "\xfrnets" >> $HOSTNAME.txt 2>&1
     else
       echo "/etc/named.boot 파일 없음" >> $HOSTNAME.txt 2>&1
   fi

echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "양호" >> $HOSTNAME.txt 2>&1
  else
     if [ -f /etc/named.conf ]
       then
         if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "^ *#" | wc -l` -eq 0 ]
            then
               echo "취약" >> $HOSTNAME.txt 2>&1
            else
               echo "양호" >> $HOSTNAME.txt 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
           then
             if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "^ *#" | wc -l` -eq 0 ]
            then
               echo "취약" >> $HOSTNAME.txt 2>&1
            else
               echo "양호" >> $HOSTNAME.txt 2>&1
            fi
           else
              echo "취약" >> $HOSTNAME.txt 2>&1
          fi

     fi
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-51] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-52]  Apache 디렉토리 리스팅 제거"  
echo "[U-52]  Apache 디렉토리 리스팅 제거)"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 디렉토리 리스팅 옵션(Indexes)가 모든 디렉토리에서 제거 되어 있을 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
	     ps -ef | grep httpd | grep -v "grep"   >> $HOSTNAME.txt 2>&1
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 요청 후 진단 수행" >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-52] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-53]  Apache 웹 프로세스 권한 제한"  
echo "[U-53]  Apache 웹 프로세스 권한 제한"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 초기 구동된 httpd 데몬을 제외한 웹 프로세스의 소유자가 Root가 아닐경우 && 웹 프로세스 계정이 \bin\false 또는 nologin일 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 요청 후 진단 수행" >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-53] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "##################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-54]  Apache 상위 디렉토리 접근 금지"  
echo "[U-54]  Apache 상위 디렉토리 접근 금지"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : AllowOverride 지시자의 옵션이 None 이면 취약, AuthConfig 면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 및 인증 설정할 디렉토리의 .htaccess 파일 요청 후 진단 또는 수동진단 수행" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-54] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-55]  Apache 불필요한 파일 제거"  
echo "[U-55]  Apache 불필요한 파일 제거"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 매뉴얼 파일 및 디렉터리가 제거되어 있는 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "[Apache_home]/htdocs/manual 및 [Apache_home]/manual 파일 제거 여부 직접 확인" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-55] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-56]  Apache 링크 사용금지"  
echo "[U-56]  Apache 링크 사용금지"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : Options 중 FollowSymLinks가 제거 되어 있으면 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 요청 후 진단 수행" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-56] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-57]  Apache 파일 업로드 및 다운로드 제한"  
echo "[U-57]  Apache 파일 업로드 및 다운로드 제한 작성 필요"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 파일 업로드 및 다운로드 용량을 모든디렉토리에서 제한시 양호. 설정값이 없을시 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 요청 후 진단 수행" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-57] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-58]  Apache 웹 서비스 영역의 분리"  
echo "[U-58]  Apache 웹 서비스 영역의 분리"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : DocumentRoot가 /usr/local/apache/htdocs가 아닐 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 요청 후 진단 수행" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-58] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-59] ssh 원격접속 허용"  
echo "[U-59] ssh 원격접속 허용"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 원격 접속 시 SSH 프로토콜을 사용하는 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 위 판단기준을 적용하기 모호한 경우 22번 포트가 오픈되어 있으면 양호 처리" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#ps -ef | grep telnet | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep -v grep | grep telnet >> $HOSTNAME.txt 2>&1



echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "netstat -an | grep tcp | grep 23" >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 23 >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1




echo "#ps -ef | grep ssh | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep -v grep | grep ssh >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo "netstat -an | grep tcp | grep 22" >> $HOSTNAME.txt 2>&1
netstat -an | grep tcp | grep 22 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-59] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-59]  ssh 원격접속 허용 TIP										             	>> $HOSTNAME.txt 2>&1
echo "telnet 서비스가 존재한다면 ssh 를 사용하지 않고 telnet 사용여지를 남겨두는것이므로 확인필요함"  >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo " "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1





echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-60] ftp 서비스 확인"
echo "[U-60] ftp 서비스 확인" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: FTP 서비스가 비활성화 되어 있는 경우 양호  " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "21번포트 LISTEN 상태 확인" >> $HOSTNAME.txt 2>&1 
echo "netstat -na | grep 21 | grep LISTEN | grep tcp"   >>  $HOSTNAME.txt 2>&1 
netstat -na | grep 21 | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1 

echo "일반 FTP 확인" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/inetd.conf | grep ftp" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "ProFTP 확인 #ps -ef | grep proftpd | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep proftpd | grep -v grep >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "vsFTP 확인 #ps -ef | grep vsftpd | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep vsftpd | grep -v grep >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-60] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-61]  ftp 계정 shell 제한"  
echo "[U-61]  ftp 계정 shell 제한"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ftp 계정의 shell 이 /bin/false로 부여되어 있는 경우 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#cat /etc/passwd | grep ftp" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | grep ftp >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1

echo "[U-61] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-62] Ftpusers 파일 소유자 및 권한설정"  
echo "[U-62] Ftpusers 파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 소유자 root && 640 이하일시 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/ftpusers ]
	then
		echo "#ls -al /etc/ftpusers" >> $HOSTNAME.txt 2>&1
		ls -al /etc/ftpusers >> $HOSTNAME.txt 2>&1
		echo "#cat /etc/ftpusers" >> $HOSTNAME.txt 2>&1
		cat /etc/ftpusers >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/ftpusers | grep "...-.-----.*root.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "퍼미션이 640이 아닙니다." >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
		echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/ftpusers 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi


echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/ftpd/ftpusers ]
	then
		echo "#ls -al /etc/ftpd/ftpusers" >> $HOSTNAME.txt 2>&1
		ls -al /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
		echo "#cat /etc/ftpd/ftpusers" >> $HOSTNAME.txt 2>&1
		cat /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/ftpd/ftpusers | grep "...-.-----.*root.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "퍼미션이 640이 아닙니다." >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/ftpd/ftpusers 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/vsftpd/ftpusers ]
	then
		echo "#ls -al /etc/vsftpd/ftpusers" >> $HOSTNAME.txt 2>&1
		ls -al /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
		echo "#cat /etc/vsftpd/ftpusers" >> $HOSTNAME.txt 2>&1
		cat /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/vsftpd/ftpusers | grep "...-.-----.*root.*" | wc -l` -eq 1 ]
			then
				echo "양호" >> $HOSTNAME.txt 2>&1
			else
				echo "퍼미션이 640이 아닙니다." >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/vsftpd/ftpusers 파일이 없습니다" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-62] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "----------------------------------------------------------------------------------------"										>> $HOSTNAME.txt 2>&1
echo [U-62] Ftpusers 파일 소유자 및 권한설정[TIP]																					>> $HOSTNAME.txt 2>&1
echo "Ftpusers 파일은 ftp를 사용하는 계정들의 접근을 제한또는 허용하는 파일인데 SFTP는 SSH와 함께 22번포트를 사용함으로"	     	>> $HOSTNAME.txt 2>&1
echo "FTPUSERS 파일이 존재하지 않는다. "												                                            >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"										>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-63] Ftpusers 파일 설정"  
echo "[U-63] Ftpusers 파일 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: FTP가 활성화 되어 있는 경우 root 계정 접속을 차단했을 경우만 양호" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "일반 FTP 확인" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/ftpusers" >> $HOSTNAME.txt 2>&1
cat /etc/ftpusers >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/ftpd/ftpusers" >> $HOSTNAME.txt 2>&1
cat /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "vsFTPD 확인" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/vsftpd/ftpusers" >> $HOSTNAME.txt 2>&1
cat /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "ProFTP 확인" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/proftpd.conf | grep -i rootlogin" >> $HOSTNAME.txt 2>&1
cat /etc/proftpd.conf | grep -i "rootlogin" >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-63] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-64] at파일 소유자 및 권한설정"  
echo "[U-64] at파일 소유자 및 권한설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: at.allow, at.deny 파일 owner:root 또는 bin등 시스템 계정  && Permission:640이 -> OK " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: at.allow 또는 at.deny 파일 중 하나만 존재하여도 무방" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "ls -lL /etc/at*"  >> $HOSTNAME.txt 2>&1
ls -lL /etc/at* >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "ls -lL /etc/cron.d/at*"  >> $HOSTNAME.txt 2>&1
ls -lL /etc/cron.d/at* >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-64] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-65]  SNMP 서비스 구동 점검"  
echo "[U-65]  SNMP 서비스 구동 점검"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : SNMP가 구동되고 있지 않으면 양호" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 프로세스중 NAScenterAgent는 한국지역정보개발원 지킴-e 서비스를 위해 사용하는 SNMP서비스 이므로 양호처리" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
 then
   echo "SNMP가 비실행중입니다. 양호"  >> $HOSTNAME.txt 2>&1
   echo " " >> $HOSTNAME.txt 2>&1
   echo "ps -ef | grep snmp | grep -v grep" >> $HOSTNAME.txt 2>&1
   ps -ef | grep snmp | grep -v grep       >> $HOSTNAME.txt 2>&1
   touch snmp_tmp
 else
   echo "ps -ef | grep snmp | grep -v dmi | grep -v grep"   >> $HOSTNAME.txt 2>&1
   ps -ef | grep snmp | grep -v "dmi" | grep -v "grep"  >> $HOSTNAME.txt 2>&1
   echo "SNMP가 실행중 입니다. 취약" >> $HOSTNAME.txt 2>&1
      echo " " >> $HOSTNAME.txt 2>&1

fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-65] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-66] SNMP 서비스 커뮤니티스트링의 복잡성 설정"  
echo "[U-66] SNMP 서비스 커뮤니티스트링의 복잡성 설정"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 커뮤니티스트링이 public 또는 private이 아닐경우 양호 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f snmp_tmp ]
	then
		echo "SNMP가 비실행중입니다.양호" >> $HOSTNAME.txt 2>&1
	   
	else
		if [ `cat /etc/snmpd.conf | egrep -i "public|private" | grep -v "^ *#" | wc -l ` -eq 0 ]
			then
				echo "cat /etc/snmpd.conf | egrep -i 'public|private'" >> $HOSTNAME.txt 2>&1
				cat /etc/snmpd.conf | egrep -i 'public|private' >> $HOSTNAME.txt 2>&1
				echo "양호" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				
			else
				echo "cat /etc/snmpd.conf | egrep -i 'public|private'" >> $HOSTNAME.txt 2>&1
				cat /etc/snmpd.conf | egrep -i 'public|private' >> $HOSTNAME.txt 2>&1
				echo "취약" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				
		fi
fi
rm -rf snmp_tmp
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-66] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-67]  로그온 시 경고 메시지 제공"  
echo "[U-67]  로그온 시 경고 메시지 제공"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : issue.net && motd 파일의 내용이 기본 설정이거나 없을경우 취약" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : telnet 서비스가 중지되어 있을경우 /etc/issue.net 파일 설정 고려하지 않아도 됨" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/issue.net ]
	then
		echo "#cat /etc/issue.net" >> $HOSTNAME.txt 2>&1
		cat /etc/issue.net >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/issue.net 파일이 없습니다.취약" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "참고사항 : ssh 배너 사용여부 확인" >> $HOSTNAME.txt 2>&1 
echo "cat /etc/ssh/sshd_config | grep Banner" >> $HOSTNAME.txt 2>&1 
cat /etc/ssh/sshd_config | grep Banner >> $HOSTNAME.txt 2>&1 
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/motd ]
	then
		echo "#cat /etc/motd" >> $HOSTNAME.txt 2>&1
		cat /etc/motd >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/motd 파일이 없습니다.취약" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-67] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"		>> $HOSTNAME.txt 2>&1
echo [U-67] 로그온 시 경고 메시지 제공[TIP]																	>> $HOSTNAME.txt 2>&1
echo "경고메세지 설정은 다음과 같은 파일에서 처리함"	     														>> $HOSTNAME.txt 2>&1
echo "issue.net = 사용자가 로그인전에 출력되는 메세지[ssh는 별도설정필요함]"						                                          >> $HOSTNAME.txt 2>&1
echo "motd = 사용자가 로그인후에 출력되는메세지 "             														>> $HOSTNAME.txt 2>&1
echo "ssh를 사용한다면 /etc/ssh/sshd_config 파일내의  #Banner none  구문의 주석을 제거한후"                                     >> $HOSTNAME.txt 2>&1
echo "예제]#Banner none 에서 Banner /etc/issue.net 으로 베너 경로를"   												 >> $HOSTNAME.txt 2>&1 
echo "변경하여야만 ssh로 로그인할시 베너가 출력된다."              															  >> $HOSTNAME.txt 2>&1 
echo "단 motd 파일은 접속후에 메세지를 출력하기때문에 별도의 설정없이 telnet 및 ssh 모두 메세지가 출력된다."                         >> $HOSTNAME.txt 2>&1 
echo "기반시설 취약점 분석평가 기준에는 SSH 배너 설정부분은 언급되지 않으므로, 설정되지 않아도 양호 처리하나, 여력이 될 시 권고사항으로 언급."                         >> $HOSTNAME.txt 2>&1 
echo "--------------------------------------------------------------------------------------" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-68]  NFS 설정 파일 접근 권한"  
echo "[U-68]  NFS 설정 파일 접근 권한" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : NFS설정파일이 없거나 퍼미션이 644이하인 경우 -> OK" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo "  " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/exports 확인" >> $HOSTNAME.txt 2>&1
if [ -f /etc/exports ]
 then
	if [ `ls -alL /etc/exports | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
		then
			ls -alL /etc/exports >> $HOSTNAME.txt 2>&1
			echo "양호" >> $HOSTNAME.txt 2>&1
		else
			ls -alL /etc/exports >> $HOSTNAME.txt 2>&1
			echo "취약" >> $HOSTNAME.txt 2>&1
	fi

 else
    echo "/etc/exports 파일이 없습니다." >> $HOSTNAME.txt 2>&1
fi

echo "참고 : /etc/dfs/dfstab 확인" >> $HOSTNAME.txt 2>&1
if [ -f /etc/dfs/dfstab ]
 then
	if [ `ls -alL /etc/dfs/dfstab | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
		then
			ls -alL /etc/dfs/dfstab >> $HOSTNAME.txt 2>&1
			echo "양호" >> $HOSTNAME.txt 2>&1
		else
			ls -alL /etc/dfs/dfstab >> $HOSTNAME.txt 2>&1
			echo "취약" >> $HOSTNAME.txt 2>&1
	fi

 else
    echo "/etc/dfs/dfstab 파일이 없습니다." >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-68] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-69] expn, vrfy 명령어 제한" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: PricacyOptions=authwarnings, goaway(noexpn,novrfy)를 포함하고 있을경우 양호 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
	then
		echo "Sendmail 서비스가 비실행 중입니다." >> $HOSTNAME.txt 2>&1
	else
		echo "#/etc/mail/sendmail.cf 파일의 옵션 확인" >> $HOSTNAME.txt 2>&1
			if [ -f /etc/mail/sendmail.cf ]
				then
					    if [ `cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn" | grep -v "grep" | wc -l ` -eq 1 ]
							then
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn" | grep -v "grep" >> $HOSTNAME.txt 2>&1
								echo " " >> $HOSTNAME.txt 2>&1
							else
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn" | grep -v "grep" >> $HOSTNAME.txt 2>&1
								echo "취약" >> $HOSTNAME.txt 2>&1
						fi
				else
					echo "/etc/mail/sendmail.cf 파일 없음.취약" >> $HOSTNAME.txt 2>&1
					echo " " >> $HOSTNAME.txt 2>&1
			fi
fi

rm -rf sendmail_tmp
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-69] End" >> $HOSTNAME.txt 2>&1  
echo " " >> $HOSTNAME.txt 2>&1

echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-70]  Apache 웹서비스 정보 숨김"  
echo "[U-70]  Apache 웹서비스 정보 숨김"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 모든 디렉토리에서 설정값이 없거나 ServerTokens 지시자의 옵션이 Prod[uctOnly]가 아닐경우 취약" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache가 실행중이 아닙니다." >> $HOSTNAME.txt 2>&1
	else
		echo "시스템 담당자에게 Apache 환경설정파일 (Httpd.conf) 요청 후 진단 수행" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-70] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo [U-70]  Apache 웹서비스 정보 숨김[TIP]											>> $HOSTNAME.txt 2>&1
echo "ServerTokens Prod 행을 추가해야함 "									>> $HOSTNAME.txt 2>&1
echo "ServerTokens Optisns 설명"                                            >> $HOSTNAME.txt 2>&1 
echo "Prod : 웹서버 종류  - Server:Apache"                                   >> $HOSTNAME.txt 2>&1 
echo "Min : Prod + 웹서버 버전 - Server:Apache/1.3.0"                         >> $HOSTNAME.txt 2>&1 
echo "OS : MIN + 운영체제  - Server:Apache/1.3.0(UNIX)"                      >> $HOSTNAME.txt 2>&1                                                   >> $HOSTNAME.txt 2>&1 
echo "Full: OS + 설치된 모듈정보 - Server:Apache/1.3.0(UNX)"                  >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-71] 최신 보안패치 및 벤더 권고사항 적용"  
echo "[U-71] 최신 보안패치 및 벤더 권고사항 적용"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 수동진단 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "수동진단"  >> $HOSTNAME.txt 2>&1
uname -a          >> $HOSTNAME.txt 2>&1 
uname -r          >> $HOSTNAME.txt 2>&1 
cat /proc/version  >> $HOSTNAME.txt 2>&1 
cat /etc/*release  >> $HOSTNAME.txt 2>&1 

echo " " >> $HOSTNAME.txt 2>&1
echo "[U-71] End" >> $HOSTNAME.txt 2>&1

echo "####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-72]  로그의 정기적 검토 및 보고"  
echo "[U-72]  로그의 정기적 검토 및 보고"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: 관리진단 로그 항목 참조 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "관리진단 로그 항목 참"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[U-72] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-73] 정책에 따른 시스템 로깅 설정"
echo "[U-73] 정책에 따른 시스템 로깅 설정" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : 로그 기록 정책이 아래 예시를 포함하여 수립되어 있으면 양호 " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "syslog 프로세스" >> $HOSTNAME.txt 2>&1
echo "#ps -ef | grep "syslog" | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep 'syslog' | grep -v grep >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "----------------예시----------------------" >> $HOSTNAME.txt 2>&1
echo "*.info;mail.none;authpriv.none;cron.none /var/log/messages" >> $HOSTNAME.txt 2>&1
echo "authpriv.* /var/log/secure" >> $HOSTNAME.txt 2>&1
echo "mail.* /var/log/maillog" >> $HOSTNAME.txt 2>&1
echo "cron.* /var/log/cron" >> $HOSTNAME.txt 2>&1
echo "*.alert /dev/console" >> $HOSTNAME.txt 2>&1
echo "*.emerg *" >> $HOSTNAME.txt 2>&1
echo "----------------------------------------- " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "시스템 로깅 설정" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/syslog.conf" >> $HOSTNAME.txt 2>&1
cat /etc/syslog.conf >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "rsyslog 시스템 로깅 설정" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/rsyslog.conf" >> $HOSTNAME.txt 2>&1
cat /etc/rsyslog.conf >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-73] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "---------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo [U-73] 정책에 따른 시스템 로깅 설정[TIP]																	>> $HOSTNAME.txt 2>&1
echo "최신버전의 LINUX는 /etc/syslog.conf 가 아닌 /etc/rsyslog.conf 를 사용함" 									>> $HOSTNAME.txt 2>&1
echo "기 구축장비가 아닌 신규사업시 대부분 CentOS[무료] 상위버전 및 REDHAT[유료] 상위버전이 설치됨으로 유의해야함"           >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1





