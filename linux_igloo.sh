#!/bin/sh

###################################################################################
# 본 스크립트에 문제점을 발견할 시 kdh1116@igloosec.com 으로 연락주시기 바랍니다. #
###################################################################################

LANG=C
export LANG
BUILD_VER=1.0
LAST_UPDATE=2017.02
alias ls=ls
_HOST_NAME=`hostname`
DATE=`date '+%F'`
CREATE_FILE=`hostname`"_before_ini_".txt

echo "=============================================================================="
echo " 		Copyright (c) 2017 igloosec Co. Ltd. All rights Reserved. "
echo "		  Linux Vulnerability Scanner Version $BUILD_VER ($LAST_UPDATE)"
echo "=============================================================================="
echo " "
echo " "
echo "================== Starting Linux Vulnerability Scanner $BUILD_VER =================="
echo " "
echo " "
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo " 		Copyright (c) 2017 igloosec Co. Ltd. All rights Reserved. "				  >> $CREATE_FILE 2>&1
echo "		  Linux Vulnerability Scanner Version $BUILD_VER ($LAST_UPDATE)"		  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo "================== Starting Linux Vulnerability Scanner $BUILD_VER ==================" >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo "Check Time : `date`"                                                            >> $CREATE_FILE 2>&1
echo "Hostname   : `hostname`"														  >> $CREATE_FILE 2>&1
echo "Kernal     : `uname -a`"														  >> $CREATE_FILE 2>&1
echo "==============================================================================" >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo " "																			  >> $CREATE_FILE 2>&1
echo "============================  Apache service check  ==========================" >> $CREATE_FILE 2>&1
#Apache 환경설정 관련
web='default'

if [ `ps -ef | egrep -i "httpd|apache2" | grep -v "grep" | grep -v "ns-httpd" | wc -l` -ge 1 ]; then 	
	if [ `ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | awk -F' ' '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -ge 1 ]; then
		web='httpd'
		ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | awk -F' ' '{print $8}' | grep "/" | grep -v "httpd.conf" | uniq >> webdir.txt
		webdir=`cat -n webdir.txt | grep 1 | awk -F' ' '{print $2}'`
		apache=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
		conf=`$webdir -V | grep -i "server_config_file" | awk -F'"' '{print $2}'`
		if [ ! -f $conf ];then
			conf="$apache/$conf"
		fi
		#docroot=`cat $conf | grep -i documentroot  | grep -v '#' | awk -F'"' '{print $2}'`
		rm -rf webdir.txt
		$webdir -v >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	elif [ `ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | awk -F' ' '{print $9}' | grep "/" | grep -v "httpd.conf" | uniq | wc -l` -ge 1 ]; then
		web='httpd'
		ps -ef | egrep -i "httpd|apache2" | grep -v "ns-httpd" | grep -v "grep" | awk -F' ' '{print $9}' | grep "/" | grep -v "httpd.conf" | uniq >> webdir.txt
		webdir=`cat -n webdir.txt | grep 1 | awk -F' ' '{print $2}'`
		apache=`$webdir -V | grep -i "httpd_root" | awk -F'"' '{print $2}'`
		conf=`$webdir -V | grep -i "server_config_file" | awk -F'"' '{print $2}'`
		if [ ! -f $conf ];then
			conf="$apache/$conf"
		fi
		#docroot=`cat $conf | grep -i documentroot | grep -v '#' | awk -F'"' '{print $2}'`
		rm -rf webdir.txt
		$webdir -v >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	else
		echo "Apache 환경 변수 세팅 미흡. 수동점검 필요" >> $CREATE_FILE 2>&1
	fi	
else
	echo "Apache 서비스 비활성화" >> $CREATE_FILE 2>&1
fi





U_01() {
  echo -n "U-01. root 계정 원격 접속 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-01. root 계정 원격 접속 제한" >> $CREATE_FILE 2>&1
  echo ":: 원격 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우 양호"    >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Telnet 프로세스 데몬 동작 확인 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep -v grep | grep -i "telnet" | wc -l` -gt 0 ]
	  then
          ps -ef | grep -v grep | grep -i "telnet" >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1 
    	  echo "☞ Telnet Service enable" >> $CREATE_FILE 2>&1
		  
		  echo " " >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
  
		  echo "② /etc/securetty 현황" >> $CREATE_FILE 2>&1
	      echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
		  if [ -f /etc/securetty ]
			then
			  cat /etc/securetty | grep -i "pts" >> $CREATE_FILE 2>&1
			  if [ `cat /etc/securetty | grep -i "pts" | grep -v '#' | wc -l` -eq 0 ]
			    then
				  result_telnet='true'
				else
				  result_telnet='false'
			  fi
			else
			   echo "/etc/securetty파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			   result_telnet='false'
		   fi
		   
		   echo " " >> $CREATE_FILE 2>&1
		   
		   echo "ⓢ /etc/pam.d/login 현황" >> $CREATE_FILE 2>&1
	       echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
		   if [ -f /etc/pam.d/login ]
			then
			  cat /etc/pam.d/login | grep -i "pam_securetty.so" >> $CREATE_FILE 2>&1
			  if [ `cat /etc/pam.d/login | grep "pam_securetty.so" | grep -v "#" | wc -l` -eq 0 ]
			    then
				  result_telnet='false'
				else
				  result_telnet='true'
			  fi
			else
			   echo "/etc/pam.d/login파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			   result_telnet='false'
		   fi
   else
      	echo "☞ Telnet Service disable" >> $CREATE_FILE 2>&1
		result_telnet='true'		
  fi
  
  
  echo " " >> $CREATE_FILE 2>&1  
  echo " " >> $CREATE_FILE 2>&1 
  
  
  
  echo "① SSH 프로세스 데몬 동작 확인 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	  then
		  echo "☞ SSH Service Disable" >> $CREATE_FILE 2>&1
		  result_sshd='true'
	  else
		  ps -ef | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1 
		  echo "☞ SSH Service Enable" >> $CREATE_FILE 2>&1
		  
		  echo " " >> $CREATE_FILE 2>&1 
		  echo " " >> $CREATE_FILE 2>&1 
		  
		  echo "② sshd_config파일 확인" >> $CREATE_FILE 2>&1
		  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

		  echo " " > ssh-result.igloo

		  ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config /etc/opt/ssh/sshd_config"

		  for file in $ServiceDIR
			do
				if [ -f $file ]
					then
						if [ `cat $file | grep "PermitRootLogin" | grep -v "setting" | wc -l` -gt 0 ]
							then
							cat $file | grep "PermitRootLogin" | grep -v "setting" | awk '{print "SSH 설정파일('${file}'): "}' >> ssh-result.igloo
							echo " " >> $CREATE_FILE 2>&1
							cat $file | grep "PermitRootLogin" | grep -v "setting" | awk '{print $0 }' >> ssh-result.igloo 
							if [ `cat $file | grep -i "PermitRootLogin no" | grep -v '#' | wc -l` -gt 0 ]
								then
									result_sshd='true'
								else
									result_sshd='false'
							fi
						else	
							echo "SSH 설정파일($file): PermitRootLogin 설정이 존재하지 않습니다." >> ssh-result.igloo
						fi
						if [ `cat $file | grep -i "banner" | grep -v "default banner" | wc -l` -gt 0 ]
							then
								cat $file | grep -i "banner" | grep -v "default banner" | awk '{print "SSH 설정파일('${file}'): " $0 }' >> ssh-banner.igloo
						else
							echo "ssh 로그인 전 출력되는 배너지정이 되어 있지 않습니다. " >> ssh-banner.igloo
						fi	
						# U-67 항목 ssh 배너설정 여부 추가, ssh-banner.igloo 파일 해당 항목에서 제거
				fi
			done 
			
			  if [ `cat ssh-result.igloo | grep -v "^ *$" | wc -l` -gt 0 ]
				then
					cat ssh-result.igloo | grep -v "^ *$" >> $CREATE_FILE 2>&1
			  else
				echo "SSH 설정파일을 찾을 수 없습니다. (인터뷰/수동점검)" >> $CREATE_FILE 2>&1
			  fi
			
	fi

  echo " " >> $CREATE_FILE 2>&1 
  echo " " >> $CREATE_FILE 2>&1 
  
  if [ $result_telnet = 'true' -a $result_sshd = 'true' ]
    then
      echo "★ U-01. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-01. Result : BAD" >> $CREATE_FILE 2>&1
  fi
  

  rm -rf ssh-result.igloo 
 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_02() {
  echo -n "U-02. 패스워드 복잡성 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-02. 패스워드 복잡성 설정" >> $CREATE_FILE 2>&1
  echo ":: 영문·숫자·특수문자가 혼합된 9자리 이상의 패스워드가 설정된 경우 양호"        >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1 
  echo " " >> $CREATE_FILE 2>&1
  echo "minlen : 패스워드 최소길이, dcredit : 숫자, ucredit:대문자, lcredit: 소문자, ocredit: 특수문자 " >> $CREATE_FILE 2>&1
  
  echo " " >> $CREATE_FILE 2>&1
  
  echo "패스워드 복잡도 설정 확인 : /etc/pam.d/system-auth " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  cat /etc/pam.d/system-auth | egrep -i "minlen|dcredit|ucredit|lcredit|ocredit" | grep -v "#" >> $CREATE_FILE 2>&1
   echo " " >> $CREATE_FILE 2>&1
  if [ -f /etc/shadow ]
    then
      echo "[/etc/shadow 파일]" >> $CREATE_FILE 2>&1
      cat /etc/shadow  | grep -v '*' >> $CREATE_FILE 2>&1
    else
      echo "/etc/shadow 파일이 없습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "★ U-02. Result : Manual check" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_03() {
  echo -n "U-03. 계정 잠금 임계값 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-03. 계정 잠금 임계값 설정" >> $CREATE_FILE 2>&1
  echo ":: 계정 잠금 임계값이 5이하의 값으로 설정되어 있는 경우 양호" >> $SCREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1 
  echo " " >> $CREATE_FILE 2>&1
  
releaseString=$(uname -a)

	if echo $releaseString | egrep -qe 'el5|el6|el7'; then
		if [ `cat /etc/pam.d/system-auth | grep "pam_tally2.so" | grep -v "#" | wc -l` -gt 0 ]; then
			cat /etc/pam.d/system-auth | grep "pam_tally2.so" | grep -v "#" >> $CREATE_FILE 2>&1
		else
			echo "/etc/pam.d/system-auth 파일에 설정값이 없습니다." >> $CREATE_FILE 2>&1
		fi

		echo " " >> $CREATE_FILE 2>&1


		if [ -f /etc/pam.d/system-auth ]; then
			if [ `grep "pam_tally2.so" /etc/pam.d/system-auth | grep -v '#' | wc -l` -gt 0 ]; then
				if [ `grep "deny" /etc/pam.d/system-auth | grep -v '#' | egrep [1-5] |wc -l` -gt 0 ]; then  #2015.10.07 수정/끝
					echo "★ U-03. Result : GOOD" >> $CREATE_FILE 2>&1
				else
					echo "★ U-03. Result : BAD" >> $CREATE_FILE 2>&1
				fi
			else
				echo "★ U-03. Result : BAD" >> $CREATE_FILE 2>&1
			fi
		else
			echo "★ U-03. Result : BAD" >> $CREATE_FILE 2>&1
		fi
	else
		  
		  
		  if [ `cat /etc/pam.d/system-auth | grep "pam_tally.so" | grep -v "#" | wc -l` -gt 0 ]
			then
			  cat /etc/pam.d/system-auth | grep "pam_tally.so" | grep -v "#" >> $CREATE_FILE 2>&1
			else
			  echo "/etc/pam.d/system-auth 파일에 설정값이 없습니다." >> $CREATE_FILE 2>&1
		  fi

		  echo " " >> $CREATE_FILE 2>&1


		  if [ -f /etc/pam.d/system-auth ]
			then
			  if [ `grep "pam_tally.so" /etc/pam.d/system-auth | grep -v '#' | wc -l` -gt 0 ]
				then
				  if [ `grep "deny=5" /etc/pam.d/system-auth | grep -v '#' | wc -l` -gt 0 ]
					then
					  echo "★ U-03. Result : GOOD" >> $CREATE_FILE 2>&1
					else
					  echo "★ U-03. Result : BAD" >> $CREATE_FILE 2>&1
				  fi
				else
				  echo "★ U-03. Result : BAD" >> $CREATE_FILE 2>&1
			  fi
			else
			  echo "★ U-03. Result : BAD" >> $CREATE_FILE 2>&1
		  fi
	fi
	
	echo " " >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "Completed"
	echo " "
}


U_04() {
  echo -n "U-04. 패스워드 파일 보호 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-04 패스워드 파일 보호" >> $CREATE_FILE 2>&1
  echo ":: 쉐도우 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ ▶ System status" >> $CREATE_FILE 2>&1
  echo " PS: 정상, NP: 패스워드 없음 , LK:Lock 상태거나 NP 상태 " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
	cat /etc/passwd | grep -v "\*" | grep -v nologin | grep -v false | awk -F: '{print $1}' > PW.txt

	for P in `cat PW.txt`
	do
        passwd -S $P >> sd.txt
	done
	
	for W in `cat PW.txt`
	do
        cat /etc/shadow | grep -v '*' |grep -w $W >> d2.txt
	done
	
	echo "" >> $CREATE_FILE 2>&1
	echo "활성화 계정 /etc/shadow 패스워드 현황" >> $CREATE_FILE 2>&1
	echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	cat d2.txt >> $CREATE_FILE 2>&1
	
	echo "" >> $CREATE_FILE 2>&1
	echo "활성화 계정 패스워드 상태" >> $CREATE_FILE 2>&1
	echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	cat sd.txt >> $CREATE_FILE 2>&1

	echo "" >> $CREATE_FILE 2>&1
	
	if [ `awk -F" " '{print $2}' sd.txt | grep -i "np" | wc -l` -eq 0 ]
        then
                echo "★ U-04. Result : GOOD" >> $CREATE_FILE 2>&1
        else
                echo "★ U-04. Result : BAD" >> $CREATE_FILE 2>&1
	fi

	rm -rf PW.txt sd.txt d2.txt


 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_05() {
  echo -n "U-05. root 이외의 UID '0' 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-05. root 이외의 UID '0' 금지" >> $CREATE_FILE 2>&1
  echo ":: root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/passwd ]
    then
      awk -F: '$3==0 { print $1 " -> UID=" $3 }' /etc/passwd >> $CREATE_FILE 2>&1
    else
      echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1 
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "[/etc/passwd 파일 내용]" >> $CREATE_FILE 2>&1
  cat /etc/passwd >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ `awk -F: '$3==0  { print $1 }' /etc/passwd | grep -v "root" | wc -l` -eq 0 ]
    then
      echo "★ U-05. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-05. Result : BAD" >> $CREATE_FILE 2>&1
  fi



  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_06() {
  echo -n "U-06. root계정 su 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-06. root계정 su 제한" >> $CREATE_FILE 2>&1
  echo ":: su 명령어를 특정 그룹에 속한 사용자만 사용하도록 제한되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/pam.d/su ]
    then
      echo "① /etc/pam.d/su 파일" >> $CREATE_FILE 2>&1
      cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v 'trust' >> $CREATE_FILE 2>&1
    else
      echo "/etc/pam.d/su 파일이 없습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② /bin/su 파일" >> $CREATE_FILE 2>&1
  if [ `ls -al /bin/su | wc -l` -eq 0 ]
    then
      echo "/bin/su 파일이 없습니다. " >> $CREATE_FILE 2>&1
    else
      ls -al /bin/su >> $CREATE_FILE 2>&1
  fi

  echo "③ /usr/bin/su 파일" >> $CREATE_FILE 2>&1
  if [ `ls -al /usr/bin/su | wc -l` -eq 0 ]
    then
      echo "/usr/bin/su 파일이 없습니다. " >> $CREATE_FILE 2>&1
    else
      ls -al /usr/bin/su >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1

  echo "④ /etc/group 파일" >> $CREATE_FILE 2>&1
    cat /etc/group >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat /etc/pam.d/su | grep 'pam_wheel.so' | grep -v '#' | grep -v 'trust' | wc -l` -ge 1 ]
    then
      if [ -f /bin/su ]
        then
          if [ `ls -alL /bin/su | grep ".....-.---" | wc -l` -eq 1 ]
            then
              echo "★ U-06. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-06. Result : BAD" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-06. Result : BAD" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-06. Result : BAD" >> $CREATE_FILE 2>&1
  fi


 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_07() {
  echo -n "U-07. 패스워드 최소 길이 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-07. 패스워드 최소 길이 설정" >> $CREATE_FILE 2>&1
  echo ":: 패스워드 최소 길이가 9자 이상으로 설정되어 있는 경우"  >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/login.defs ]
    then
      echo "[패스워드 설정 현황]" >> $CREATE_FILE 2>&1
      cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" >> $CREATE_FILE 2>&1
    else
      echo " /etc/login.defs 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " > password.igloo
  
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_LEN" | grep -v "#" | awk '{print $2}'` -ge 9 ]
    then
      echo "GOOD" >> password.igloo 2>&1
    else
      echo "BAD" >> password.igloo 2>&1
  fi


  if [ `cat password.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
	        echo "★ U-07. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-07. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf password.igloo


 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_08() {
  echo -n "U-08. 패스워드 최대 사용기간 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-08. 패스워드 최대 사용기간 설정" >> $CREATE_FILE 2>&1
  echo ":: 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있을 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/login.defs ]
    then
      echo "[패스워드 설정 현황]" >> $CREATE_FILE 2>&1
      cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" >> $CREATE_FILE 2>&1
    else
      echo " /etc/login.defs 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  #170131
  echo " " >> $CREATE_FILE 2>&1
  echo " " > password.igloo
  pass_max_days=`cat /etc/login.defs | grep -i "PASS_MAX_DAYS" | grep -v "#" | awk '{print $2}'`
  if [ $pass_max_days -gt 0 ] && [ $pass_max_days -le 90 ]
  then
	echo "GOOD" >> password.igloo 2>&1	
  else
    echo "BAD" >> password.igloo 2>&1
  fi


  if [ `cat password.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-08. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-08. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf password.igloo


 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_09() {
  echo -n "U-09. 패스워드 최소 사용기간 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-09. 패스워드 최소 사용기간 설정" >> $CREATE_FILE 2>&1
  echo ":: 패스워드 최소 사용기간이 7일(1주)로 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/login.defs ]
    then
      echo "[패스워드 설정 현황]" >> $CREATE_FILE 2>&1
      cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" >> $CREATE_FILE 2>&1
    else
      echo " /etc/login.defs 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " > password.igloo
  
  if [ `cat /etc/login.defs | grep -i "PASS_MIN_DAYS" | grep -v "#" | awk '{print $2}'` -ge 7 ]
    then
      echo "GOOD" >> password.igloo 2>&1
    else
      echo "BAD" >> password.igloo 2>&1
  fi


  if [ `cat password.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-09. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-09. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf password.igloo



  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_10() {
  echo -n "U-10. 불필요한 계정 제거 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-10. 불필요한 계정 제거" >> $CREATE_FILE 2>&1
  echo ":: 불필요한 계정이 존재하지 않는 경우 양호"
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  #2016-06-14 
  #start 
  echo "① 기본 시스템 계정(adm, sync, shutdown, halt, news, operator, games, gopher, nfsnobody, squid) " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `cat /etc/passwd | egrep -v "false|nologin"|egrep "^adm:| ^sync: | ^shutdown:| ^halt:| ^news:| ^operator:| ^games:| ^gopher:| ^nfsnobody:| ^squid:" | wc -l` -eq 0 ]
    then
      echo "불필요한 기본 시스템 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	  echo "good" >> igloosec_id.txt 2>&1 
    else
      cat /etc/passwd | egrep -v "false|nologin" | egrep "^adm:| ^sync: | ^shutdown:| ^halt:| ^news:| ^operator:| ^games:| ^gopher:| ^nfsnobody:| ^squid:" >> $CREATE_FILE 2>&1
	  echo "bad" >> igloosec_id.txt 2>&1 
  fi
  echo " " >> $CREATE_FILE 2>&1
  
  #170131
  echo "② 서버계정 리스트 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  cat /etc/passwd | egrep -v "false|nologin" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  
  echo "③ 계정 접속 로그(lastlog) " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  lastlog >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
    if [ `cat igloosec_id.txt | grep "bad" | wc -l` -eq 0 ]
    then
      echo "★ U-10. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-10. Result : BAD" >> $CREATE_FILE 2>&1
  fi
	rm -rf igloosec_id.txt

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}
  #end 

U_11() {
  echo -n "U-11. 관리자 그룹에 최소한의 계정 포함 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-11. 관리자 그룹에 최소한의 계정 포함" >> $CREATE_FILE 2>&1
  echo ":: 관리자 그룹에 불필요한 계정이 등록되어 있지 않은 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

 
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/group ]
    then
      echo "[관리자 그룹 계정 현황]" >> $CREATE_FILE 2>&1
      cat /etc/group | grep "root:" >> $CREATE_FILE 2>&1
    else
      echo " /etc/group 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat /etc/group | grep "root:" | grep ":root," | wc -l` -eq 0 ]
    then
      echo "★ U-11. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-11. Result : BAD" >> $CREATE_FILE 2>&1
  fi



  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_12() {
  echo -n "U-12. 계정이 존재하지 않는 GID 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-12. 계정이 존재하지 않는 GID 금지" >> $CREATE_FILE 2>&1
  echo ":: 구성원이 없거나, 더 이상 사용하지 않는 그룹을 삭제한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  #170131
  echo "☞ /etc/group 파일 내역" >> $CREATE_FILE 2>&1
  cat /etc/group >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "-------------------------" >> $CREATE_FILE 2>&1
  echo "☞ /etc/passwd 파일 내역" >> $CREATE_FILE 2>&1
  cat /etc/passwd >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  echo "☞ 구성원이 존재하지 않는 그룹" >> $CREATE_FILE 2>&1 #20160106-03
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	awk -F: '$4==null' /etc/group > no_4.txt
	awk -F: '{print $3}' no_4.txt > gid_group.txt 
  
  for D in `cat gid_group.txt` 
  do 
	awk -F: '{print $4}' /etc/passwd | grep -w $D > gid_1.txt 
	
	if [ `cat gid_1.txt | wc -l` -gt 0 ]
	then 
		echo "gid=$D"  > /dev/null 
	else 
		echo $D >> gid_none.txt 
	fi 
 done

	if [ `cat gid_none.txt | wc -l` -gt 0 ]
	then
		for A in `cat gid_none.txt` 
		do
			awk -F: '{print $1, $3}' /etc/group | grep -w $A >> $CREATE_FILE 2>&1  
			done 
		echo " " >> $CREATE_FILE 2>&1
		echo "★ U-12. Result : BAD" >> $CREATE_FILE 2>&1 
	else
	    echo " " >> $CREATE_FILE 2>&1
		echo "★ U-12. Result : GOOD" >> $CREATE_FILE 2>&1
	fi
	
rm -rf no_4.txt
rm -rf gid_group.txt 
rm -rf gid_none.txt 
rm -rf gid_1.txt   

  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_13() {
  echo -n "U-13. 동일한 UID 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-13. 동일한 UID 금지" >> $CREATE_FILE 2>&1
  echo ":: 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  for uid in `cat /etc/passwd | awk -F: '{print $3}'`
    do
	    cat /etc/passwd | awk -F: '$3=="'${uid}'" { print "UID=" $3 " -> " $1 }' > account.igloo
    	if [ `cat account.igloo | wc -l` -gt 1 ]
	      then
		      cat account.igloo >> total-account.igloo
	    fi
    done
  if [ `sort -k 1 total-account.igloo | wc -l` -gt 1 ]
    then
	    sort -k 1 total-account.igloo | uniq -d >> $CREATE_FILE 2>&1
    else
	    echo "동일한 UID를 사용하는 계정이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `sort -k 1 total-account.igloo | wc -l` -gt 1 ]
    then
      echo "★ U-13. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-13. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf account.igloo
  rm -rf total-account.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_14() {
  echo -n "U-14. 사용자 shell 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-14. 사용자 shell 점검" >> $CREATE_FILE 2>&1
  echo ":: 로그인이 필요하지 않은 계정에 /bin/false(nologin) 쉘이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/passwd ]
    then
      cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" >> $CREATE_FILE 2>&1
    else
      echo "/etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat /etc/passwd | egrep "^daemon|^bin|^sys|^adm|^listen|^nobody|^nobody4|^noaccess|^diag|^listen|^operator|^games|^gopher" | grep -v "admin" |  awk -F: '{print $7}'| egrep -v 'false|nologin|null|halt|sync|shutdown' | wc -l` -eq 0 ]
    then
      echo "★ U-14. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-14. Result : BAD" >> $CREATE_FILE 2>&1
  fi


  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_15() {
  echo -n "U-15. Session Timeout 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-15. Session Timeout 설정" >> $CREATE_FILE 2>&1
  echo ":: Session Timeout이 600초(10분) 이하로 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
 echo "" > account_sson.igloo
  
  echo "① /etc/profile 파일설정" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1	

  if [ -f /etc/profile ]
    then
	  if [ `cat /etc/profile | egrep -i "TMOUT|TIMEOUT" | grep -v "#" | wc -l` -eq 0 ]
	   then
	     echo "/etc/profile 파일 내 TMOUT/TIMEOUT 설정이 없습니다." >> $CREATE_FILE 2>&1
		 echo "BAD" >> account_sson.igloo
       else
	     cat /etc/profile | egrep -i "TMOUT|TIMEOUT" >> $CREATE_FILE 2>&1
		 if [ `cat /etc/profile | grep -v "#" | egrep -i "TMOUT|TIMEOUT" | awk -F= '$2<=600' | awk -F= '$2>0' | wc -l` -ge 1 ]
		   then
		     echo "GOOD" >> account_sson.igloo
	       else
		     echo "BAD" >> account_sson.igloo
	     fi
	  fi
    else
      echo "/etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  
  if [ -f /etc/csh.login ]
    then
	 echo "② /etc/csh.login 파일설정" >> $CREATE_FILE 2>&1
     echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1	
	  if [ `cat /etc/csh.login | egrep -i "autologout" | grep -v "#" | wc -l` -eq 0 ]
	   then
	    echo "/etc/csh.login 파일 내 autologout 설정이 없습니다." >> $CREATE_FILE 2>&1
		echo "BAD" >> account_sson.igloo
	  else
       cat /etc/csh.login | grep -i "autologout" >> $CREATE_FILE 2>&1
	   	if [ `cat /etc/csh.login | grep -v "#" | grep -i 'autologout' | awk -F= '$2<=10' | awk -F= '$2>0' | wc -l` -ge 1  ]
		   then
		     echo "GOOD" >> account_sson.igloo
	       else
		     echo "BAD" >> account_sson.igloo
	    fi
	  fi
  else if [ -f /etc/csh.cshrc ]
   then
    echo "② /etc/csh.cshrc 파일설정" >> $CREATE_FILE 2>&1
    echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1	
      if [ `cat /etc/csh.cshrc | egrep -i "autologout" | grep -v "#" | wc -l` -eq 0 ]
	   then
	    echo "/etc/csh.cshrc 파일 내 autologout 설정이 없습니다." >> $CREATE_FILE 2>&1
		echo "BAD" >> account_sson.igloo
	  else
       cat /etc/csh.cshrc | grep -i "autologout" >> $CREATE_FILE 2>&1
	   	if [ `cat /etc/csh.cshrc | grep -v "#" | grep -i 'autologout' | awk -F= '$2<=10' | awk -F= '$2>0' | wc -l`-ge 1 ]
		   then
		     echo "GOOD" >> account_sson.igloo
	       else
		     echo "BAD" >> account_sson.igloo
	    fi
	  fi
  else
     echo "/etc/csh.login, /etc/csh.cshrc 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat account_sson.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
       echo "★ U-15. Result : GOOD" >> $CREATE_FILE 2>&1
    else
       echo "★ U-15. Result : BAD" >> $CREATE_FILE 2>&1
  fi
  
  rm -rf account_sson.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_16() {
  echo -n "U-16. root 홈, 패스 디렉터리 권한 및 패스 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-16. root 홈, 패스 디렉터리 권한 및 패스 설정" >> $CREATE_FILE 2>&1
  echo ":: PATH 환경변수에 . 이 맨 앞이나 중간에 포함되지 않은 경우" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo $PATH >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  if [ `echo $PATH | grep "\.:" | wc -l` -eq 0 ]
    then
      echo "★ U-16. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-16. Result : BAD" >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_17() {
  echo -n "U-17. 파일 및 디렉터리 소유자 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-17. 파일 및 디렉터리 소유자 설정" >> $CREATE_FILE 2>&1
  echo ":: 소유자가 존재하지 않은 파일 및 디렉터리가 존재하지 않은 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "☞ 소유자가 존재하지 않는 파일 (소유자 => 파일위치: 경로)" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1


  find /tmp -ls 2> /dev/null  | awk '{print $5 " => 파일위치:" $11}' | egrep -v -i '(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z|^_)' > file-own.igloo
  find /home -ls 2> /dev/null  | awk '{print $5 " => 파일위치:" $11}' | egrep -v -i '(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z|^_)' >> file-own.igloo
  find /var -ls 2> /dev/null  | awk '{print $5 " => 파일위치:" $11}' | egrep -v -i '(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z|^_)' >> file-own.igloo
  find /bin -ls 2> /dev/null | awk '{print $5 " => 파일위치:" $11}' | egrep -v -i '(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z|^_)' >> file-own.igloo
  find /sbin -ls 2> /dev/null | awk '{print $5 " => 파일위치:" $11}' | egrep -v -i '(^a|^b|^c|^d|^e|^f|^g|^h|^i|^j|^k|^l|^m|^n|^o|^p|^q|^r|^s|^t|^u|^v|^w|^x|^y|^z|^_)' >> file-own.igloo
	
		  
  if [ -s file-own.igloo ]
    then
	    cat file-own.igloo >> $CREATE_FILE 2>&1
    else
	    echo "소유자가 존재하지 않는 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  
  if [ -s file-own.igloo ]
    then
      echo "★ U-17. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-17. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf file-own.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_18() {
  echo -n "U-18. /etc/passwd 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-18. /etc/passwd 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
  echo ":: /etc/passwd 파일의 소유자가 root이고, 권한이 ,644 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/passwd ]
    then
      ls -alL /etc/passwd >> $CREATE_FILE 2>&1
    else
      echo " /etc/passwd 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ls -alL /etc/passwd | grep "...-.--.--" | wc -l` -eq 1 ]
    then
      echo "★ U-18. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ `ls -alL /etc/passwd | grep "..--.--.--" | wc -l` -eq 1 ]
        then
          echo "★ U-18. Result : GOOD" >> $CREATE_FILE 2>&1
        else
          echo "★ U-18. Result : BAD" >> $CREATE_FILE 2>&1
      fi
    fi



  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_19() {
  echo -n "U-19. /etc/shadow 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-19. /etc/shadow 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: /etc/shadow 파일의 소유자가 root이고, 권한이 400인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  if [ -f /etc/shadow ]
    then
      ls -alL /etc/shadow >> $CREATE_FILE 2>&1
    else
      echo " /etc/shadow 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ls -alL /etc/shadow | grep "..--------" | wc -l` -eq 1 ]
    then
      echo "★ U-19. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-19. Result : BAD" >> $CREATE_FILE 2>&1
  fi



  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_20() {
  echo -n "U-20. /etc/hosts 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-20. /etc/hosts 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: /etc/hosts 파일의 소유자가 root이고, 권한이 600인 경우 양호" >> $CREATE_FILE 2>&1  
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
	#170201
  if [ -f /etc/hosts ]
    then
		echo "/etc/hosts 파일 퍼미션" >> $CREATE_FILE 2>&1
		ls -alL /etc/hosts >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "/etc/hosts 파일 내용" >> $CREATE_FILE 2>&1
		cat /etc/hosts >> $CREATE_FILE 2>&1
    else
		echo " /etc/hosts 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ls -alL /etc/hosts | grep "...-------" | wc -l` -eq 1 ]
    then
      echo "★ U-20. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-20. Result : BAD" >> $CREATE_FILE 2>&1
  fi


 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_21() {
  echo -n "U-21. /etc/(x)inetd.conf 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-21. /etc/(x)inetd.conf 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: /etc/(X)inetd.conf파일의 소유자가 root이고, 권한이 600인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

	
  
 if [ -d /etc/xinetd.d ] 
    then
	  echo "☞ /etc/xinetd.d 디렉토리 내용 현황." >> $CREATE_FILE 2>&1
      ls -al /etc/xinetd.d/* >> $CREATE_FILE 2>&1
    else
      echo "/etc/xinetd.d 디렉토리가 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/xinetd.conf ]
	then
	   echo "☞ /etc/xinetd.conf 파일 퍼미션 현황." >> $CREATE_FILE 2>&1
	   ls -al /etc/xinetd.conf >> $CREATE_FILE 2>&1
	else
		echo "/etc/xinetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/inetd.conf ]
    then
	  echo "☞ /etc/inetd.conf 파일 퍼미션 현황." >> $CREATE_FILE 2>&1
      ls -al /etc/inetd.conf >> $CREATE_FILE 2>&1
    else
      echo "/etc/inetd.conf 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo " " > inetd.igloo

  if [ -f /etc/inetd.conf ]
    then
      if [ `ls -alL /etc/inetd.conf | awk '{print $1}' | grep '....------'| wc -l` -eq 1 ]
        then
          echo "GOOD" >> inetd.igloo
        else
          echo "BAD" >> inetd.igloo
      fi
    else
      echo "GOOD" >> inetd.igloo
  fi

  if [ -f /etc/xinetd.conf ]
    then
      if [ `ls -alL /etc/xinetd.conf | awk '{print $1}' | grep '....------'| wc -l` -eq 1 ]
        then
          echo "GOOD" >> inetd.igloo
        else
          echo "BAD" >> inetd.igloo
      fi
    else
      echo "" >> inetd.igloo
  fi
  echo " " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d/* | awk '{print $1}' | grep -v '....------'| wc -l` -gt 0 ]
        then
          echo "BAD" >> inetd.igloo
        else
          echo "GOOD" >> inetd.igloo
      fi
    else
      echo "GOOD" >> inetd.igloo
  fi

  if [ `cat inetd.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-21. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-21. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf inetd.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_22() {
  echo -n "U-22. /etc/syslog.conf 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-22. /etc/syslog.conf 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: /etc/syslog.conf 파일의 소유자가 root이고, 권한이 644인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


 if [ -f  /etc/rsyslog.conf ]
    then
		echo "☞ rsyslog 파일권한" >> $CREATE_FILE 2>&1
		ls -alL /etc/rsyslog.conf  >> $CREATE_FILE 2>&1
    elif [ -f /etc/syslog.conf ]
	then
		echo "☞ syslog 파일권한" >> $CREATE_FILE 2>&1
		ls -alL /etc/syslog.conf  >> $CREATE_FILE 2>&1
	else 
		echo "☞ syslog-ng 파일권한" >> $CREATE_FILE 2>&1
                ls -alL /etc/syslog-ng.conf  >> $CREATE_FILE 2>&1

  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/syslog.conf ]
    then
      if [ `ls -alL /etc/syslog.conf | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
        then
          echo "GOOD" >> syslog.igloo 2>&1
       else
          echo "BAD" >> syslog.igloo 2>&1
      fi
  elif [ -f /etc/rsyslog.conf ]
		then 
			if [ `ls -alL /etc/rsyslog.conf | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
			  then
          echo "GOOD" >> syslog.igloo 2>&1
        else
          echo "BAD" >> syslog.igloo 2>&1
		fi
  fi
  if [ -f /etc/syslog-ng.conf ]
    then
      if [ `ls -alL /etc/syslog-ng.conf | awk '{print $1}' | grep '...-.--.--' | wc -l` -eq 1 ]
        then
          echo "GOOD" >> syslog.igloo 2>&1
       else
          echo "BAD" >> syslog.igloo 2>&1
      fi
	fi 
	
	 if [ `cat inetd.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-22. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-22. Result : BAD" >> $CREATE_FILE 2>&1
  fi
  
  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_23() {
  echo -n "U-23. /etc/service 파일 소유자 및 권한 설정  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-23. /etc/service 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: /etc/service 파일의 소유자가 root이고, 권한이 644인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f  /etc/services ]
    then
      ls -alL /etc/services  >> $CREATE_FILE 2>&1
    else
      echo " /etc/services 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/services ]
    then
      if [ `ls -alL /etc/services | awk '{print $1}' | grep '.....--.--' | wc -l` -eq 1 ]
        then
          echo "★ U-23. Result : GOOD" >> $CREATE_FILE 2>&1
       else
          echo "★ U-23. Result : BAD" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-23. Result : Manual check" >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_24() {
  echo -n "U-24. SUID, SGID, Sticky bit 설정파일 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-24. SUID, SGID, Sticky bit 설정파일 점검 " >> $CREATE_FILE 2>&1
  echo ":: 주요 파일의 권한에 SUID와 SGID에 대한 설정이 부여되어 있지 않을 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

   FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

  for check_file in $FILES
    do
      if [ -f $check_file ]
        then
          if [ -g $check_file -o -u $check_file ]
            then
              echo `ls -alL $check_file` >> $CREATE_FILE 2>&1
            else
              echo $check_file "파일에 SUID, SGID가 부여되어 있지 않습니다." >> $CREATE_FILE 2>&1
          fi
        else
          echo $check_file "이 없습니다." >> $CREATE_FILE 2>&1
      fi
    done

  echo " " >> $CREATE_FILE 2>&1


  echo "setuid " > set.igloo

  FILES="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

  for check_file in $FILES
    do
      if [ -f $check_file ]
        then
          if [ `ls -alL $check_file | awk '{print $1}' | grep -i 's'| wc -l` -gt 0 ]
            then
              ls -alL $check_file |awk '{print $1}' | grep -i 's' >> set.igloo
            else
              echo " " >> set.igloo
          fi
      fi
    done

  if [ `cat set.igloo | awk '{print $1}' | grep -i 's' | wc -l` -gt 1 ]
    then
      echo "★ U-24. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-24. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf set.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_25() {
  echo -n "U-25. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 >>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-25. 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고," >> $CREATE_FILE 2>&1
  echo "   홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  echo " " >> $CREATE_FILE 2>&1
  HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
  FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

  for file in $FILES
  do
    FILE=/$file
    if [ -f $FILE ]
      then
        ls -al $FILE >> $CREATE_FILE 2>&1
    fi
  done

  for dir in $HOMEDIRS
  do
    for file in $FILES
    do
      FILE=$dir/$file
        if [ -f $FILE ]
          then
          ls -al $FILE >> $CREATE_FILE 2>&1
        fi
    done
  done
  echo " " >> $CREATE_FILE 2>&1

  echo " " > home.igloo

  HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v '/bin/false' | grep -v 'nologin' | grep -v "#"`
  FILES=".profile .cshrc .kshrc .login .bash_profile .bashrc .bash_login .exrc .netrc .history .sh_history .bash_history .dtprofile"

  for file in $FILES
    do
      if [ -f /$file ]
        then
          if [ `ls -alL /$file |  awk '{print $1}' | grep "........-." | wc -l` -eq 0 ]
            then
              echo "BAD" >> home.igloo
            else
              echo "GOOD" >> home.igloo
          fi
        else
          echo "GOOD" >> home.igloo
      fi
    done

  for dir in $HOMEDIRS
    do
      for file in $FILES
        do
          if [ -f $dir/$file ]
            then
              if [ `ls -al $dir/$file | awk '{print $1}' | grep "........-." | wc -l` -eq 0 ]
                then
                  echo "BAD" >> home.igloo
                else
                  echo "GOOD" >> home.igloo
              fi
            else
              echo "GOOD" >> home.igloo
          fi
        done
    done

  if [ `cat home.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-25. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-25. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf home.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_26() {
  echo -n "U-26. world writable 파일 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-26. world writable 파일 점검 " >> $CREATE_FILE 2>&1
  echo ":: world writable 파일 존재 여부를 확인하고, 존재 시 설정이유를 확인하고 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  #170131 tmp, /var/tmp 제외, | grep -v "p.w..w..w." 추가
  #2016-06-22 수정 
  #find /tmp -perm -2 -ls | grep -v "srw.rw.rw." | grep -v " lrw.rw.rw." | grep -v "rwt" | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l > world.igloo 2>&1
  find /home -perm -2 -ls | grep -v "srw.rw.rw." | grep -v "p.w..w..w." | grep -v " lrw.rw.rw." |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.igloo 2>&1
  find /var -perm -2 -ls | grep -v "srw.rw.rw." | grep -v "p.w..w..w." | grep -v " lrw.rw.rw." | grep -v "tmp" | grep -v "dev" | awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.igloo 2>&1
  #find /var/tmp -perm -2 -ls | grep -v "srw.rw.rw." | grep -v " lrw.rw.rw." | grep -v "rwt" |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.igloo 2>&1
  find /bin -perm -2 -ls | grep -v "srw.rw.rw."| grep -v "p.w..w..w." | grep -v " lrw.rw.rw."  |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.igloo 2>&1 
  find /sbin -perm -2 -ls | grep -v "srw.rw.rw."| grep -v "p.w..w..w." | grep -v " lrw.rw.rw." |awk '{print $3 " : " $5 " : " $6 " : " $11}' | grep -v ^l >> world.igloo 2>&1

  if [ -s world.igloo ]
    then
	    cat world.igloo >> $CREATE_FILE 2>&1
    else
	  echo "☞ World Writable 권한이 부여된 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -s world.igloo ]
    then
      echo "★ U-26. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-26. Result : GOOD" >> $CREATE_FILE 2>&1
  fi
  
  rm -rf world.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_27() {
  echo -n "U-27. /dev에 존재하지 않는 device 파일 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-27. /dev에 존재하지 않는 device 파일 점검 " >> $CREATE_FILE 2>&1
  echo ":: dev에 대한 파일 점검 후 존재하지 않은 device 파일을 제거한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① 기반시설 점검기준 명령 : find /dev -type f -exec ls -l {} \;" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1 
  find /dev -type f -exec ls -l {} \; > dev-file.igloo

  if [ -s dev-file.igloo ]
    then
	  cat dev-file.igloo >> $CREATE_FILE 2>&1
    else
  	  echo "☞ /dev 에 존재하지 않은 Device 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "디바이스 파일(charactor, block file) 점검 : find /dev -type [C B] -exec ls -l {} \;  " >> $CREATE_FILE 2>&1
  echo "major, minor 필드에 값이 올바르지 않은 경우 취약  " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1 
  find /dev -type c -exec ls -l {} \; > dev-file2.igloo
  find /dev -type b -exec ls -l {} \; > dev-file2.igloo
  
  if [ -s dev-file2.igloo ]
    then
	  cat dev-file2.igloo >> $CREATE_FILE 2>&1
    else
  	  echo "☞ /dev 에 charactor, block Device 파일이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -s dev-file.igloo ]
    then
      echo "★ U-27. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-27. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf dev-file.igloo  dev-file2.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_28() {
  echo -n "U-28. $HOME/.rhosts, hosts.equiv 사용 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-28. $HOME/.rhosts, hosts.equiv 사용금지 " >> $CREATE_FILE 2>&1
  echo ":: login, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우 양호" >> $CREATE_FILE 2>&1
  echo "   1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우" >> $CREATE_FILE 2>&1
  echo "   2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우" >> $CREATE_FILE 2>&1
  echo "   3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 '+' 설정이 없는 경우" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="rsh|rlogin|rexec|shell|login|exec"

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 서비스 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD |egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "r 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "xinetd.d디렉터리에 r 계열 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="rsh|rlogin|rexec|shell|login|exec"

  echo "■ inetd.conf 파일에서 'r' commnad 관련 서비스 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/inetd.conf ]
    then
      cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
    else
      echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "r command" > r_temp
              else
                echo "GOOD" >> trust.igloo
                result="GOOD"
            fi
          done
        else
          echo "GOOD" >> trust.igloo
          result="GOOD"
      fi
    elif [ -f /etc/inetd.conf ]
      then
        if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
          then
            echo "GOOD" >> trust.igloo
            result="GOOD"
          else
            echo "r command" > r_temp
        fi
      else
        echo "GOOD" >> trust.igloo
        result="GOOD"
  fi


  HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | sort -u`
  FILES="/.rhosts"

  

  if [ -s r_temp ]
    then
      if [ -f /etc/hosts.equiv ]
        then
		echo "■ /etc/hosts.equiv 파일 현황 " >> $CREATE_FILE 2>&1
		echo "-------------------------------- " >> $CREATE_FILE 2>&1
          ls -alL /etc/hosts.equiv >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
          echo "/etc/hosts.equiv 파일 설정 내용" >> $CREATE_FILE 2>&1
          cat /etc/hosts.equiv >> $CREATE_FILE 2>&1
        else
          echo "/etc/hosts.equiv 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo " " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  

  if [ -s r_temp ]
    then
      for dir in $HOMEDIRS
        do
          for file in $FILES
            do
              if [ -f $dir$file ]
                then
					echo "■ $HOME/.rhosts 파일 현황 " >> $CREATE_FILE 2>&1
					echo "-------------------------------- " >> $CREATE_FILE 2>&1
					ls -alL $dir$file  >> $CREATE_FILE 2>&1
					echo " " >> $CREATE_FILE 2>&1
					echo "- $dir$file 설정 내용" >> $CREATE_FILE 2>&1
					cat $dir$file | grep -v "#" >> $CREATE_FILE 2>&1
                else
					echo "없음" >> nothing.igloo
              fi
            done
        done
    else
      echo " " >> $CREATE_FILE 2>&1
  fi

  if [ -f nothing.igloo ]
    then
      echo "/.rhosts 파일이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  if [ -s r_temp ]
    then
      if [ -f /etc/hosts.equiv ]
        then
          if [ `ls -alL /etc/hosts.equiv |  awk '{print $1}' | grep "....------" | wc -l` -eq 1 ]
            then
              echo "GOOD" >> trust.igloo
            else
              echo "BAD" >> trust.igloo
          fi
          if [ `cat /etc/hosts.equiv | grep "+" | grep -v "grep" | grep -v "#" | wc -l` -eq 0 ]
            then
              echo "GOOD" >> trust.igloo
            else
              echo "BAD" >> trust.igloo
          fi
        else
          echo "GOOD" >> trust.igloo
      fi
    else
      echo "GOOD" >> trust.igloo
  fi


  if [ -s r_temp ]
    then
      for dir in $HOMEDIRS
	      do
	        for file in $FILES
	          do
	            if [ -f $dir$file ]
	              then
                  if [ `ls -alL $dir$file |  awk '{print $1}' | grep "....------" | wc -l` -eq 1 ]
                    then
                      echo "GOOD" >> trust.igloo
                    else
                      echo "BAD" >> trust.igloo
                  fi
                  if [ `cat $dir$file | grep "+" | grep -v "grep" | grep -v "#" |wc -l ` -eq 0 ]
                    then
                      echo "GOOD" >> trust.igloo
                    else
                      echo "BAD" >> trust.igloo
                  fi
                fi
            done
        done
    else
      echo "GOOD" >> trust.igloo
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat trust.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-28. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-28. Result : BAD" >> $CREATE_FILE 2>&1
  fi


  rm -rf trust.igloo r_temp nothing.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}

U_29() {
  echo -n "U-29. 접속 IP 및 포트 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-29. 접속 IP 및 포트 제한 " >> $CREATE_FILE 2>&1
  echo ":: /etc/hosts.deny 파일에 ALL Deny 설정 후" >> $CREATE_FILE 2>&1
  echo "   /etc/hosts.allow 파일에 접근을 허용할 특정 호스트를 등록한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.deny ]
    then
      echo "☞ /etc/hosts.deny 파일 내용" >> $CREATE_FILE 2>&1
      cat /etc/hosts.deny | grep -v "#"  >> $CREATE_FILE 2>&1
    else
      echo "/etc/hosts.deny 파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.allow ]
    then
      echo "☞ /etc/hosts.allow 파일 내용" >> $CREATE_FILE 2>&1
      cat /etc/hosts.allow | grep -v "#"  >> $CREATE_FILE 2>&1
    else
      echo "/etc/hosts.allow 파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.deny ]
    then
      if [ `cat /etc/hosts.deny  | grep -v "#" | sed 's/ *//g' |  grep "ALL:ALL" |wc -l ` -gt 0 ]
        then
          echo "GOOD" >> IP_ACL.igloo
        else
          echo "BAD" >> IP_ACL.igloo
      fi
    else
      echo "BAD" >> IP_ACL.igloo
  fi

  if [ -f /etc/hosts.allow ]
    then
      if [ `cat /etc/hosts.allow | grep -v "#" | sed 's/ *//g' | grep -v "^$" | grep -v "ALL:ALL" | wc -l ` -gt 0 ]
        then
          echo "GOOD" >> IP_ACL.igloo
        else
          echo "BAD" >> IP_ACL.igloo
      fi
    else
      echo "BAD" >> IP_ACL.igloo
  fi


  if [ `cat IP_ACL.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-29. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-29. Result : BAD" >> $CREATE_FILE 2>&1
  fi


rm -rf IP_ACL.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}

U_30() {
  echo -n "U-30. hosts.lpd 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-30. hosts.lpd 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: 파일의 소유자가 root이고 Other에 쓰기 권한이 부여되어 있지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f  /etc/hosts.lpd ]
    then
      ls -alL /etc/hosts.lpd  >> $CREATE_FILE 2>&1
    else
      echo " /etc/hosts.lpd 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/hosts.lpd ]
    then
      if [ `ls -alL /etc/hosts.lpd | awk '{print $1}' | grep '........-.' | wc -l` -eq 1 ]
        then
          echo "★ U-30. Result : GOOD" >> $CREATE_FILE 2>&1
       else
          echo "★ U-30. Result : BAD" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-30. Result : Manual check" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_31() {
  echo -n "U-31. NIS 서비스 비활성화 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-31. NIS 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: 불필요한 NIS 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "NIS, NIS+ 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-31. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-31. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_32() {
  echo -n "U-32. UMASK 설정 관리 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-32. UMASK 설정 관리 " >> $CREATE_FILE 2>&1
  echo ":: UMASK 값이 022 이하로 설정된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "☞ UMASK 명령어  " >> $CREATE_FILE 2>&1
  umask >> $CREATE_FILE 2>&1

  echo "  " >> $CREATE_FILE 2>&1

  echo "☞ /etc/profile 파일  " >> $CREATE_FILE 2>&1
  if [ -f /etc/profile ]
    then
      cat /etc/profile  |grep -i -A1 -B1 umask | grep -v "#" >> $CREATE_FILE 2>&1
      if [ `cat /etc/profile | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -eq 2 ]
      then
        echo "GOOD" >> umask.igloo
      else
        echo "BAD" >> umask.igloo
      fi
    else
      echo "/etc/profile 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi
  echo "  " >> $CREATE_FILE 2>&1
  echo "☞ /etc/bashrc 파일  " >> $CREATE_FILE 2>&1
  if [ -f /etc/bashrc ]
    then
      cat /etc/bashrc | grep -v "#"| grep -i umask >> $CREATE_FILE 2>&1
      if [ `cat /etc/bashrc | grep -i "umask" |grep -v "#" | awk -F"0" '$2 >= "22"' | wc -l` -eq 2 ]
      then
        echo "GOOD" >> umask.igloo
      else
        echo "BAD" >> umask.igloo
      fi
    else
      echo "/etc/bashrc 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1

 if [ `cat umask.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-32. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-32. Result : BAD" >> $CREATE_FILE 2>&1
  fi

 rm -rf umask.igloo
 
 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_33() {
  echo -n "U-33. 홈 디렉터리 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-33. 홈 디렉터리 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: 홈 디렉터리 소유자가 해당 계정이고, 일반 사용자 쓰기 권한이 제거된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  HOMEDIRS=`cat /etc/passwd | egrep -v "false|nologin"  | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | grep -v "var" | grep -v "news" | uniq`
  
  for dir in $HOMEDIRS
    do
      if [ -d $dir ]; then
  	    ls -dal $dir | grep '\d.........' >> homedir.igloo 2>&1
		fi
    done
  echo " " >> $CREATE_FILE 2>&1
	if [ `cat homedir.igloo | grep "........w." | wc -l` -ge 1 ]
		then
			
			cat homedir.igloo | grep "........w." >> $CREATE_FILE 2>&1
	else 
		echo "홈 디렉터리 소유자 및 권한 설정이 양호 합니다." >> $CREATE_FILE 2>&1
		#170131
		cat homedir.igloo >> $CREATE_FILE 2>&1
	fi
		
  echo " " > home.igloo
  HOMEDIRS=`cat /etc/passwd | egrep -v "false|nologin" | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | grep -v "var" | grep -v "news" | uniq`
  for dir in $HOMEDIRS
    do
      if [ -d $dir ]
        then
          if [ `ls -dal $dir |  awk '{print $1}' | grep "........w." | grep '\d.........'| wc -l` -ge 1 ]
            then
              echo "BAD" >> home.igloo
            else
              echo "GOOD" >> home.igloo
          fi
        else
          echo "GOOD" >> home.igloo
      fi
    done

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat home.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-33. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-33. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf home.igloo homedir.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_34() {
  echo -n "U-34. 홈 디렉터리로 지정한 디렉터리의 존재 관리 >>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-34. 홈 디렉터리로 지정한 디렉터리의 존재 관리 " >> $CREATE_FILE 2>&1
  echo ":: 홈 디렉터리가 존재하지 않는 계정이 발견되지 않고," >> $CREATE_FILE 2>&1
  echo "   root 계정을 제외한 일반 계정의 홈 디렉터리가 '/'가 아닌 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "☞ 홈 디렉터리가 존재하지 않는 계정리스트" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  echo " " > DHOME_pan.igloo
  
  HOMEDIRS=`cat /etc/passwd | egrep -v -i "nologin|false" | awk -F":" 'length($6) > 0 {print $6}' | sort -u | grep -v "#" | grep -v "/tmp" | grep -v "uucppublic" | uniq`

  for dir in $HOMEDIRS
    do
	    if [ ! -d $dir ]
	      then
		      awk -F: '$6=="'${dir}'" { print "● 계정명(홈디렉터리):"$1 "(" $6 ")" }' /etc/passwd >> $CREATE_FILE 2>&1
		      echo " " > Home.igloo
		 
	    fi
    done

  echo " " >> $CREATE_FILE 2>&1

  if [ ! -f Home.igloo ]
    then
		  echo "홈 디렉터리가 존재하지 않은 계정이 발견되지 않았습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  
  echo "☞ root 계정 외 '/'를 홈디렉터리로 사용하는 계정리스트" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  
  if [ `cat /etc/passwd | egrep -v -i "nologin|false" | grep -v root | awk -F":" 'length($6) > 0' | awk -F":" '$6 == "/"' | wc -l` -eq 0 ]
  then
        echo "root 계정 외 '/'를 홈 디렉터리로 사용하는 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  else
        cat /etc/passwd | egrep -v -i "nologin|false" | grep -v root | awk -F":" 'length($6) > 0' | awk -F":" '$6 == "/"' >> $CREATE_FILE 2>&1
        echo "BAD" >> DHOME_pan.igloo
  fi
        

  echo " " >> $CREATE_FILE 2>&1

  if [ ! -f Home.igloo ]
    then
      echo "GOOD" >> DHOME_pan.igloo
    else
      echo "BAD" >> DHOME_pan.igloo
      rm -rf Home.igloo
  fi
  
  if [ `cat DHOME_pan.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-34. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-34. Result : BAD" >> $CREATE_FILE 2>&1
      
	  
  fi
  rm -rf DHOME_pan.igloo
 rm -rf no_Home.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_35() {
  echo -n "U-35. 숨겨진 파일 및 디렉터리 검색 및 제거 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-35. 숨겨진 파일 및 디렉터리 검색 및 제거 " >> $CREATE_FILE 2>&1
  echo ":: 디렉터리 내 숨겨진 파일을 확인하여, 불필요한 파일 삭제를 완료한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "☞ 숨겨진 파일 및 디렉터리 현황" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  find /tmp -name ".*" -ls  > hidden-file.igloo
  find /home -name ".*" -ls | egrep -v ".bash|viminfo|mozilla" >> hidden-file.igloo
  find /var -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.igloo
  find /bin -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.igloo
  find /sbin -name ".*" -ls |  grep -v "root" | grep -v "var" >> hidden-file.igloo
  echo " " >> $CREATE_FILE 2>&1

  if [ -s hidden-file.igloo ]
    then
      cat hidden-file.igloo >> $CREATE_FILE 2>&1
      echo " " >> $CREATE_FILE 2>&1
      echo "★ U-35. Result : Manual check" >> $CREATE_FILE 2>&1
      rm -rf hidden-file.igloo
    else
      echo "★ U-35. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}




U_36() {
  echo -n "U-36. Finger 서비스 비활성화 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-36. Finger 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: Finger 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="finger"
  
	echo "■ finger 포트 활성화 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ `netstat -na | grep :79 | grep -i listen | wc -l` -ge 1 ]
		then
			echo "finger 서비스 포트 활성화" >>$CREATE_FILE 2>&1
			echo "BAD" >> service.igloo
	else
		echo " " >> $CREATE_FILE 2>&1
		
		echo " finger Service Disable" >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
	
  echo "■ inetd.conf 파일에서 finger 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "/etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "■ /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "finger 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "xinetd.d디렉터리에 finger 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  echo " " > service.igloo

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> service.igloo
        else
          echo "BAD" >> service.igloo
      fi
    else
      echo "GOOD" >> service.igloo
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> service.igloo
              else
                echo "GOOD" >> service.igloo
            fi
          done
        else
          echo "GOOD" >> service.igloo
      fi
    else
      echo "GOOD" >> service.igloo
  fi

  if [ `cat service.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-36. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-36. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf service.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_37() {
  echo -n "U-37. Anonymous FTP 비활성화 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-37. Anonymous FTP 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: Anonymous FTP (익명 ftp) 접속을 차단한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

 
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
	cat /etc/vsftpd.conf | grep -i  "anonymous_enable"  >> $CREATE_FILE 2>&1
cat /etc/vsftpd/vsftpd.conf | grep -i "anonymous_enable" >> $CREATE_FILE 2>&1		
  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | grep "ftp" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "ftp enable" >> ftpps.igloo
                echo "/etc/xinetd.d/ FTP 구동 정보" >> $CREATE_FILE 2>&1
                ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" >> $CREATE_FILE 2>&1
                cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
            fi
          done
      fi
    else
      if [ -f /etc/inetd.conf ]
        then
          if [ `cat /etc/inetd.conf | grep -v '#' | grep ftp  | grep -v "tftp" |  wc -l` -gt 0  ]
            then
              echo "ftp enable" >> ftpps.igloo
          fi
      fi
  fi

  ps -ef | grep ftp  | grep -v grep | grep -v "tftp" >> ftpps.igloo
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat ftpps.igloo | grep ftp | grep -v grep | wc -l` -gt 0 ]
    then
      if [ -f /etc/passwd ]
        then
          cat /etc/passwd | grep "ftp" >> $CREATE_FILE 2>&1
        else
          echo "/etc/passwd 파일이 없습니다. " >> $CREATE_FILE 2>&1
      fi
    else
      echo "☞ ftp 서비스 비 실행중입니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat ftpps.igloo | grep ftp | grep -v grep | wc -l` -gt 0 ]
    then
      if [ `grep -v "^ *#" /etc/passwd | grep "ftp" | grep -v "false" | grep -v "nologin"  | wc -l` -gt 0 ]
        then
          echo "★ U-37. Result : BAD" >> $CREATE_FILE 2>&1
        else
          echo "★ U-37. Result : GOOD" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-37. Result : GOOD" >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_38() {
  echo -n "U-38. r 계열 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-38. r 계열 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: r 계열 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="shell|login|exec|rsh|rlogin|rexec"
	echo " " > 38.igloo
  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 서비스 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD |egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "r 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "xinetd.d디렉터리에 r 계열 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="shell|login|exec|rsh|rlogin|rexec"

  echo "■ inetd.conf 파일에서 'r' commnad 관련 서비스 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/inetd.conf ]
    then
      cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $CREATE_FILE 2>&1
    else
      echo "/etc/inetd.conf 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "★ U-38. Result : BAD" >> 38.igloo 2>&1
                
              else
                echo "★ U-38. Result : GOOD" >> 38.igloo 2>&1
            fi
          done
        else
          echo "★ U-38. Result : GOOD" >> 38.igloo 2>&1
      fi
    elif [ -f /etc/inetd.conf ]
      then
        if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
          then
            echo "★ U-38. Result : GOOD" >> 38.igloo 2>&1
          else
            echo "★ U-38. Result : BAD" >> 38.igloo 2>&1
            
        fi
      else
        echo "★ U-38. Result : GOOD" >> 38.igloo 2>&1
  fi
    if [ `cat 38.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
       echo "★ U-38. Result : GOOD" >> $CREATE_FILE 2>&1
    else
       echo "★ U-38. Result : BAD" >> $CREATE_FILE 2>&1
  fi
  
	rm -rf 38.igloo 
  rm -rf r_temp

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}

#20150923-01
U_39() {
  echo -n "U-39. cron 파일 소유자 및 권한 설정  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-39. cron 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: cron 접근제어 파일 소유자가 root이고, 권한이 640 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
 
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 crons="/etc/crontab /etc/cron.daily/* /etc/cron.hourly/* /etc/cron.monthly/* /etc/cron.weekly/* /var/spool/cron/*"
  crond="/etc/cron.deny /etc/cron.allow"

  echo "① Cron 프로세스 활성화 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1 
  if [ `ps -ef | grep cron | grep -v grep | wc -l` -ge 1 ];then
    ps -ef | grep cron | grep -v grep >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	  echo "☞ cron Service Enable"  >> $CREATE_FILE 2>&1
	  echo " " >> $CREATE_FILE 2>&1
	   
  echo "② Cron 파일 권한  " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
   for check_dir in $crons
   do
    if [ -f $check_dir ]
      then
        ls -alL $check_dir >> $CREATE_FILE 2>&1
      else
        echo $check_dir "이 없습니다." >> $CREATE_FILE 2>&1
    fi
  done
  echo " " >>$CREATE_FILE 2>&1
  
  
  echo "③ Cron.allow, Cron.deny 파일 정보" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	for check_dir in $crond
   do
    if [ -f $check_dir ]
      then
        ls -alL $check_dir >> $CREATE_FILE 2>&1
			if [ `cat $check_dir | wc -l` -ge 1 ]
			then
				echo " " >> $CREATE_FILE 2>&1
				echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $check_dir'파일의 내용'>>$CREATE_FILE 2>&1
				cat $check_dir >> $CREATE_FILE 2>&1
				echo " " >>$CREATE_FILE 2>&1
			else
				echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $check_dir"파일의 내용없음">> $CREATE_FILE 2>&1
        echo " " >>$CREATE_FILE 2>&1
				echo "BAD" >> crontab.igloo
			fi
    else
      echo $check_dir"파일이 없습니다." >> $CREATE_FILE 2>&1
    fi
  done

  echo " " >> $CREATE_FILE 2>&1

  echo " " > crontab.igloo
     
  for check_dir in $crons
  do
	if [ -f $check_dir ] 
	then
    if [  `ls -alL $check_dir | awk '{print $1}' |grep  '.......---' |wc -l` -eq 0 ]
      then
        echo "BAD" >> crontab.igloo
      else
        echo "GOOD" >> crontab.igloo
    fi
	fi
  done

  for check_dir in $crond
  do
	if [ -f $check_dir ] 
	then
    if [  `ls -alL $check_dir | awk '{print $1}' |grep  '.......---' |wc -l` -eq 0 ]
      then
        echo "BAD" >> crontab.igloo
      else
			if [ `cat $check_dir | wc -l` -ge 1 ]
			then 
        		echo "GOOD" >> crontab.igloo
			else
				echo "BAD" >> crontab.igloo
			fi
	  fi
	fi
  done
else
 	echo "☞ cron Service Disable"  >> $CREATE_FILE 2>&1
	echo " " >> $CREATE_FILE 2>&1
	echo "GOOD" >> crontab.igloo
fi	
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat crontab.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-39. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-39. Result : BAD" >> $CREATE_FILE 2>&1
  fi



  rm -rf crontab.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_40() {
  echo -n "U-40. DoS 공격에 취약한 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-40. DoS 공격에 취약한 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: DoS 공격에 취약한 echo, discard, daytime, chargen 서비스가 비활성화 된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="echo|discard|daytime|chargen"


  echo "■ inetd.conf 파일에서 echo, discard, daytime, chargen 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "/etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "■ /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "DoS 공격에 취약한 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "xinetd.d 디렉터리에 DoS에 취약한 서비스 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  echo " " > service.igloo

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> service.igloo
        else
          echo "BAD" >> service.igloo
      fi
    else
      echo "GOOD" >> service.igloo
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> service.igloo
              else
                echo "GOOD" >> service.igloo
            fi
          done
        else
          echo "GOOD" >> service.igloo
      fi
    else
      echo "GOOD" >> service.igloo
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat service.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-40. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-40. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf service.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_41() {
  echo -n "U-41. NFS 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-41. NFS 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: NFS 서비스 관련 데몬이 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo "☞ NFS 데몬(nfsd)확인" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
    then
      if [ -f /etc/exports ]
        then
          cat /etc/exports  >> $CREATE_FILE 2>&1
        else
          echo "/etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
      fi
    else
      echo "NFS 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1


  if [ `ps -ef | egrep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-41. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/exports ]
        then
          if [ `cat /etc/exports | grep -v "#" | grep "/" | wc -l` -eq 0 ]
            then
              echo "★ U-41. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-41. Result : Manual check" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-41. Result : GOOD"  >> $CREATE_FILE 2>&1
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_42() {
  echo -n "U-42. NFS 접근통제  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-42. NFS 접근통제 " >> $CREATE_FILE 2>&1
  echo ":: NFS 서비스를 사용하지 않거나, 사용 시 everyone 공유를 제한한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  ls -al /etc/rc*.d/* | grep -i nfs | grep "/S" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
    then
      if [ -f /etc/exports ]
        then
          cat /etc/exports  >> $CREATE_FILE 2>&1
        else
          echo "/etc/exports 파일이 존재하지 않습니다."  >> $CREATE_FILE 2>&1
      fi
    else
    echo "NFS 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1


  if [ `ps -ef | egrep "nfsd" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-42. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/exports ]
        then
          if [ `cat /etc/exports | grep -v "#" | grep "/" | wc -l` -eq 0 ]
            then
              echo "★ U-42. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-42. Result : Manual check" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-42. Result : GOOD"  >> $CREATE_FILE 2>&1
      fi
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_43() {
  echo -n "U-43. automountd 제거  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-43. automountd 제거 " >> $CREATE_FILE 2>&1
  echo ":: automountd 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "☞ Automount 데몬 확인 " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  ps -ef | egrep 'automountd|autofs' | grep -v "grep" | egrep -v "grep|statdaemon|emi" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  ls -al /etc/rc*.d/* | grep -i "auto" | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | egrep 'automountd|autofs' | grep -v "grep" | egrep -v "grep|statdaemon|emi"  | wc -l` -eq 0 ]
    then
      echo "automount 데몬이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ps -ef | egrep 'automountd|autofs' | grep -v "grep" | egrep -v "grep|statdaemon|emi" | wc -l` -eq 0 ]
    then
      echo "★ U-43. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-43. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_44() {
  echo -n "U-44. RPC 서비스 확인  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-44. RPC 서비스 확인 " >> $CREATE_FILE 2>&1
  echo ":: 불필요한 RPC 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|ruserd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

  echo "■ inetd.conf 파일에서 RPC 관련 서비스 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "/etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  

  echo "■ /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -eq 0 ]
        then
          echo "/etc/xinetd.d RPC 서비스가 없음" >> $CREATE_FILE 2>&1
        else
          ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
      fi
    else
      echo "/etc/xinetd.d 디렉토리가 존재하지 않습니다. " >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "xinetd.d에 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo " " > rpc.igloo

  SERVICE_INETD="rpc.cmsd|rpc.ttdbserverd|sadmind|ruserd|walld|sprayd|rstatd|rpc.nisd|rexd|rpc.pcnfsd|rpc.statd|rpc.ypupdated|rpc.rquotad|kcms_server|cachefsd"

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> rpc.igloo
        else
          echo "BAD" >> rpc.igloo
      fi
    else
      echo "GOOD" >> rpc.igloo
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> rpc.igloo
              else
                echo "GOOD" >> rpc.igloo
            fi
          done
        else
          echo "GOOD" >> rpc.igloo
      fi
    else
      echo "GOOD" >> rpc.igloo
  fi

  if [ `cat rpc.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-44. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-44. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf rpc.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_45() {
  echo -n "U-45. NIS, NIS+ 점검  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-45. NIS, NIS+ 점검 " >> $CREATE_FILE 2>&1
  echo ":: NIS 서비스가 비활성화 되어 있거나, 필요 시 NIS+를 사용하는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
	    echo "☞ NIS, NIS+ Service Disable" >> $CREATE_FILE 2>&1
    else
	    ps -ef | egrep $SERVICE | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-45. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-45. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_46() {
  echo -n "U-46. tffp, talk 서비스 비활성화  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-46. tftp, talk 서비스 비활성화 " >> $CREATE_FILE 2>&1
  echo ":: tftp, talk, ntalk 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  SERVICE_INETD="tftp|talk|ntalk"


  echo "■ inetd.conf 파일에서 tftp, talk 상태" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/inetd.conf ]
  	then
	    cat /etc/inetd.conf | grep -v "^ *#" | egrep $SERVICE_INETD >> $CREATE_FILE 2>&1
	  else
	    echo "/etc/inetd.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "■ /etc/xinetd.d 서비스" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      ls -alL /etc/xinetd.d/* | egrep $SERVICE_INETD  >> $CREATE_FILE 2>&1
    else
      echo "tftp, talk 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo "■ /etc/xinetd.d 내용 " >> $CREATE_FILE 2>&1
  echo "-----------------------" >> $CREATE_FILE 2>&1
  if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
    then
      for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
      do
        echo " $VVV 파일" >> $CREATE_FILE 2>&1
        cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
        echo "   " >> $CREATE_FILE 2>&1
      done
    else
      echo "xinetd.d 디렉터리에 tftp, talk, ntalk 파일이 없습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  echo " " > service.igloo

  if [ -f /etc/inetd.conf ]
    then
      if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l ` -eq 0 ]
        then
          echo "GOOD" >> service.igloo
        else
          echo "BAD" >> service.igloo
      fi
    else
      echo "GOOD" >> service.igloo
  fi

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "BAD" >> service.igloo
              else
                echo "GOOD" >> service.igloo
            fi
          done
        else
          echo "GOOD" >> service.igloo
      fi
    else
      echo "GOOD" >> service.igloo
  fi

  if [ `cat service.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-46. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-46. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf service.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_47() {
  echo -n "U-47. Sendmail 버전 점검  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-47. Sendmail 버전 점검 " >> $CREATE_FILE 2>&1
  echo ":: Sendmail 버전이 8.13.8 이상인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② sendmail 버전확인" >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $CREATE_FILE 2>&1
    else
      echo "/etc/mail/sendmail.cf 파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-47. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `grep -v '^ *#' /etc/mail/sendmail.cf | egrep "DZ8.13.8|8.14.0|8.14.1|8.14.4" | wc -l ` -eq 1 ]
            then
              echo "★ U-47. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-47. Result : BAD" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-47. Result : Manual check" >> $CREATE_FILE 2>&1
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_48() {
  echo -n "U-48. 스팸 메일 릴레이 제한  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-48. 스팸 메일 릴레이 제한 " >> $CREATE_FILE 2>&1
  echo ":: SMTP 서비스를 사용하지 않거나 릴레이 제한이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1

  if [ -f /etc/mail/sendmail.cf ]
    then
      cat /etc/mail/sendmail.cf | grep "R$\*" | grep "Relaying denied" >> $CREATE_FILE 2>&1
    else
      echo "/etc/mail/sendmail.cf 파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-48. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -v "^#" | grep "R$\*" | grep -i "Relaying denied" | wc -l ` -gt 0 ]
            then
              echo "★ U-48. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-48. Result : BAD" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-48. Result : Manual check" >> $CREATE_FILE 2>&1
      fi
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_49() {
  echo -n "U-49. 일반사용자의 Sendmail 실행 방지  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-49. 일반사용자의 Sendmail 실행 방지 " >> $CREATE_FILE 2>&1
  echo ":: SMTP 서비스 미사용 또는, 일반 사용자의 Sendmail 실행 방지가 설정 된 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1
  if [ -f /etc/mail/sendmail.cf ]
    then
      grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
    else
      echo "/etc/mail/sendmail.cf 파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-49. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "restrictqrun" | grep -v "#" |wc -l ` -eq 1 ]
            then
              echo "★ U-49. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-49. Result : BAD" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-49. Result : Manual check" >> $CREATE_FILE 2>&1
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_50() {
  echo -n "U-50. DNS 보안 버전 패치  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-50. DNS 보안 버전 패치 " >> $CREATE_FILE 2>&1
  echo ":: DNS 서비스를 사용하지 않거나 주기적으로 패치를 관리하고 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 DNSPR=`ps -ef | egrep -i "/named|/in.named" | grep -v "grep" | awk 'BEGIN{ OFS="\n"} {i=1; while(i<=NF) {print $i; i++}}'| grep "/" | uniq`
  DNSPR=`echo $DNSPR | awk '{print $1}'`

  if [ `ps -ef | egrep -i "/named|/in.named" | grep -v grep | wc -l` -gt 0 ]
    then
      if [ -f $DNSPR ]
        then
          echo "BIND 버전 확인" >> $CREATE_FILE 2>&1
          echo "--------------" >> $CREATE_FILE 2>&1
          $DNSPR -v | grep BIND >> $CREATE_FILE 2>&1
        else
          echo "$DNSPR 파일 없음" >> $CREATE_FILE 2>&1
      fi
    else
      echo "☞ DNS Service Disable" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1


  if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-50. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f $DNSPR ]
        then
          if [ `$DNSPR -v | grep BIND | egrep '8.4.6 | 8.4.7 | 9.2.8-P1 | 9.3.4-P1 | 9.4.1-P1 | 9.5.0a6 | 9.9.9-P4 | 9.10.4-P4 | 9.11.0-P1' |wc -l` -gt 0 ]
            then
              echo "★ U-50. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-50. Result : BAD" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-50. Result : Manual check" >> $CREATE_FILE 2>&1
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_51() {
  echo -n "U-51. DNS Zone Transfer 설정  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-51. DNS Zone Transfer 설정 " >> $CREATE_FILE 2>&1
  echo ":: DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
 
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① DNS 프로세스 확인 " >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "DNS가 비실행중입니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep named | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i named | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/named.conf 파일의 allow-transfer 확인" >> $CREATE_FILE 2>&1
    if [ -f /etc/named.conf ]
      then
        cat /etc/named.conf | grep 'allow-transfer' >> $CREATE_FILE 2>&1
      else
        echo "/etc/named.conf 파일 없음" >> $CREATE_FILE 2>&1
   fi

  echo " " >> $CREATE_FILE 2>&1

  echo "③ /etc/named.boot 파일의 xfrnets 확인" >> $CREATE_FILE 2>&1
    if [ -f /etc/named.boot ]
      then
        cat /etc/named.boot | grep "\xfrnets" >> $CREATE_FILE 2>&1
      else
        echo "/etc/named.boot 파일 없음" >> $CREATE_FILE 2>&1
    fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-51. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/named.conf ]
        then
          if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
            then
              echo "★ U-51. Result : BAD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-51. Result : GOOD" >> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
            then
              if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "#" | wc -l` -eq 0 ]
                then
                  echo "★ U-51. Result : BAD" >> $CREATE_FILE 2>&1
                else
                  echo "★ U-51. Result : GOOD" >> $CREATE_FILE 2>&1
              fi
           else
              echo "★ U-51. Result : Manual check" >> $CREATE_FILE 2>&1
          fi
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_52() {
  echo -n "U-52. Apache 디렉터리 리스팅 제거  >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-52. Apache 디렉터리 리스팅 제거 " >> $CREATE_FILE 2>&1
  echo ":: 디렉터리 검색 기능을 사용하지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  
 if [ $web = 'httpd' ];then		
		echo > u52_Check.txt
		if [ -f $conf ]
			then
				if [ `cat $conf |grep -i Indexes | grep -i -v '\-Indexes' | grep -v '\#'|wc -l` -eq 0 ]; then
					echo "Indexes 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ Indexes 옵션이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "Indexes 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u52_Check.txt
					echo '☞ Indexes 옵션이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "Indexes 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/sites-available/default ]
			then
				if [ `cat $apache/sites-available/default | grep -i Indexes | grep -i -v '\-Indexes' | grep -v '\#' | wc -l` -eq 0 ]; then
					echo "Indexes 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ Indexes 옵션이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "Indexes 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u52_Check.txt
					echo '☞ Indexes 옵션이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "Indexes 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/sites-available/default" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi	
		if [ -f $apache/conf.d/userdir.conf ]
			then
				if [ `cat $apache/conf.d/userdir.conf | grep -i Indexes | grep -i -v '\-Indexes' | grep -v '\#'| wc -l` -eq 0 ]; then
					echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ Indexes 옵션이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u52_Check.txt
					echo '☞ Indexes 옵션이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/conf.d/userdir.conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/mods-available/userdir.conf ]
			then
				if [ `cat $apache/mods-available/userdir.conf | grep -i Indexes | grep -i -v '\-Indexes' | grep -v '\#' | wc -l` -eq 0 ]; then
					echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ Indexes 옵션이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "<Directory|Indexes|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u52_Check.txt
					echo '☞ Indexes 옵션이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "Indexes 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/mods-available/userdir.conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi
		if [ `cat u52_Check.txt | grep vulnerable | wc -l` -eq 0 ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-52. Result : GOOD" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-52. Result : BAD" >> $CREATE_FILE 2>&1
		fi
		rm -rf u52_Check.txt
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-52. Result : GOOD" >> $CREATE_FILE 2>&1
 fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_53() {
  echo -n "U-53. Apache 웹 프로세스 권한 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-53. Apache 웹 프로세스 권한 제한 " >> $CREATE_FILE 2>&1
  echo ":: Apache 데몬이 root 권한으로 구동되지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 
  if [ $web = 'httpd' ];then
		if [ `ps -ef | egrep -i "httpd|apache2" | grep -v grep | grep -v root | wc -l` -eq 0 ]; then
			ps -ef | egrep -i "httpd|apache2" | grep -v grep >>  $CREATE_FILE 2>&1
			echo ' ' >>  $CREATE_FILE 2>&1
			echo '☞ root계정으로 Apache 서비스를 구동중' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo $conf'파일의 설정 내용' >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
			cat $conf | egrep -i "User |Group " | grep -v '#' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			env | egrep -i "APACHE_RUN_USER|APACHE_RUN_GROUP" >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-53. Result : BAD" >> $CREATE_FILE 2>&1
		else
			ps -ef | egrep -i "httpd|apache2" | grep -v grep >>  $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo '☞ root계정으로 Apache 서비스를 구동하지 않음' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo $conf'파일의 설정 내용' >> $CREATE_FILE 2>&1
			echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
			cat $conf | egrep -i "User |Group " | grep -v '#' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			env | egrep -i "APACHE_RUN_USER|APACHE_RUN_GROUP" >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-53. Result : GOOD" >> $CREATE_FILE 2>&1
		fi
  else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-53. Result : GOOD" >> $CREATE_FILE 2>&1	
 fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_54() {
  echo -n "U-54. Apache 상위 디렉터리 접근 금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-54. Apache 상위 디렉터리 접근 금지 " >> $CREATE_FILE 2>&1
  echo ":: 상위 디렉터리에 이동 제한을 설정한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  if [ $web = 'httpd' ];then		
		echo > u54_Check.txt
		if [ -f $conf ]
			then
				if [ `cat $conf | grep -i "AllowOverride" | grep -v '#' | grep -i "None" | wc -l` -eq 0 ]; then
					echo "AllowOverride 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "AllowOverride 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u54_Check.txt
					echo '☞ None 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "Indexes 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/sites-available/default ]
			then
				if [ `cat $apache/sites-available/default | grep -i "AllowOverride" | grep -v '#' | grep -i "None" | wc -l` -eq 0 ]; then
					echo "AllowOverride 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "AllowOverride 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u54_Check.txt
					echo '☞ None 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "AllowOverride 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/sites-available/default" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi	
		if [ -f $apache/conf.d/userdir.conf ]
			then
				if [ `cat $apache/conf.d/userdir.conf | grep -i "AllowOverride" | grep -v '#' | grep -i "None" | wc -l` -eq 0 ]; then
					echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u54_Check.txt
					echo '☞ None 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/conf.d/userdir.conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/mods-available/userdir.conf ]
			then
				if [ `cat $apache/mods-available/userdir.conf | grep -i "AllowOverride" | grep -v '#' | grep -i "None" | wc -l` -eq 0 ]; then
					echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ None 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "<Directory|AllowOverride|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u54_Check.txt
					echo '☞ None 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "AllowOverride 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/mods-available/userdir.conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi
		if [ `cat u54_Check.txt | grep vulnerable | wc -l` -eq 0 ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-54. Result : GOOD" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-54. Result : BAD" >> $CREATE_FILE 2>&1
		fi
		rm -rf u54_Check.txt
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-54. Result : GOOD" >> $CREATE_FILE 2>&1
 fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_55() {
  echo -n "U-55. Apache 불필요한 파일 제거 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-55. Apache 불필요한 파일 제거 " >> $CREATE_FILE 2>&1
  echo ":: 메뉴얼 파일 및 디렉터리가 제거되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 if [ $web = 'httpd' ];then
	find $apache -name manual	 >> apa_Manual.txt	
	echo "서버 내 Manual 디렉터리 목록" >> $CREATE_FILE 2>&1
	echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f apa_Manual.txt ]
	then
		cat apa_Manual.txt		>>  $CREATE_FILE 2>&1
		echo ' ' >> $CREATE_FILE 2>&1
		echo "☞ Manual 디렉터리가 존재함" >> $CREATE_FILE 2>&1
		echo ' ' >>  $CREATE_FILE 2>&1
		echo "★ U-55. Result : BAD" >> $CREATE_FILE 2>&1
	else
		echo "☞ Manual 디렉터리가 존재하지 않음" >> $CREATE_FILE 2>&1
		echo ' ' >>  $CREATE_FILE 2>&1
		echo "★ U-55. Result : GOOD" >> $CREATE_FILE 2>&1
	fi	
	rm -rf apa_Manual.txt 
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-55. Result : GOOD" >> $CREATE_FILE 2>&1	
 fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_56() {
  echo -n "U-56. Apache 링크 사용금지 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-56. Apache 링크 사용금지 " >> $CREATE_FILE 2>&1
  echo ":: 심볼릭 링크, aliases 사용을 제한한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 if [ $web = 'httpd' ];then		
		echo > u56_Check.txt
		if [ -f $conf ]
			then
				if [ `cat $conf | grep -i "FollowSymLinks" | grep -v '#' | wc -l` -eq 0 ]; then
					echo "FollowSymLinks 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ FollowSymLinks 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "FollowSymLinks 설정 확인 -" $conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					cat $conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u56_Check.txt
					echo '☞ FollowSymLinks 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "FollowSymLinks 설정 확인 -" $conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/sites-available/default ]
			then
				if [ `cat $apache/sites-available/default | grep -i "FollowSymLinks" | grep -v '#' | wc -l` -eq 0 ]; then
					echo "FollowSymLinks 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ FollowSymLinks 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "FollowSymLinks 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/sites-available/default | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u56_Check.txt
					echo '☞ FollowSymLinks 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "FollowSymLinks 설정 확인[Ubuntu] -" $apache/sites-available/default >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/sites-available/default" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi	
		if [ -f $apache/conf.d/userdir.conf ]
			then
				if [ `cat $apache/conf.d/userdir.conf | grep -i "FollowSymLinks" | grep -v '#' | wc -l` -eq 0 ]; then
					echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ FollowSymLinks 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/conf.d/userdir.conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u56_Check.txt
					echo '☞ FollowSymLinks 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/conf.d/userdir.conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/conf.d/userdir.conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi		
		if [ -f $apache/mods-available/userdir.conf ]
			then
				if [ `cat $apache/mods-available/userdir.conf | grep -i "FollowSymLinks" | grep -v '#' | wc -l` -eq 0 ]; then
					echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo '☞ FollowSymLinks 설정이 적용되지 않음[GOOD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				else
					echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
					echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "DocumentRoot " >> $CREATE_FILE 2>&1
					cat $apache/mods-available/userdir.conf | egrep -i "<Directory|FollowSymLinks|</Directory" >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo vulnerable >> u56_Check.txt
					echo '☞ FollowSymLinks 설정이 적용되어 있음[BAD]' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
					echo ' ' >> $CREATE_FILE 2>&1
				fi
			else
				echo "FollowSymLinks 설정 확인[2.4 이상 버전] -" $apache/mods-available/userdir.conf >> $CREATE_FILE 2>&1
				echo "------------------------------------------------------------" >> $CREATE_FILE 2>&1
				echo $apache/mods-available/userdir.conf" 파일이 존재하지 않음" >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
				echo ' ' >> $CREATE_FILE 2>&1
		fi
		if [ `cat u56_Check.txt | grep vulnerable | wc -l` -eq 0 ]; then
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-56. Result : GOOD" >> $CREATE_FILE 2>&1
		else
			echo ' ' >> $CREATE_FILE 2>&1
			echo ' ' >> $CREATE_FILE 2>&1
			echo "★ U-56. Result : BAD" >> $CREATE_FILE 2>&1
		fi
		rm -rf u56_Check.txt
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
	echo "★ U-56. Result : GOOD" >> $CREATE_FILE 2>&1
 fi
  


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_57() {
  echo -n "U-57. Apache 파일 업로드 및 다운로드 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-57. Apache 파일 업로드 및 다운로드 제한 " >> $CREATE_FILE 2>&1
  echo ":: 파일 업로드 및 다운로드를 제한한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 if [ $web = 'httpd' ];then	
	echo "☞ 해당 항목 수정중 - 하단 전문출력 참조" >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-57. Result : Manual check" >> $CREATE_FILE 2>&1
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-57. Result : GOOD" >> $CREATE_FILE 2>&1	
 fi
 
 
  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_58() {
  echo -n "U-58. Apache 웹 서비스 영역의 분리 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-58. Apache 웹 서비스 영역의 분리 " >> $CREATE_FILE 2>&1
  echo ":: DocumentRoot를 별도의 디렉터리로 지정한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
 
 if [ $web = 'httpd' ];then	
	echo "☞ 해당 항목 수정중 - 하단 전문출력 참조" >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-58. Result : Manual check" >> $CREATE_FILE 2>&1
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-58. Result : GOOD" >> $CREATE_FILE 2>&1	
 fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_59() {
  echo -n "U-59. ssh 원격접속 허용 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-59. ssh 원격접속 허용 " >> $CREATE_FILE 2>&1
  echo ":: 원격 접속 시 SSH 프로토콜을 사용하는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① 프로세스 데몬 동작 확인" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	  then
		  echo "☞ SSH Service Disable" >> $CREATE_FILE 2>&1
	  else
		  ps -ef | grep sshd | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② 서비스 포트 확인" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  echo " " > ssh-result.igloo

  ServiceDIR="/etc/sshd_config /etc/ssh/sshd_config /usr/local/etc/sshd_config /usr/local/sshd/etc/sshd_config /usr/local/ssh/etc/sshd_config"

  for file in $ServiceDIR
    do
	    if [ -f $file ]
	      then
		      if [ `cat $file | grep "^Port" | grep -v "^#" | wc -l` -gt 0 ]
		        then
			        cat $file | grep "^Port" | grep -v "^#" | awk '{print "SSH 설정파일('${file}'): " $0 }' >> ssh-result.igloo
			        port1=`cat $file | grep "^Port" | grep -v "^#" | awk '{print $2}'`
			        echo $port1 >> port1-search.igloo
		        else
			        echo "SSH 설정파일($file): 포트 설정 X (Default 설정: 22포트 사용)" >> ssh-result.igloo
		      fi
	    fi
    done

  if [ `cat ssh-result.igloo | grep -v "^ *$" | wc -l` -gt 0 ]
    then
	    cat ssh-result.igloo | grep -v "^ *$" >> $CREATE_FILE 2>&1
    else
	    echo "SSH 설정파일: 설정 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1

  # 서비스 포트 점검
  echo "③ 서비스 포트 활성화 여부 확인" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ -f port1-search.igloo ]
    then
	    if [ `netstat -nat | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	      then
		      echo "☞ SSH Service Disable" >> $CREATE_FILE 2>&1
	      else
		      netstat -na | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
	    fi
    else
	    if [ `netstat -nat | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	      then
		      echo "☞ SSH Service Disable" >> $CREATE_FILE 2>&1
	      else
		      netstat -nat | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
	    fi
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f port1-search.igloo ]
    then
      if [ `netstat -nat | grep ":$port1 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
        then
          echo "★ U-59. Result : BAD" >> $CREATE_FILE 2>&1
        else
          echo "★ U-59. Result : GOOD" >> $CREATE_FILE 2>&1
      fi
    else
	    if [ `netstat -nat | grep ":22 " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -eq 0 ]
	      then
	        echo "★ U-59. Result : BAD" >> $CREATE_FILE 2>&1
	      else
	        echo "★ U-59. Result : GOOD" >> $CREATE_FILE 2>&1
	    fi
	fi


  rm -rf ssh-result.igloo port1-search.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_60() {
  echo -n "U-60. ftp 서비스 확인 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-60. ftp 서비스 확인 " >> $CREATE_FILE 2>&1
  echo ":: FTP 서비스가 비활성화 되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  find /etc -name "proftpd.conf" > proftpd.igloo
  find /etc -name "vsftpd.conf" > vsftpd.igloo
  profile=`cat proftpd.igloo`
  vsfile=`cat vsftpd.igloo`

  echo "① /etc/services 파일에서 포트 확인" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  if [ `cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" | wc -l` -gt 0 ]
    then
	    cat /etc/services | awk -F" " '$1=="ftp" {print "(1)/etc/service파일:" $1 " " $2}' | grep "tcp" >> $CREATE_FILE 2>&1
    else
	    echo "(1)/etc/service파일: 포트 설정 X (Default 21번 포트)" >> $CREATE_FILE 2>&1
  fi

  if [ -s vsftpd.igloo ]
    then
	    if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	      then
		      cat $vsfile | grep "listen_port" | grep -v "^#" | awk '{print "(3)VsFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	      else
		      echo "(2)VsFTP 포트: 포트 설정 X (Default 21번 포트 사용중)" >> $CREATE_FILE 2>&1
	    fi
    else
	    echo "(2)VsFTP 포트: VsFTP가 설치되어 있지 않습니다." >> $CREATE_FILE 2>&1
  fi


  if [ -s proftpd.igloo ]
    then
	    if [ `cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' | wc -l` -gt 0 ]
	      then
		      cat $profile | grep "Port" | grep -v "^#" | awk '{print "(2)ProFTP 포트: " $1 "  " $2}' >> $CREATE_FILE 2>&1
	      else
		      echo "(3)ProFTP 포트: 포트 설정 X (/etc/service 파일에 설정된 포트 사용중)" >> $CREATE_FILE 2>&1
	    fi
    else
	    echo "(3)ProFTP 포트: ProFTP가 설치되어 있지 않습니다." >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  echo "② 서비스 포트 활성화 여부 확인" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1

  ################# /etc/services 파일에서 포트 확인 #################

  if [ `cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}' | wc -l` -gt 0 ]
    then
	    port=`cat /etc/services | awk -F" " '$1=="ftp" {print $1 "   " $2}' | grep "tcp" | awk -F" " '{print $2}' | awk -F"/" '{print $1}'`;
	    
	    if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	      then
		      netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo "ftp enable" > ftpenable.igloo
	    fi
    else
	    netstat -nat | grep ":21 " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
	    echo "ftp disable" > ftpenable.igloo
  fi

  ################# vsftpd 에서 포트 확인 ############################

  if [ -s vsftpd.igloo ]
    then
	    if [ `cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}' | wc -l` -eq 0 ]
	      then
		      port=21
	      else
		      port=`cat $vsfile | grep "listen_port" | grep -v "^#" | awk -F"=" '{print $2}'`
	    fi
	    if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	      then
		      netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo "ftp enable" >> ftpenable.igloo
	    fi
	  else
	    echo "ftp disable" >> ftpenable.igloo
  fi

  ################# proftpd 에서 포트 확인 ###########################

  if [ -s proftpd.igloo ]
    then
	    port=`cat $profile | grep "Port" | grep -v "^#" | awk '{print $2}'`
	    
	    if [ `netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" | wc -l` -gt 0 ]
	      then
		      netstat -nat | grep ":$port " | grep -i "^tcp" | grep -i "LISTEN" >> $CREATE_FILE 2>&1
		      echo "ftp enable"  >> ftpenable.igloo
		    else
		      echo "ftp disable" >> ftpenable.igloo
	    fi
	  else
	    echo "ftp disable" >> ftpenable.igloo
  fi
  
	if [ `cat ftpenable.igloo | grep -i "ftp disable" | wc -l` -eq 3 ]
		then
			echo "서비스 포트가 활성화 되어 있지 않습니다." >> $CREATE_FILE 2>&1
	fi 
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat ftpenable.igloo | grep "enable" | wc -l` -gt 0 ]
    then
      echo "★ U-60. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-60. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf proftpd.igloo vsftpd.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_61() {
  echo -n "U-61. ftp 계정 shell 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-61. ftp 계정 shell 제한 " >> $CREATE_FILE 2>&1
  echo ":: ftp 계정에 /bin/fasle 쉘이 부여되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

   echo "① ftp 계정 쉘 확인(ftp 계정에 false 또는 nologin 설정시 양호)" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | egrep "false|nologin" | wc -l` -gt 0 ]
    then
      result61='good'
    else
      result61='Vulnerability'
  fi  
  
  if [ `cat /etc/passwd | awk -F: '$1=="ftp"' | wc -l` -gt 0 ]
    then
	    cat /etc/passwd | awk -F: '$1=="ftp"' >> $CREATE_FILE 2>&1
    else
	    echo "ftp 계정이 존재하지 않습니다.(GOOD)" >> $CREATE_FILE 2>&1
		result61='good'
  fi
  
  if [ $result61 = 'good' ]; then
	result61='GOOD'
  else
	result61='BAD'
  fi
  
	 echo " " >> $CREATE_FILE 2>&1
  echo "★ U-61. Result : "$result61 >> $CREATE_FILE 2>&1


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_62() {
  echo -n "U-62. Ftpusers 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-62. Ftpusers 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  
  if [ -f /etc/ftpd/ftpusers ]
    then
      ls -alL /etc/ftpd/ftpusers  >> $CREATE_FILE 2>&1
    else
      echo " /etc/ftpd/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/ftpusers ]
    then
      ls -alL /etc/ftpusers  >> $CREATE_FILE 2>&1
    else
      echo " /etc/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd.ftpusers ]
    then
      ls -alL /etc/vsftpd.ftpusers  >> $CREATE_FILE 2>&1
    else
      echo " /etc/vsftpd.ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

   echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd/ftpusers ]
    then
      ls -alL /etc/vsftpd/ftpusers  >> $CREATE_FILE 2>&1
    else
      echo " /etc/vsftpd/ftpusers 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi
  
  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/vsftpd.user_list ]
    then
      ls -alL /etc/vsftpd.user_list >> $CREATE_FILE 2>&1
    else
      echo " /etc/vsftpd.user_list 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
#20150922-02 start
  if [ -f /etc/vsftpd/user_list ]
    then
      ls -alL /etc/vsftpd/user_list >> $CREATE_FILE 2>&1
    else
      echo " /etc/vsftpd/user_list 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
#20150922-02 end
  echo "  " > ftpusers.igloo

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/ftpd/ftpusers ]
    then
      if [ `ls -alL /etc/ftpd/ftpusers | awk '{print $1}' | grep '.....-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.igloo
        else
          echo "GOOD" >> ftpusers.igloo
     fi
    else
      echo "no-file"  >> ftpusers.igloo
  fi

  if [ -f /etc/ftpusers ]
    then
      if [ `ls -alL /etc/ftpusers | awk '{print $1}' | grep '.....-----'| wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.igloo
        else
          echo "GOOD" >> ftpusers.igloo
      fi
    else
      echo "no-file"  >> ftpusers.igloo
  fi

  if [ -f /etc/vsftpd.ftpusers ]
    then
      if [ `ls -alL /etc/vsftpd.ftpusers | awk '{print $1}' | grep '.....-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.igloo
        else
          echo "GOOD" >> ftpusers.igloo
      fi
    else
      echo "no-file"  >> ftpusers.igloo
  fi

  if [ -f /etc/vsftpd/ftpusers ]
    then
      if [ `ls -alL /etc/vsftpd/ftpusers | awk '{print $1}' | grep '.....-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.igloo
        else
          echo "GOOD" >> ftpusers.igloo
      fi
    else
      echo "no-file"  >> ftpusers.igloo
  fi
  
  if [ -f /etc/vsftpd.user_list ]
    then
      if [ `ls -alL /etc/vsftpd.user_list | awk '{print $1}' | grep '.....-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.igloo
        else
          echo "GOOD" >> ftpusers.igloo
      fi
    else
      echo "no-file"  >> ftpusers.igloo
  fi
  

 if [ -f /etc/vsftpd/user_list ]
    then
      if [ `ls -alL /etc/vsftpd/user_list | awk '{print $1}' | grep '.....-----' | wc -l` -eq 0 ]
        then
          echo "BAD" >> ftpusers.igloo
        else
          echo "GOOD" >> ftpusers.igloo
      fi
    else
      echo "no-file"  >> ftpusers.igloo
  fi


  if [ `cat ftpusers.igloo | grep "BAD" | wc -l` -gt 0 ]
    then
      echo "★ U-62. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-62. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf ftpusers.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_63() {
  echo -n "U-63. Ftpusers 파일 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-63. Ftpusers 파일 설정 " >> $CREATE_FILE 2>&1
  echo ":: FTP 서비스가 비활성화 되어 있거나, 활성화 시 root 계정 접속을 차단한 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  

  #170131 "| grep root" 추가
  if [ `cat ftpenable.igloo | grep "enable" | wc -l` -gt 0 ]
    then
      if [ -f /etc/ftpd/ftpusers ]
        then
          echo "☞ /etc/ftpd/ftpusers 파일 설정 값" >> $CREATE_FILE 2>&1
          cat /etc/ftpd/ftpusers | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
          echo "☞ /etc/ftpd/ftpusers  파일 없음" >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
      fi

      echo " " >> $CREATE_FILE 2>&1

	  
	  find /etc -name "vsftpd.conf" > vsftpd.igloo
	  vsfile=`cat vsftpd.igloo`
  
  	  if [ -s vsftpd.igloo ]
		then
          echo "☞ `echo $vsfile` 파일 설정 값" >> $CREATE_FILE 2>&1
		  cat $vsfile | grep -v '^#' | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
          echo "☞ vsftpd.conf 파일이 없습니다. " >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
      fi
  
      if [ -f /etc/ftpusers ]
        then
          echo "☞ /etc/ftpuser 파일 설정 값" >> $CREATE_FILE 2>&1
          cat /etc/ftpusers | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
		  if [ -f /etc/vsftpd/ftpusers ]
			then
				echo "☞ /etc/ftpuser 파일 설정 값" >> $CREATE_FILE 2>&1
				cat /etc/ftpusers | grep 'root' >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
			else
				echo "☞ /etc/ftpusers 및 /etc/vsftpd/ftpusers 파일 없음" >> $CREATE_FILE 2>&1
				echo " " >> $CREATE_FILE 2>&1
		fi
      fi
	
      if [ -f /etc/vsftpd/user_list ]
        then
          echo "/etc/vsftpd/user_list 파일 설정 값" >> $CREATE_FILE 2>&1
		  cat /etc/vsftpd/user_list | grep 'root' >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
        else
          echo "/etc/vsftpd/user_list 파일이 없습니다. " >> $CREATE_FILE 2>&1
		  echo " " >> $CREATE_FILE 2>&1
      fi
  
  else
    echo "☞ ftp disable" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " > ftp.igloo

  cat /etc/ftpusers 2>/dev/null | grep root | grep -v '#' >> ftp.igloo
  cat /etc/ftpd/ftpusers 2>/dev/null | grep root | grep -v '#' >> ftp.igloo
  cat /etc/vsftpd/ftpusers 2>/dev/null | grep root | grep -v '#' >> ftp.igloo
  cat /etc/vsftpd/user_list 2>/dev/null | grep root | grep -v '#' >> ftp.igloo

  echo " " >> $CREATE_FILE 2>&1

  if [ `cat ftpenable.igloo | grep "enable" | wc -l` -gt 0 ]
    then
      if [ `cat ftp.igloo | grep root | grep -v grep | wc -l` -eq 0 ]
        then
          echo "★ U-63. Result : BAD" >> $CREATE_FILE 2>&1
        else
          echo "★ U-63. Result : GOOD" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-63. Result : GOOD" >> $CREATE_FILE 2>&1
  fi

  rm -rf ftpenable.igloo ftp.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_64() {
  echo -n "U-64. at 파일 소유자 및 권한 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-64. at 파일 소유자 및 권한 설정 " >> $CREATE_FILE 2>&1
  echo ":: at 접근제어 파일의 소유자가 root이고, 권한이 640 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1
 
  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

	echo " ① at 파일 소유자 및 권한 설정 확인 " >> $CREATE_FILE 2>&1
	echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/at.* ]
		then
			ls -al /etc/at.* >> $CREATE_FILE 2>&1
	else
		echo "at 파일이 없습니다." >> $CREATE_FILE 2>&1
		
	fi
  
    echo " " >> $CREATE_FILE 2>&1
	
	echo " ② at.allow 파일 내용 확인 " >> $CREATE_FILE 2>&1
	echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/at.allow ] 
		then
			cat /etc/at.allow >> $CREATE_FILE 2>&1
	else
		echo "at.allow 파일이 없습니다. " >> $CREATE_FILE 2>&1
	fi
	
	echo " " >> $CREATE_FILE 2>&1
	
	echo " ③ at.deny 파일 내용 확인 " >> $CREATE_FILE 2>&1
	echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
	if [ -f /etc/at.deny ] 
		then
			cat /etc/at.deny >> $CREATE_FILE 2>&1
	else
		echo "at.deny 파일이 없습니다. " >> $CREATE_FILE 2>&1
	fi
	
	 
	 
	 
  if [ -f /etc/at.allow ]
    then
       if [ \( `ls -l /etc/at.allow | awk '{print $3}' | grep -i root |wc -l` -eq 1 \) -a \( `ls -l /etc/at.allow | grep '...-.-----' | wc -l` -eq 1 \) ]; then
			allow_result='true'
		else
			allow_result='false'
		fi
  else
	
		allow_result='true'
  fi
  
  if [ -f /etc/at.deny ]
    then
        if [ \( `ls -l /etc/at.deny | awk '{print $3}' | grep -i root |wc -l` -eq 1 \) -a \( `ls -l /etc/at.deny | grep '...-.-----' | wc -l` -eq 1 \) ]; then
			deny_result='true'
		else
			deny_result='false'
		fi
  else
		deny_result='true'
  fi
		
  
  echo " " >> $CREATE_FILE 2>&1
  

  
  if [ $allow_result = 'false' -o $deny_result = 'false' ]
    then
      echo "★ U-64. Result : BAD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-64. Result : GOOD" >> $CREATE_FILE 2>&1
  fi



  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_65() {
  echo -n "U-65. SNMP 서비스 구동 점검 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-65. SNMP 서비스 구동 점검 " >> $CREATE_FILE 2>&1
  echo ":: SNMP 서비스를 사용하지 않는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "[SNMP 서비스 여부]" >> $CREATE_FILE 2>&1
 
  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep snmp | grep -v "dmi" | egrep -v "grep|snmpd|disabled" | wc -l` -eq 0 ]
    then
      echo "SNMP가 비실행중입니다. "  >> $CREATE_FILE 2>&1
    else
      ps -ef | grep snmp | grep -v "dmi" | egrep -v "grep|disabled|snmpd" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1
    ls -al /etc/rc*.d/* | grep -i snmp | grep "/S" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep snmp | grep -v "dmi" | egrep -v "grep|snmpd|disabled" | wc -l` -eq 0 ]
    then
      echo "★ U-65. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-65. Result : BAD" >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_66() {
  echo -n "U-66. SNMP 서비스 Community String의 복잡성 설정 >>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-66. SNMP 서비스 Community string의 복잡성 설정 " >> $CREATE_FILE 2>&1
  echo ":: SNMP Community 이름이 public, private 가 아닌 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1


  echo "① SNMP 서비스 여부 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -ge 1 ]
    then
    	echo " " >> $CREATE_FILE 2>&1
    	ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" >> $CREATE_FILE 2>&1
    	echo " " >> $CREATE_FILE 2>&1
    	echo "SNMP가 실행중입니다. "  >> $CREATE_FILE 2>&1
  
  echo " " >> $CREATE_FILE 2>&1

  echo "② 설정파일 CommunityString 현황 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
    
  SPCONF_DIR="/etc/snmpd.conf /etc/snmpdv3.conf /etc/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/sma/snmp/snmpd.conf"

 for file in $SPCONF_DIR
 do
  if [ -f $file ]
  then
     echo "■ "$file"파일 내 CommunityString 설정" >> $CREATE_FILE 2>&1
     echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
     echo " " >> $CREATE_FILE 2>&1
     cat $file | grep -i -A1 -B1 "Community" | grep -v "#" >> $CREATE_FILE 2>&1
     echo " " >> $CREATE_FILE 2>&1
  fi
 done 
  
  echo "★ U-66. Result : Manual check" >> $CREATE_FILE 2>&1  
  
else
  echo "SNMP가 비실행중입니다. "  >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "★ U-66. Result : GOOD" >> $CREATE_FILE 2>&1
fi

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_67() {
  echo -n "U-67. 로그온 시 경고 메시지 제공 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-67. 로그온 시 경고 메시지 제공 " >> $CREATE_FILE 2>&1
  echo ":: 서버 및 Telnet 서비스에 로그온 메시지가 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  #170131
  if [ -f /etc/issue.net ]
  then
		echo "☞ /etc/issue.net 확인(서버정보 출력여부 확인)" >> $CREATE_FILE 2>&1
		echo "☞ 서비스별 배너 경로 설정에 /etc/issue.net이 설정되어 있지 않으면 무관함 " >> $CREATE_FILE 2>&1
		cat /etc/issue.net >> $CREATE_FILE 2>&1
		echo "  " >> $CREATE_FILE 2>&1
  fi
  if [ -f /etc/issue ]
  then
		echo "☞ /etc/issue 확인(서버정보 출력여부 확인)" >> $CREATE_FILE 2>&1
		echo "☞ 서비스별 배너 경로 설정에 /etc/issue가 설정되어 있지 않으면 무관함 " >> $CREATE_FILE 2>&1
		cat /etc/issue >> $CREATE_FILE 2>&1
		echo "  " >> $CREATE_FILE 2>&1
  fi

  
  echo "☞ 서버 로그온 시 출력 배너(/etc/motd) 확인" >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ -f /etc/motd ]
	then  
		if [ `cat /etc/motd | wc -l` -gt 0 ]
    	then
			 echo "GOOD" >> banner.igloo
	   	 cat /etc/motd >> $CREATE_FILE 2>&1
		else
			echo
			echo "BAD" >> banner.igloo 
		fi
  else
	  echo "/etc/motd 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	  echo "BAD" >> banner.igloo
  fi
  
  echo "  " >> $CREATE_FILE 2>&1
  
  echo "☞ SSH 관련 설정 " >> $CREATE_FILE 2>&1
  echo "-------------------------------------------------------------------" >> $CREATE_FILE 2>&1
  if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
	  then
		  echo "☞ SSH Service Disable" >> $CREATE_FILE 2>&1
	  else
		  echo "☞ SSH Service Enable" >> $CREATE_FILE 2>&1
		  echo "  " >> $CREATE_FILE 2>&1
          echo "■ ssh 배너 연동 여부" >> $CREATE_FILE 2>&1		  
		  cat ssh-banner.igloo >> $CREATE_FILE 2>&1
		  # ssh-banner.igloo는 U-01에서 생성 for문 두번돌리지 않기위해..
		  
		  echo "  " >> $CREATE_FILE 2>&1
		  echo "■ 연동된 ssh 배너파일 존재시 해당 파일 내용" >> $CREATE_FILE 2>&1
		  
		  if [ `cat ssh-banner.igloo | grep -v "#" | wc -l` -gt 0 ]
		  then
			#170201
			ssh_path=`cat ssh-banner.igloo | grep -v "#" | awk -F' ' '{print $4}'`
			cat $ssh_path >> $CREATE_FILE 2>&1
			echo "GOOD" >> banner.igloo
		  else
			echo "ssh 배너 연동이 적절하지 않습니다." >> $CREATE_FILE 2>&1
			echo "BAD" >> banner.igloo
		  fi
  fi
 
  ps -ef | grep telnetd  | grep -v grep >> banner_temp.igloo
  
  if [ -f /etc/inetd.conf ]
  then
  cat /etc/inetd.conf | grep 'telnetd' | grep -v '#' >> banner_temp.igloo
  fi
  
   echo "  " >> $CREATE_FILE 2>&1

  
  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | grep "telnet" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | grep telnet | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "telnet enable" >> telnetps.igloo
            fi
          done
      fi
    else
      if [ -f /etc/inetd.conf ]
        then
          if [ `cat /etc/inetd.conf | grep -v '^ *#' | grep telnet | wc -l` -gt 0 ]
            then
              echo "telnet enable" >> telnetps.igloo
          fi
      fi
  fi

  echo " " >> $CREATE_FILE 2>&1

  ps -ef | grep telnetd  | grep -v grep >> telnetps.igloo
  cat /etc/issue >> telnetbanner.igloo
  cat /etc/issue.net >> telnetbanner.igloo

  if [ `cat telnetps.igloo | grep telnet | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ Telnet 서비스 구동됨" >> $CREATE_FILE 2>&1
      echo "■ TELNET 배너" >> $CREATE_FILE 2>&1
      if [ `cat telnetbanner.igloo | egrep "Linux|Kernel" | grep -v grep | wc -l` -eq 0 ]
        then
          echo "GOOD" >> banner.igloo
          ls -al /etc/issue >> $CREATE_FILE 2>&1
          cat /etc/issue >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
          ls -al /etc/issue.net >> $CREATE_FILE 2>&1
          cat /etc/issue.net >> $CREATE_FILE 2>&1
        else
          echo "BAD" >> banner.igloo
          ls -al /etc/issue >> $CREATE_FILE 2>&1
          cat /etc/issue >> $CREATE_FILE 2>&1
          echo " " >> $CREATE_FILE 2>&1
          ls -al /etc/issue.net >> $CREATE_FILE 2>&1
          cat /etc/issue.net >> $CREATE_FILE 2>&1
      fi
    else
      echo "GOOD" >> banner.igloo
      echo "☞ Telnet 서비스 비 실행중입니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1
  echo "  " >> $CREATE_FILE 2>&1

  if [ -d /etc/xinetd.d ]
    then
      if [ `ls -alL /etc/xinetd.d | grep "ftp" | wc -l` -gt 0 ]
        then
          for VVV in `ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" | awk '{print $9}'`
          do
            if [ `cat /etc/xinetd.d/$VVV | grep -i "disable" | grep -i "no" | wc -l` -gt 0 ]
              then
                echo "ftp enable" >> ftpps.igloo
                echo "/etc/xinetd.d/ FTP 구동 정보" >> $CREATE_FILE 2>&1
                ls -alL /etc/xinetd.d | grep ftp | grep -v "tftp" >> $CREATE_FILE 2>&1
                cat /etc/xinetd.d/$VVV | grep -i "disable" >> $CREATE_FILE 2>&1
            fi
          done
      fi
    else
      if [ -f /etc/inetd.conf ]
        then
          if [ `cat /etc/inetd.conf | grep -v '#' | grep ftp  | grep -v "tftp" |  wc -l` -gt 0  ]
            then
              echo "ftp enable" >> ftpps.igloo
          fi
      fi
  fi

  ps -ef | grep ftp  | grep -v grep | grep -v "tftp" >> ftpps.igloo
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat ftpps.igloo | grep ftp | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ FTP 서비스 구동됨" >> $CREATE_FILE 2>&1
      echo "■ FTP 배너" >> $CREATE_FILE 2>&1

      if [ -f /etc/welcome.msg ]
        then
          if [ `cat /etc/welcome.msg | grep -i "banner" | grep "=" | grep "\".\"" | wc -l` -eq 0 ]
            then
              echo "BAD" >> banner.igloo
              cat /etc/welcome.msg >> $CREATE_FILE 2>&1
              echo " " >> $CREATE_FILE 2>&1
            else
              echo "GOOD" >> banner.igloo
              cat /etc/welcome.msg >> $CREATE_FILE 2>&1
              echo " " >> $CREATE_FILE 2>&1
          fi
        else
          if [ -f /etc/vsftpd.conf ]
            then
              if [ `cat /etc/vsftpd.conf | grep -i "ftp_banner" | grep "=" | wc -l` -eq 0 ]
                then
                  echo "BAD" >> banner.igloo
                  cat /etc/vsftpd.conf | grep -i "ftp_banner" >> $CREATE_FILE 2>&1
                else
                  echo "GOOD" >> banner.igloo
                  cat /etc/vsftpd.conf | grep -i "ftp_banner" >> $CREATE_FILE 2>&1
              fi
            else
              if [ -f /etc/proftpd.conf ]
                then
                  if [ `cat /etc/proftpd.conf | grep -i "Serverldent" | grep -i "off" | wc -l` -eq 0 ]
                    then
                      echo "BAD" >> banner.igloo
                      cat /etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                    else
              	      echo "GOOD" >> banner.igloo
                      cat /etc/proftpd.conf  | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                  fi
                else
                  if [ -f /usr/local/etc/proftpd.conf ]
                    then
                      if [ `cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" | grep -i "off" | wc -l` -eq 0 ]
                        then
                          echo "BAD" >> banner.igloo
                          cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                        else
              	          echo "GOOD" >> banner.igloo
              	          cat /usr/local/etc/proftpd.conf | grep -i "Serverldent" >> $CREATE_FILE 2>&1
                      fi
                    else
                      if [ -f /etc/ftpaccess ]
                        then
                          if [ `cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" | wc -l` -eq 0 ]
                            then
                              echo "BAD" >> banner.igloo
                              cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" >> $CREATE_FILE 2>&1
                            else
              	              echo "GOOD" >> banner.igloo
                              cat /etc/ftpaccess | grep -i "greeting" | grep -i "terse" >> $CREATE_FILE 2>&1
                          fi
                        else
                          echo "미점검" >> banner.igloo
                      fi
                  fi
              fi
          fi
      fi
    else
      echo "GOOD" >> banner.igloo
      echo "☞ ftp 서비스 비 실행중입니다." >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1


  echo " " > banner_temp.igloo
  echo "  " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ SMTP 서비스 구동됨" >> $CREATE_FILE 2>&1
      echo "■ SMTP 배너" >> $CREATE_FILE 2>&1
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" | grep -i "Sendmail" | wc -l` -gt 0 ]
            then
              echo "BAD" >> banner.igloo
              echo "/etc/mail/sendmail.cf 파일 내용" >> $CREATE_FILE 2>&1
              cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
            else
              echo "GOOD" >> banner.igloo
              echo "/etc/mail/sendmail.cf 파일 내용" >> $CREATE_FILE 2>&1
              cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
          fi
        else
          echo "미점검" >> banner.igloo
          echo "/etc/mail/sendmail.cf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo "GOOD" >> banner.igloo
      echo "☞ SMTP 서비스 구동중이지 않음" >> $CREATE_FILE 2>&1
  fi


  echo "  " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep named | grep -v grep | wc -l` -gt 0 ]
    then
      echo "☞ DNS 서비스 구동됨" >> $CREATE_FILE 2>&1
      echo "■ DNS 배너" >> $CREATE_FILE 2>&1
      if [ -f /etc/named.conf ]
        then
          if [ `cat /etc/named.conf | grep "version" | wc -l` -eq 0 ]
            then
              echo "BAD" >> banner.igloo
              echo "/etc/named.conf 파일 내용" >> $CREATE_FILE 2>&1
              echo "/etc/named.conf 파일 설정 없음" >> $CREATE_FILE 2>&1
            else
              echo "GOOD" >> banner.igloo
              echo "/etc/named.conf 파일 내용" >> $CREATE_FILE 2>&1
              cat /etc/named.conf | grep -i "version" >> $CREATE_FILE 2>&1
          fi
        else
          echo "미점검" >> banner.igloo
          echo "/etc/named.conf 파일 존재하지 않습니다." >> $CREATE_FILE 2>&1
      fi
    else
      echo "GOOD" >> banner.igloo
      echo "☞ DNS 서비스 구동중이지 않음" >> $CREATE_FILE 2>&1
  fi

  echo "  " >> $CREATE_FILE 2>&1

  if [ `cat banner.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-67. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-67. Result : BAD" >> $CREATE_FILE 2>&1
  fi

  rm -rf ssh-banner.igloo
  rm -rf banner.igloo
  rm -rf banner_temp.igloo
  rm -rf telnetbanner.igloo

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_68() {
  echo -n "U-68. NFS 설정파일 접근권한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-68. NFS 설정파일 접근권한 " >> $CREATE_FILE 2>&1
  echo ":: NFS 접근제어 설정파일의 소유자가 root이고, 권한이 644 이하인 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  if [ -f  /etc/exports ]
    then
      ls -alL /etc/exports  >> $CREATE_FILE 2>&1
    else
      echo " /etc/exports 파일이 없습니다."  >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ -f /etc/exports ]
    then
      if [ `ls -alL /etc/exports | awk '{print $1}' | grep '.....--.--' | wc -l` -eq 1 ]
        then
          echo "★ U-68. Result : GOOD" >> $CREATE_FILE 2>&1
        else
          echo "★ U-68. Result : BAD" >> $CREATE_FILE 2>&1
      fi
    else
      echo "★ U-68. Result : GOOD" >> $CREATE_FILE 2>&1
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_69() {
  echo -n "U-69. expn, vrfy 명령어 제한 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-69. expn, vrfy 명령어 제한 " >> $CREATE_FILE 2>&1
  echo ":: SMTP 서비스 미사용 또는, noexpn, novrfy 옵션이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "① Sendmail 프로세스 확인" >> $CREATE_FILE 2>&1
  
  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "Sendmail 서비스가 비실행중입니다." >> $CREATE_FILE 2>&1
    else
      ps -ef | grep sendmail | grep -v "grep" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  ls -al /etc/rc*.d/* | grep -i sendmail | grep "/S" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1

  echo "② /etc/mail/sendmail.cf 파일의 옵션 확인" >> $CREATE_FILE 2>&1

  if [ -f /etc/mail/sendmail.cf ]
    then
      grep -v '^ *#' /etc/mail/sendmail.cf | grep PrivacyOptions >> $CREATE_FILE 2>&1
    else
      echo "/etc/mail/sendmail.cf 파일 없음" >> $CREATE_FILE 2>&1
  fi

  echo " " >> $CREATE_FILE 2>&1

  if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
    then
      echo "★ U-69. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      if [ -f /etc/mail/sendmail.cf ]
        then
          if [ `cat /etc/mail/sendmail.cf | grep -i "O PrivacyOptions" | grep -i "noexpn" | grep -i "novrfy" |grep -v "#" |wc -l ` -eq 1 ]
            then
              echo "★ U-69. Result : GOOD" >> $CREATE_FILE 2>&1
            else
              echo "★ U-69. Result : BAD" >> $CREATE_FILE 2>&1
          fi
        else
          echo "★ U-69. Result : GOOD" >> $CREATE_FILE 2>&1
      fi
  fi


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_70() {
  echo -n "U-70. Apache 웹서비스 정보 숨김 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-70. Apache 웹서비스 정보 숨김 " >> $CREATE_FILE 2>&1
  echo ":: ServerTokens 지시자에 Prod 옵션이 설정되어 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

 if [ $web = 'httpd' ];then	
	echo "☞ 해당 항목 수정중 - 하단 전문출력 참조" >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-70. Result : Manual check" >> $CREATE_FILE 2>&1
 else
	echo '☞ Apache 서비스가 구동중이지 않음' >> $CREATE_FILE 2>&1
	echo ' ' >> $CREATE_FILE 2>&1
    echo "★ U-70. Result : GOOD" >> $CREATE_FILE 2>&1	
 fi
  

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_71() {
  echo -n "U-71. 최신 보안패치 및 벤더 권고사항 적용 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-71. 최신 보안패치 및 벤더 권고사항 적용 " >> $CREATE_FILE 2>&1
  echo ":: 패치 적용 정책을 수립하여 주기적으로 패치를 관리하고 있는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1


  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "해당항목은 운영담당자와 인터뷰를 통해서 점검 진행" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  echo "★ U-71. Result : Manual check" >> $CREATE_FILE 2>&1

  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}

U_72() {
  echo -n "U-72. 로그의 정기적 검토 및 보고 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-72. 로그의 정기적 검토 및 보고 " >> $CREATE_FILE 2>&1
  echo ":: 로그 기록의 검토, 분석, 리포트 작성 및 보고 등이 정기적으로 이루어지는 경우 양호" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "해당항목은 운영담당자와 인터뷰를 통해서 점검 진행" >> $CREATE_FILE 2>&1
  echo "★ U-72. Result : Manual check" >> $CREATE_FILE 2>&1


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}


U_73() {
  echo -n "U-73. 정책에 따른 시스템 로깅 설정 >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>"
  echo "==============================================================================" >> $CREATE_FILE 2>&1
  echo "U-73. 정책에 따른 시스템 로깅 설정 " >> $CREATE_FILE 2>&1
  echo ":: 정책에 따른 시스템 로깅 설정" >> $CREATE_FILE 2>&1
  echo "==============================================================================" >> $CREATE_FILE 2>&1

  echo "▶ System status" >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1

  #20151113-01 
  #Start 
	if [ -f /etc/rsyslog.conf ]
		then	
			echo "☞ rsyslog 프로세스" >> $CREATE_FILE 2>&1
			ps -ef | grep 'rsyslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
		else
			echo "☞ syslog 프로세스" >> $CREATE_FILE 2>&1
			ps -ef | grep 'syslog' | grep -v 'grep' >> $CREATE_FILE 2>&1
	fi

  echo " " >> $CREATE_FILE 2>&1

  echo "☞ 시스템 로깅 설정" >> $CREATE_FILE 2>&1

	if [ -f /etc/rsyslog.conf ]
		then
			if [ `cat /etc/rsyslog.conf | wc -l` -gt 0 ]
				then 
					cat /etc/rsyslog.conf | grep -v "#" | grep -v '^$' >> $CREATE_FILE 2>&1
				else
					echo "/etc/rsyslog.conf  파일 없음" >> $CREATE_FILE 2>&1
			fi
		elif [ -f /etc/syslog.conf ]
			then
				cat /etc/syslog.conf | grep -v "#" | grep -v '^$' >> $CREATE_FILE 2>&1
			else	
				echo "/etc/syslog.conf  파일 없음" >> $CREATE_FILE 2>&1
		
	fi
	

  echo " " >> $CREATE_FILE 2>&1

  echo " " > syslog.igloo
	if [ -f /etc/syslog.conf ] 
		then
			if [ `cat /etc/syslog.conf | egrep "info|alert|notice|debug" | egrep "var|log" | grep -v "#" | wc -l` -gt 0 ]
				then
					echo "GOOD" >> syslog.igloo
			else
				echo "BAD" >> syslog.igloo
			fi
					
			if [ `cat /etc/syslog.conf | egrep "alert|err|crit" | egrep "console|sysmsg" | grep -v "#" | wc -l` -gt 0 ]
				then
					echo "GOOD" >> syslog.igloo
			else
				echo "BAD" >> syslog.igloo
			fi

			if [ `cat /etc/syslog.conf | grep "emerg" | grep "\*" | grep -v "#" | wc -l` -gt 0 ]
				then
					echo "GOOD" >> syslog.igloo
			else 
				echo "BAD" >> syslog.igloo
			fi
			
		elif [ -f /etc/rsyslog.conf ]
			then
				if [ `cat /etc/rsyslog.conf | egrep "info|alert|notice|debug" | egrep "var|log" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "GOOD" >> syslog.igloo
				else
					echo "BAD" >> syslog.igloo
				fi
				if [ `cat /etc/rsyslog.conf | egrep "alert|err|crit" | egrep "console|sysmsg" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "GOOD" >> syslog.igloo
				else
					echo "BAD" >> syslog.igloo
				fi
				if [ `cat /etc/rsyslog.conf | grep "emerg" | grep "\*" | grep -v "#" | wc -l` -gt 0 ]
					then
						echo "GOOD" >> syslog.igloo
				else
					echo "BAD" >> syslog.igloo
				fi
									
		else
			echo "BAD" >> syslog.igloo
	fi
  echo " " >> $CREATE_FILE 2>&1

  if [ `cat syslog.igloo | grep "BAD" | wc -l` -eq 0 ]
    then
      echo "★ U-73. Result : GOOD" >> $CREATE_FILE 2>&1
    else
      echo "★ U-73. Result : BAD" >> $CREATE_FILE 2>&1
  fi
#end 

  rm -rf syslog.igloo


  echo " " >> $CREATE_FILE 2>&1
  echo " " >> $CREATE_FILE 2>&1
  echo "Completed"
  echo " "
}



#U1. 계정관리
U_01
U_02
U_03
U_04
U_05
U_06
U_07
U_08
U_09
U_10
U_11
U_12
U_13
U_14
U_15
#U2. 파일 및 디렉터리 관리
U_16
U_17
U_18
U_19
U_20
U_21
U_22
U_23
U_24
U_25
U_26
U_27
U_28
U_29
U_30
U_31
U_32
U_33
U_34
#U3. 서비스 관리
U_35
U_36
U_37
U_38
U_39
U_40
U_41
U_42
U_43
U_44
U_45
U_46
U_47
U_48
U_49
U_50
U_51
U_52
U_53
U_54
U_55
U_56
U_57
U_58
U_59
U_60
U_61
U_62
U_63
U_64
U_65
U_66
U_67
U_68
U_69
U_70
#U4. 패치 관리
U_71
U_72
U_73



echo "=================================  IP info  ==================================" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "================================  Network info  ==============================" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "===============================  Routing info  ===============================" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "===============================  Process info  ===============================" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "===========================  Environment variables  ==========================" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo "=================================  WEB info  =================================" >> $CREATE_FILE 2>&1
# 아파치 전문 출력
if [ $web != default ]; then
	ls $conf >> $CREATE_FILE 2>&1
	cat $conf >> $CREATE_FILE 2>&1
fi

echo "☞ 진단작업이 완료되었습니다. 수고하셨습니다!"

## "***************************************  전체 결과물 파일 생성 시작  ***********************************"
# 
#echo "서버명 또는 자산번호를 입력하여 주세요(input ID) "
#echo "(EX : igloo-server) : " 
#read ID
#
#_HOSTNAME=`hostname`
#CREATE_FILE_RESULT=${ID}"__"${_HOSTNAME}"__"`date +%m%d`.txt
##CREATE_FILE_RESULT=`hostname`"_"`date +%m%d`.txt
#echo > $CREATE_FILE_RESULT
#
#echo " "
#
#
#"***************************************  전체 결과물 파일 생성 끝 **************************************" #20150923-02
#170131
#echo "**************************************** 진단 결과만 출력 시작 *****************************************" #20150923-02
#
#echo "▶ Total result ◀" > `hostname`_result.txt 2>&1
#echo " " >> `hostname`_result.txt 2>&1
#
#cat $CREATE_FILE | egrep 'GOOD|BAD|Manual check' | grep '★ ' >> `hostname`_result.txt 2>&1
#
#echo " " >> `hostname`_result.txt 2>&1
#
#echo "**************************************** 진단 결과만 출력 끝 *******************************************" #20150923-02
#cat $CREATE_FILE >> $CREATE_FILE_RESULT 2>&1
#rm -Rf $CREATE_FILE 2>&1

unset FILES
unset HOMEDIRS
unset SERVICE_INETD
unset SERVICE
unset APROC1
unset APROC
unset ACONF
unset AHOME
unset ACFILE
unset ServiceDIR
unset vsfile
unset profile
unset result

rm -Rf list.txt
rm -Rf result.txt
rm -Rf telnetps.igloo ftpps.igloo
rm -Rf vsftpd.igloo
rm -Rf apa_Manual.txt
