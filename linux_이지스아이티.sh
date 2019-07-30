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



echo "========================== ���� ���� =========================" >> $HOSTNAME.txt 2>&1
echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-1] root ���� ���� ���� ����"  
echo "[U-1] root ���� ���� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/securetty �� pts/0 ~ pts/x ������ ���� �Ǿ� �ְų� �ּ�ó�� �Ǿ� ���� ���" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ���� ���� ���� �� auth required /lib/security/pam_securetty.so ������ �ּ�(#)���� �Ǵ� �ű� �߰��Ͽ����� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "22��, 23�� ��Ʈ ���� Ȯ��" >> $HOSTNAME.txt 2>&1
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
echo "auth	required	/lib/security/pam_securetty.so	// �ּ�(#)���� �Ǵ� �ű� ����" >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
cat /etc/pam.d/login >> $HOSTNAME.txt 2>&1
echo ". " >> $HOSTNAME.txt 2>&1
echo "SSH �ɼ� Ȯ��"  >> $HOSTNAME.txt 2>&1
echo "cat /etc/ssh/sshd_config | grep PermitRootLogin" >> $HOSTNAME.txt 2>&1
cat /etc/ssh/sshd_config | grep "PermitRootLogin" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[U-1] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-2] �н����� ���⼺"
echo "[U-2] �н����� ���⼺"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: MANUAL(Using LC6 or John the ripper) " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �н����带 �������� ȥ���� ������� �ʰ� �����ϰ� �����Ͽ����� ���" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "��ȣȭ ��� Ȯ��"  >> $HOSTNAME.txt 2>&1 
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
echo [U-2] �н����� ���⼺ TIP >> $HOSTNAME.txt 2>&1
echo "md5 = $ 1 $ ���� ����"  	                  			                 >> $HOSTNAME.txt 2>&1
echo "sha256 = $ 5 $ ���� ����"                          			            >> $HOSTNAME.txt 2>&1
echo "sha512 = $ 6 $ ���� ����"  												 >> $HOSTNAME.txt 2>&1 
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                        >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-3] ���� ��� �Ӱ谪 ����"  
echo "[U-3] ���� ��� �Ӱ谪 ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/pam.d/system-auth ���� �� auth  required  pam_tally[2].so  onerr=fail  deny=5  unlock_time=120  no_magic_root  reset" >> $HOSTNAME.txt 2>&1
echo "          account  required  pam_tally[2].so  no_magic_root �� �����Ǿ� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "����ϴ� pam_tally ����Ȯ��" >> $HOSTNAME.txt 2>&1 
echo "find / -name "*pam_tally*"" >> $HOSTNAME.txt 2>&1 
find / -name "*pam_tally*"        >> $HOSTNAME.txt 2>&1 
echo " " >> $HOSTNAME.txt 2>&1
echo "���� ��� ���� Ȯ��" >>  $HOSTNAME.txt 2>&1 
echo "pam_tally"  >> $HOSTNAME.txt 2>&1 
pam_tally >> $HOSTNAME.txt 2>&1 
echo "." >> $HOSTNAME.txt 2>&1
echo "pam_tally2" >> $HOSTNAME.txt 2>&1 
pam_tally2 >> $HOSTNAME.txt 2>&1 
echo "." >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "telnet �Ӱ谪 �������� Ȯ��" >> $HOSTNAME.txt 2>&1 
echo "cat /etc/pam.d/remote" >> $HOSTNAME.txt 2>&1 
cat /etc/pam.d/remote >> $HOSTNAME.txt 2>&1 
echo " " >> $HOSTNAME.txt 2>&1
echo "ssh �Ӱ谪 �������� Ȯ��" >> $HOSTNAME.txt 2>&1 
echo "cat /etc/pamd.d/sshd" >> $HOSTNAME.txt 2>&1 
cat /etc/pam.d/sshd  >> $HOSTNAME.txt 2>&1 

echo " " >> $HOSTNAME.txt 2>&1 
echo "system-auth Ȯ�� " >> $HOSTNAME.txt 2>&1 

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
echo [U-3] ���� ��� �Ӱ谪 ���� TIP 												>> $HOSTNAME.txt 2>&1
echo ���� �Ӱ谪�� �����Ϸ��� pam_tally.so ��� ���̺귯���� ����ϴµ� ������ ������ ���� >> $HOSTNAME.txt 2>&1 
echo pam_tally.so[������]  pam_tally2.so[�Ź���] �� ��ġ�Ǿ������Ƿ� �ش� ������ �µ��� �����ؾ��Ѵ�. >> $HOSTNAME.txt 2>&1 
echo telnet �� ��� /etc/pam.d/remote �� ������ �Ѵ�.                                                  >> $HOSTNAME.txt 2>&1 
echo ssh �� ��� /etc/pamd.d/sshd �� ������ �Ѵ�.                                                    >> $HOSTNAME.txt 2>&1 
echo ftp �� ��� /etc/pamd.d/ftp �� ������ �Ѵ�.[SFTP��� ssh��å������]        >> $HOSTNAME.txt 2>&1
echo �� ���Ͽ� ������ ���� ������ ���־���Ѵ�.                        >> $HOSTNAME.txt 2>&1 
echo ����] vi /etc/pam.d/sshd                                          >> $HOSTNAME.txt 2>&1             
echo ����] auth  required  pam_tally.so  onerr=fail  deny=5  unlock_time=1800  no_magic_root  reset  >> $HOSTNAME.txt 
echo ����] account  required  pam_tally.so  no_magic_root            >> $HOSTNAME.txt 2>&1 
echo ���� ���ÿ��� pam_tally2�� ����Ѵٸ� pam_tally2.so �� ����Ѵ�.   >> $HOSTNAME.txt 2>&1 
echo onerr=fail  : ������ �߻��ϸ� ���� ����                            >> $HOSTNAME.txt 2>&1
echo deny=5 : 5���� �Ӱ谪�� ���� [���� ���� ���]                      >> $HOSTNAME.txt 2>&1
echo unlock_time=120 : ���� ��� �� 2�� ���� ��� ���� 				>> $HOSTNAME.txt 2>&1
echo no_magic_root : root ������ ����� �ʵ��� ����                        >> $HOSTNAME.txt 2>&1
echo reset : �α����� �����ϸ� badcount �� reset��                           >> $HOSTNAME.txt 2>&1
echo ��ݼ����� ������ �ʱ�ȭ �ϰ�ʹٸ� ���������� �����Ѵ�                 >> $HOSTNAME.txt 2>&1
echo pam_tally2 ���� = pam_tally2 -u [username] -r                        >> $HOSTNAME.txt 2>&1
echo pam_tally ���� = faillog -u [username] -r 												>> $HOSTNAME.txt 2>&1
echo �ش��׸���� �������Ͽ��� ã���� ���ٸ� �����                             >> $HOSTNAME.txt 2>&1
echo ������� �������� �� ��å�� �ݿ��Ұ�� �����ؾ� �ϴ°� ������ �߸��ϸ� root ���� �� �Ϲݰ����� ������� >> $HOSTNAME.txt 2>&1
echo �����Ͼ�� �Բ� ��å�� �ݿ��ϰ� �ּ� �Ѱ��� ������ root �������� ������ ������Ų�� �۾��Ϸ� ���θ� Ȯ������ �����Ѵ� >> $HOSTNAME.txt 2>&1 
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                               >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-4] �н����� ���� ��ȣ"
echo "[U-4] �н����� ���� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK] �н����� ������ /etc/shadow ���Ͽ� �����ϸ� ��ȣ" >> $HOSTNAME.txt 2>&1
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
echo [U-4] �н����� ���� ��ȣ TIP 												>> $HOSTNAME.txt 2>&1
echo �н����� �ؽ����� /etc/passwd �����Ѵٸ� �����            >> $HOSTNAME.txt 2>&1
echo ���� /etc/shadow ������ ������ �׿ܻ���ڰ� �аų� ���Ⱑ �����ص� �����  >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                               >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-5] root �̿��� UID�� '0' ����"  
echo "[U-5] root �̿��� UID�� '0' ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: if exists(UID = 0) except root THEN VUL" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: root������ ������ UID�� ���� ������ �������� ���� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
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
echo [U-5] root �̿��� UID�� '0' ���� TIP 												>> $HOSTNAME.txt 2>&1
echo root �̿ܿ� UID�� 0�� user�� ��µǸ� �����             >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                               >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-6] root ���� su ����"  
echo "[U-6] root ���� su ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/pam.d/su ���Ͽ� auth required /lib/security/pam_wheel.so debug group=wheel ������ �߰��Ǿ������� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: PAM����� ������� ���� ��� su ��ɾ ����� �׷��� �����ϰ�, /bin/su ������ ������ 4750���� ���� �� �����׷��� Ư���׷����� �����Ǿ� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/pam.d/su ]
  then
    echo "/etc/pam.d/su ����" >> $HOSTNAME.txt 2>&1
    cat /etc/pam.d/su >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/pam.d/su ������ �����ϴ�. " >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "/bin/su ����" >> $HOSTNAME.txt 2>&1
if [ `ls -al /bin/su | wc -l` -eq 0 ]
 then
   echo "/bin/su ������ �����ϴ�. " >> $HOSTNAME.txt 2>&1
 else
   ls -al /bin/su >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/group ���� wheel�׷쿡 ��ϵ� ����� Ȯ��" >> $HOSTNAME.txt 2>&1
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
echo [U-6] root ���� su ���� TIP												>> $HOSTNAME.txt 2>&1

echo su�� �����ϱ����ؼ��� ���������� �����Ǿ���Ѵ�.                           >> $HOSTNAME.txt 2>&1
echo �⺻������ �������ü������  /etc/pam.d/su ���Ͽ� pam_wheel.so    >> $HOSTNAME.txt 2>&1
echo �������� �ּ�ó���Ǿ����� �̺κ��� �ּ����� ���� wheel �׷쿡 su��  >> $HOSTNAME.txt 2>&1
echo ����� user�� ����ϸ� wheel �׷쿡 ��ϵ� ����ڸ� su ����� ����Ҽ� �ְԵ�  >> $HOSTNAME.txt 2>&1
echo ���� ���������� ����Ǹ� ���ΰ��ڰ� su �� ����Ͽ� �������� �н����带 �Է��ص� �н����尡 Ʋ�ȴٴ� �޼��� �� ��µǹǷ�  >> $HOSTNAME.txt 2>&1
echo ����� ������ �н����尡 Ʋ���� �˰Եȴ�.  >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                          				     >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-7] �н����� �ּ� ���� ����"  
echo "[U-7] �н����� �ּ� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �н����� �ּұ��̰� 9���� ������ ��� " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ����� �м��� ���ؿ��� 8���� �̻��̸� ��ȣ�ϳ�, ������ ������ ������ 9���� �̻��̹Ƿ�, 8���ڷ� �����Ǿ� ������ ��ȣ ������ ������, 9���� �̻����� �����ϵ��� �ǰ� " >> $HOSTNAME.txt 2>&1
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
				echo "���" >> $HOSTNAME.txt 2>&1
			else 
				echo "#grep PASS_MIN_LEN /etc/login.defs" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MIN_LEN /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_LEN /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "�������� �����ϴ�." >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-7] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-8] �н����� �ִ� ��� �Ⱓ ����"  
echo "[U-8] �н����� �ִ� ��� �Ⱓ ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �ִ� ���Ⱓ�� 90���� ũ�� ��� " >> $HOSTNAME.txt 2>&1
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
				echo "���" >> $HOSTNAME.txt 2>&1
			else 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MAX_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MAX_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#grep PASS_MAX_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
		grep PASS_MAX_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "�������� �����ϴ�.���" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-8] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-9] �н����� �ּ� ���Ⱓ ����"
echo "[U-9] �н����� �ּ� ���Ⱓ ���� �ۼ� �ʿ�"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �н����� �ּ� ���Ⱓ�� 0 �̸� ��� " >> $HOSTNAME.txt 2>&1
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
				echo "���" >> $HOSTNAME.txt 2>&1
			else 
				echo " " >> $HOSTNAME.txt 2>&1
				echo "#grep PASS_MIN_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
				grep PASS_MIN_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo " " >> $HOSTNAME.txt 2>&1
		echo "#grep PASS_MIN_DAYS /etc/login.defs" >> $HOSTNAME.txt 2>&1
		grep PASS_MIN_DAYS /etc/login.defs >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		echo "�������� �����ϴ�." >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-9] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
 
echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-10] ���ʿ��� ���� ����"
echo "[U-10] ���ʿ��� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �̻�� ���� �� �ǽɽ����� ���� ���� ���� Ȯ�� && ������� �ʴ� Default ���� ����(ex: adm, lp, sync, shutdown, halt, news, uucp, operator, games, gopher, nfsnobody, squid" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �α��� ���� ��� ������ ���� �̻�� ���� �� �ǽɽ����� ���� Ȯ��" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo "���� Ȯ��" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/passwd" >> $HOSTNAME.txt 2>&1
cat /etc/passwd >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "Default ���� ����" >> $HOSTNAME.txt 2>&1
echo "cat /etc/passwd | egrep \"adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid\"" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | egrep "adm|lp|sync|shutdown|halt|news|uucp|operator|games|gopher|nfsnobody|squid" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "���� �α� Ȯ��" >> $HOSTNAME.txt 2>&1
echo "#cat /var/log/loginlog" >> $HOSTNAME.txt 2>&1
cat /var/log/loginlog >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "su �α� Ȯ��" >> $HOSTNAME.txt 2>&1
echo "#cat /var/log/sulog" >> $HOSTNAME.txt 2>&1
cat /var/log/sulog >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[�������Ȯ��]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
lastlog >> $HOSTNAME.txt 2>&1
echo "�α��� ���� ��� ����" >> $HOSTNAME.txt 2>&1
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
echo [U-10] ���ʿ��� ���� ���� TIP												>> $HOSTNAME.txt 2>&1
echo ���������� ���� OS��ġ��ú��� �����ϴ� �������� �ý��۰������̹Ƿ�        >> $HOSTNAME.txt 2>&1
echo ���� �ο��Ǿ����� �ʴ�.     												>> $HOSTNAME.txt 2>&1
echo ���������� ������ ���� �ο��� ����[UID500�̻�]�� ���������� Ȯ���Ѵ�.   >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                          				     >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-11] ������ �׷쿡 �ּ����� ���� ����"
echo "[U-11] ������ �׷쿡 �ּ����� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: MANUAL CHECK " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �������� �׷쿡 ���� ������ ���� ��� ���" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#cat /etc/group | grep "root"" >> $HOSTNAME.txt 2>&1
cat /etc/group | grep "root" >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-11] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-12] ������ �������� �ʴ� GID ����"  
echo "[U-12] ������ �������� �ʴ� GID ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �������� ���� ������ GID ������ ���� ��� ���" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �������� �������� �ʴ� �׷��� �����ϸ� ���" >> $HOSTNAME.txt 2>&1
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
echo "[U-13] ������ UID ����"  
echo "[U-13] ������ UID ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ������ UID�� ����� ��� " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#awk -F: '{print \$1 " = " \$3}' /etc/passwd" >> $HOSTNAME.txt 2>&1
awk -F: '{print $1 " = " $3}' /etc/passwd >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-13] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-14] ����� Shell ����"
echo "[U-14] ����� Shell ����" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �α����� �ʿ� ���� ������ ���� /bin/false(/bin/nologin) ���� ���� ���" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �α����� ���ʿ��� ������ ���� �����Ǿ� ���� ������(�� �κ� ����) ���" >> $HOSTNAME.txt 2>&1
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
    echo "/etc/passwd ������ �����ϴ�." >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "����: /etc/shadow Ȯ��" >> $HOSTNAME.txt 2>&1
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
echo [U-14] ����� Shell ���� TIP												>> $HOSTNAME.txt 2>&1
echo ���������� �ƹ����� �ο����� �ʾƵ� �������� ������ �����ϹǷ�  /bin/false ,  /no shell , bin/nologin   ������ �ʿ���    >> $HOSTNAME.txt 2>&1
echo ��1] news:x:9:13:news:/etc/news: [�н����� ������ �����̰�����]                                               >> $HOSTNAME.txt 2>&1
echo ��2] news:x:9:13:news:/etc/news:/sbin/nologin [�н����� �����ص� �����̺Ұ�����]                                 >> $HOSTNAME.txt 2>&1
echo ������ �����Ͽ� �ؽ�Ʈ�����縦 Ȱ��     >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo 			                                                          				     >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-15] Session Timeout ����"  
echo "[U-15] Session Timeout ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] �������� ���ų� TMOUT������ 600���� ũ�� ���" >> $HOSTNAME.txt 2>&1
echo "[CHECK] Csh ���� autologout �ɼ��� 10���� ũ�� ���" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "sh, ksh, bash ����" >> $HOSTNAME.txt 2>&1
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

echo "����: csh ����" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/csh.login | grep autologout" >> $HOSTNAME.txt 2>&1
cat /etc/csh.login | grep autologout >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/csh.cshrc | grep autologout" >> $HOSTNAME.txt 2>&1
cat /etc/csh.cshrc | grep autologout >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-15] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-16] root Ȩ, �н� ���͸� ���� �� �н� ����"  
echo "[U-16] root Ȩ, �н� ���͸� ���� �� �н� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: . �Ǵ� ..�� �� �� �Ǵ� �߰���  �����ϸ� ���" >> $HOSTNAME.txt 2>&1
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
echo [U-16] Session Timeout ���� TIP												>> $HOSTNAME.txt 2>&1
echo PATH ��μ����� ��.���� �� �� �Ǵ� �߰��� ����Ǿ� ���� ��� �����ڰ� ���� �ǵ��� ����� �������� ������ �ƴ� �����ڰ�   >> $HOSTNAME.txt 2>&1
echo ������ ������ ������ �� �ִ� ������ �ִ�.��.���� ��ġ�� �� �ڷ� �����Ǿ����� ������� �����  >> $HOSTNAME.txt 2>&1
echo ���� ���丮�� ��Ī�ϴ� ��.���� PATH ���� �� �ڿ� ��ġ�ϵ��� �����Ǿ��־����               >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-17] ���� �� ���͸� ������ ����(�ð����� �ɸ�)"  
echo "[U-17] ���� �� ���͸� ������ ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ������� ������ ���  " >> $HOSTNAME.txt 2>&1
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
echo [U-17] ���� �� ���͸� ������ ����											>> $HOSTNAME.txt 2>&1
echo /etc /tmp /bin /sbin ���͸��� ������ �����ڰ� ���ų� �׷��� �������� �ʴ������� ã����    >> $HOSTNAME.txt 2>&1
echo ��1] srwxrwxr-x 1  503  503 0 Dec  7  2010 mapping-tofaz_lkj [������, �׷��� ���� ����]  >> $HOSTNAME.txt 2>&1
echo -xdev �ɼ��� �ش��οܿ��� ã�� �ʴ¿ɼ� �� find / -xdev �� ��ü�� �˻��ϴ°� �ƴ� / �� �˻��ϴ°���    >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-18]  /etc/passwd ���� ������"  
echo "[U-18]  /etc/passwd ���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root�Ǵ� bin�� �ý��� ���� , 444(644)�̸� -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#ls -alL /etc/passwd" >> $HOSTNAME.txt 2>&1
ls -alL /etc/passwd >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/passwd | grep "...-.--.--.*.*" | wc -l` -eq 1 ]
	then
		echo "��ȣ" >> $HOSTNAME.txt 2>&1
	else
		echo "�۹̼��� 444(644)�� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-18] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-19]  /etc/shadow ���� ������ �� ���Ѽ���"  
echo "[U-19]  /etc/shadow ���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root, 400(600) -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#ls -al /etc/shadow" >> $HOSTNAME.txt 2>&1
ls -al /etc/shadow >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-19] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-20] /etc/hosts ���� ������ �� ���� ����"  
echo "[U-20] /etc/hosts ���� ������ �� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root�Ǵ� bin�� �ý��� ����, 600 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/hosts ] 
	then
		echo "ls -l /etc/hosts" >> $HOSTNAME.txt 2>&1
		ls -l /etc/hosts >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/hosts | grep ".r.-------.*.*" | wc -l` -eq 1 ]
			then
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "���" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/hosts ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-20] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-20]  /etc/hosts ���� ������ �� ���� ���� TIP											>> $HOSTNAME.txt 2>&1
echo �̷�â�����к��� ���̵���α����� ������ root�� �����۹̼��� 600 �̴�.    >> $HOSTNAME.txt 2>&1
echo �� ���׸��� ��ġ�ϸ� ����Ŭ DB ������ �Ұ��� ��� �ټ��߻� Ư�� �ַ�ǰ� �����κ��� Ȯ���ؾ���    >> $HOSTNAME.txt 2>&1
echo ���å���δ� 644������ ������ ������ �̷�â�����к� �Ǵܱ����� 600�� ��ȣ��                         >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-21]  /etc/(x)inetd.conf ���� ������ �� ���� ����"  
echo "[U-21]  /etc/(x)inetd.conf ���� ������ �� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root�Ǵ� bin�� �ý��� ����, ���� 600 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/inetd.conf ]
	then 
		echo "ls -alL /etc/inetd.conf" >> $HOSTNAME.txt 2>&1
		ls -alL /etc/inetd.conf >> $HOSTNAME.txt 2>&1
		
		echo " " >> $HOSTNAME.txt 2>&1
		if [ `ls -alL /etc/inetd.conf | grep ".r.-------.*.*" | wc -l` -eq 1 ]
			then
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "���" >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/inetd.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "���" >> $HOSTNAME.txt 2>&1
		fi
		
	else
		echo "/etc/xinetd.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
echo [U-21]  /etc/[x]inetd.conf ���� ������ �� ���� ���� TIP											>> $HOSTNAME.txt 2>&1
echo �̷�â�����к��� ���̵���α����� ������ root�� �����۹̼��� 600 �̴�.    >> $HOSTNAME.txt 2>&1
echo REDHAT �迭�� �⺻��ġ�� xinetd �� �̼�ġ �Ǿ��������� ���� /etc/xinetd.conf �� �������� �ʴ´ٸ� �̼�ġ�Ȱ��� N/Aó����    >> $HOSTNAME.txt 2>&1
echo "---------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-22] /etc/syslog.conf ���� ������ �� ���Ѽ���"  
echo "[U-22] /etc/syslog.conf ���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root�Ǵ� bin�� �ý��� ����, 644 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/syslog.conf ]
	then
		echo "#ls -lL /etc/syslog.conf" >> $HOSTNAME.txt 2>&1
		ls -lL /etc/syslog.conf  >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/syslog.conf | grep "...-.--.--.*.*" | wc -l` -eq 1 ]
			then
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "���" >> $HOSTNAME.txt 2>&1
		fi
		
	else
		echo "/etc/syslog.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
fi
if [ -f /etc/rsyslog.conf ]
	then
		echo "#ls -lL /etc/rsyslog.conf" >> $HOSTNAME.txt 2>&1
		ls -lL /etc/rsyslog.conf  >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/rsyslog.conf | grep "...-.--.--.*.*" | wc -l` -eq 1 ]
	then
		echo "��ȣ" >> $HOSTNAME.txt 2>&1
	else
		echo "���" >> $HOSTNAME.txt 2>&1
		fi
		
		
	else
		echo "/etc/rsyslog.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
echo [U-22] /etc/syslog.conf ���� ������ �� ���Ѽ��� TIP											>> $HOSTNAME.txt 2>&1
echo �̷�â�����к��� ���̵���α����� ������ root�� �����۹̼��� 644 �̴�.                         >> $HOSTNAME.txt 2>&1
echo ��쿡 ���� ���������� rsyslog.conf �� ����Ҽ�������                                      >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-23]  /etc/services ���� ������ �� ���Ѽ���"  
echo "[U-23]  /etc/services ���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: owner:root�Ǵ� bin�� �ý��� ����, Permission:644 -> OK " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/services ]
	then
		echo "#ls -lL /etc/services" >> $HOSTNAME.txt 2>&1
		ls -lL /etc/services >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
		if [ `ls -alL /etc/services | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
	then
		echo "��ȣ" >> $HOSTNAME.txt 2>&1
	else
		echo "���" >> $HOSTNAME.txt 2>&1
		fi
		
		
	else
		echo "/etc/services ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
echo [U-23] /etc/services ���� ������ �� ���Ѽ��� TIP											>> $HOSTNAME.txt 2>&1
echo �̷�â�����к��� ���̵���α����� ������ root�� �����۹̼��� 644 �̴�.    >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-24]  SUID, SGID, Sticky bit ���� ���� ����"  
echo "[U-24]  SUID, SGID, Sticky bit ���� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ���ʿ��ϰ� ������ SUID, SGID���� ���� " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ������ ���並 ���� ��ȣ ��� �Ǵ�. �Ұ��ҽ� �ֿ������� ����(4750- �Ϲݻ���� ���� ����) ���� ���·� ��ȣ ��� �Ǵ�" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "find /  -user root -type f \( -perm -04000 -o -perm -02000 \) -exec ls -al  {}  \;" >> $HOSTNAME.txt 2>&1
find / -user root -type f \( -perm -04000 -o -perm -02000 \) -xdev -exec ls -al  {}  \; >> $HOSTNAME.txt 2>&1
echo "### End. " >> $HOSTNAME.txt 2>&1

echo "�ֿ����� ����" >> $HOSTNAME.txt 2>&1
echo "�ֿ����� : /sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc" >> $HOSTNAME.txt 2>&1 
echo "�ֿ����� : /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute " >> $HOSTNAME.txt 2>&1
echo "�ֿ����� : /usr/bin/lpq /usr/bin/lprm-lpd " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
FILECHECK="/sbin/dump /usr/bin/lpq-lpd /usr/bin/newgrp /sbin/restore /usr/bin/lpr /usr/sbin/lpc /sbin/unix_chkpwd /usr/bin/lpr-lpd /usr/sbin/lpc-lpd /usr/bin/at /usr/bin/lprm /usr/sbin/traceroute /usr/bin/lpq /usr/bin/lprm-lpd"

for check in $FILECHECK
do
	
if [ -f $check ]
	then
		echo "#ls -la $check" >> $HOSTNAME.txt 2>&1
		ls -la $check >> $HOSTNAME.txt 2>&1
	else
		echo "$check ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
echo [U-24] SUID, SGID, Sticky bit ���� ���� ���� TIP											>> $HOSTNAME.txt 2>&1
echo �ֿ����Ͽ� ���� ���� ���� �� �����ϴ� ���񽺿� ������ ��ĥ �� ������, ���� �� �����ϰ� �����ؾ� �� >> $HOSTNAME.txt 2>&1
echo ��ũ��[lrwxrwxrwx] ����� ������ SUID ������ �Ҽ� �����Ƿ� ��󿡼� ���ܽ�Ŵ                >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------- "  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-25]  �����, �ý��� �������� �� ȯ������ ������ �� ���� ����"  
echo "[U-25]  �����, �ý��� �������� �� ȯ������ ������ �� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: Owner : root�Ǵ� bin�� ���� �ý��� ���� && 644 ���� �� ��� ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/profile ]
	then 
		echo "ls -l /etc/profile" >> $HOSTNAME.txt 2>&1
		ls -l /etc/profile >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
			if [ `ls -alL /etc/profile | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
				then
					echo "��ȣ" >> $HOSTNAME.txt 2>&1
				else
					echo "���" >> $HOSTNAME.txt 2>&1
			fi
		
	else
		echo "/etc/profile ������ �������� �ʽ��ϴ�" >> $HOSTNAME.txt 2>&1
fi

if [ -f /.profile ]
	then 
		echo "ls -l /.profile" >> $HOSTNAME.txt 2>&1
		ls -l /etc/.profile >> $HOSTNAME .txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
			if [ `ls -alL /.profile | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
				then
					echo "��ȣ" >> $HOSTNAME.txt 2>&1
				else
					echo "���" >> $HOSTNAME.txt 2>&1
			fi
		
	else
		echo "/.profile ������ �������� �ʽ��ϴ�" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-25] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-25] �����, �ý��� �������� �� ȯ������ ������ �� ���� ����											>> $HOSTNAME.txt 2>&1
echo �̷�â�����к��� ���̵���α����� ������ root�� �����۹̼��� 644 �̴�.    >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-26]  world writable ���� ����"  
echo "[U-26]  world writable ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: world writable ����(777����)�� �������� �ʰų� �ش� ���� ������ Ȯ�� �����ϸ� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: "										 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "������ڰ� ���� ������ ��������"									 >> $HOSTNAME.txt 2>&1 
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
echo [U-26] world writable ���� ���� TIP											>> $HOSTNAME.txt 2>&1
echo world writable ������ ������ ���氡���� ������ ���� [����] ������  ������ڰԿ� ���Ե�����     >> $HOSTNAME.txt 2>&1
echo �� ������ Ÿ���� link[lrwxrwxrwx] , soket[srwxrwxrwx] ������ �����Ѵ�[���ܿ� �ǹ̰����� ������ ���ϱ����� ������]         >> $HOSTNAME.txt 2>&1
echo ���� ����Ʈ�� ���� ����� ����Ͽ�  15000���α��� ������                                                         >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-27]  /dev�� �������� �ʴ� device ���� ����"  
echo "[U-27]  /dev�� �������� �ʴ� device ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: dev �� �������� ���� device ������ �����ϰ�, �������� ���� device �� ���� ���� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
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
echo [U-27] /dev�� �������� �ʴ� device ���� ���� TIP                  >> $HOSTNAME.txt 2>&1
echo  Major Number�� ���� ����̽� ����̹� �߿� �ϳ��� �����ϱ� ���� ����   >> $HOSTNAME.txt 2>&1
echo  Minor Number�� ����̽� ����̹����� Ư���� ����̽��� ����Ų��.					>> $HOSTNAME.txt 2>&1
echo  ���ʼ��ڴ� Major Number �̸� ������ڴ� Minor Number �̴�. 					>> $HOSTNAME.txt 2>&1
echo  �̷�â�����к� ���̵���ο����� �� Major, Ninor Number �� ������ ���� �ʴ� ������ �߸���  ���� Ȥ�� ������� �ʴ�  >> $HOSTNAME.txt 2>&1
echo  ���ʿ��� ������ ���ɼ��� �����Ƿ� Ȯ����  �����Ұ��� �ǰ�                        >> $HOSTNAME.txt 2>&1
echo ����] -rw-r--r-- 1 root root 80 Feb  9 20:24 /dev/.udev/db/block:loop1           >> $HOSTNAME.txt 2>&1
echo ����] ��¥ feb ���� �������� ���ʿ� �ִ¼��ڰ� Number �̸� �ϳ���ǥ�õǸ� Major Number �̴�.    >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-28] \$HOME/.rhosts, hosts.equiv ��� ����"  
echo "[U-28] \$HOME/.rhosts, hosts.equiv ��� ����" >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  rsh, rlogin, rexec���� ������� ������ ��ȣ, �ε����� ��� ������ 600���� ���� �� Ư�� ȣ��Ʈ�� ��밡���ϵ��� �����ϸ� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  �ش� ������ �������� �ʾƵ� ��ȣ ó��" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.equiv ] 
then
	echo "#ls -l /etc/hosts.equiv" >> $HOSTNAME.txt 2>&1
	ls -l /etc/hosts.equiv >> $HOSTNAME.txt 2>&1
	
		if [ `ls -alL /etc/hosts.equiv | grep ".r.-------.*root.*" | wc -l` -eq 1 ]
			then
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "���" >> $HOSTNAME.txt 2>&1
		fi
	
	echo "#cat /etc/hosts.equiv" >> $HOSTNAME.txt 2>&1
	cat /etc/hosts.equiv >> $HOSTNAME.txt 2>&1
else
	echo "#/etc/hosts.equiv ������ �������� ����" >> $HOSTNAME.txt 2>&1
	echo "��ȣ" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/passwd �� ��ϵ� ������ Ȩ���丮 .rhosts ���� ����" >> $HOSTNAME.txt 2>&1
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
		echo "$dir/.rhosts ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
echo [U-28]  \$HOME/.rhosts, hosts.equiv ��� ����											   >> $HOSTNAME.txt 2>&1
echo �̷�â�����к��� ���̵���α����� ������ root�� �����۹̼��� 600 �̴�. 				       >> $HOSTNAME.txt 2>&1
echo ���� hosts.equiv ���ϳ��� + �� ���Ե��� �ʵ����ؾ��Ѵ�. 								   >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################" >> $HOSTNAME.txt 2>&1
echo "[U-29] ���� IP �� ��Ʈ ����"  
echo "[U-29] ���� IP �� ��Ʈ ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: /etc/hosts.deny ���� all deny ���� Ȯ�� �� /etc/hosts.allow ���Ͽ� ���� ���� ���� �� IP�� �����Ǿ� ������ ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ������ ���� �������� �ַ�� � �� ��ȣ ó�� " >> $HOSTNAME.txt 2>&1
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
echo $file "�������� �ʽ��ϴ�." >> $HOSTNAME.txt 2>&1
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
echo [U-29] ���� IP �� ��Ʈ ���� TIP                  >> $HOSTNAME.txt 2>&1
echo  xinetd�� �⺻������ tcp-wrapper�� �����ϰ�����    >> $HOSTNAME.txt 2>&1
echo  tcpd��� tcp_wrapper�� ���� ���� ���� ��� �ްԵ�     >> $HOSTNAME.txt 2>&1
echo  tcpd - /etc/hosts.allow : ������� ��å 					>> $HOSTNAME.txt 2>&1
echo         /etc/hosts.deny  : ���ӽ��� ��å                  >> $HOSTNAME.txt 2>&1
echo  �� tcpd�� ��ġ���� �ʾҰų� ���͸��� �������� �ʴ´ٸ� tcp-wrapper�� ������� �ʴ°���		>> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-30]  hosts.lpd ���� ������ �� ���Ѽ���"  
echo "[U-30]  hosts.lpd ���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ������ root�Ǵ� bin�� ���� �ý��� ����  && 600 �����̸� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/hosts.lpd ] 
	then
		echo "#ls -al /etc/hosts.lpd" >> $HOSTNAME.txt 2>&1
		ls -al /etc/hosts.lpd >> $HOSTNAME.txt 2>&1
		echo " " >> $HOSTNAME.txt 2>&1
		
			if [ `ls -alL /etc/hosts.lpd | grep ".r.-------.*.*" | wc -l` -eq 1 ]
				then
					echo "��ȣ" >> $HOSTNAME.txt 2>&1
				else
					echo "���" >> $HOSTNAME.txt 2>&1
			fi
		
	else
		echo "/etc/hosts.lpd ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
echo [U-30] hosts.lpd ���� ������ �� ���Ѽ��� TIP                  >> $HOSTNAME.txt 2>&1
echo  hosts.lpd = �����ͼ������� Ŭ���̾�Ʈ�� �����ϴ�����     >> $HOSTNAME.txt 2>&1
echo �̷�â�����к� �ǰ���� ������ root �۹̼� 600                 >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-31]  NIS���� ��Ȱ��ȭ"  
echo "[U-31]  NIS���� ��Ȱ��ȭ"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: NIS disable�̰ų� ����� ������ ��ȣ" >> $HOSTNAME.txt 2>&1	
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated"

echo "NIS ���� ��������"   >> $HOSTNAME.txt 2>&1
ps -ef | grep yp | grep -v "grep"	>> $HOSTNAME.txt 2>&1


if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "NIS, NIS+ ���񽺰� ��������Դϴ�." >> $HOSTNAME.txt 2>&1
   else
    ps -ef | egrep $SERVICE | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


echo "." >> $HOSTNAME.txt 2>&1
echo "[U-31] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-32]  UMASK ���� ����"  
echo "[U-32]  UMASK ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  umask �������� 022(644����) ���Ϸ� ������ ��� ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "Umsk Ȯ��" >> $HOSTNAME.txt 2>&1
umask >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-32] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-33]  Ȩ ���丮 ������ �� ���� ����"  
echo "[U-33]  Ȩ ���丮 ������ �� ���� ����"  >> $HOSTNAME.txt 2>&1 
echo "[CHECK]:  Ȩ ���͸� �����ڰ� �ش� �����̰�, �Ϲ� ����� ���� ������ ���ŵ� ��� ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "CENTOS, REDHOT �迭 UID 500�̻� Ȯ��"     >> $HOSTNAME.txt 2>&1 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 && $3 > 500 || $3 == 500 {print $6}' | grep -wv "\/" | sort -u`
     
         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $HOSTNAME.txt 2>&1
         done
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "��Ÿ ������ �迭 UID 100�̻� Ȯ��" >> $HOSTNAME.txt 2>&1 
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 && $3 > 100 || $3 == 100 {print $6}' | grep -wv "\/" | sort -u`
         for dir in $HOMEDIRS
          do
            ls -dal $dir | grep '\d.........' >> $HOSTNAME.txt 2>&1
         done


echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "# /etc/passwd ����" >> $HOSTNAME.txt 2>&1
cat /etc/passwd >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-33] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-33] Ȩ ���丮 ������ �� ���� ���� TIP                  >> $HOSTNAME.txt 2>&1
echo UID�� 500�� �Ѿ�� ������ ���� Ȯ��[�����ϴ� �ý��� ����]     >> $HOSTNAME.txt 2>&1
echo Ȩ���͸��� �����ϴ� ������ ������, �۹̼�Ȯ�� �׿ܻ���ڰ� ���� ������ ������ �ȵ�    >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------#"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-34]  Ȩ ���丮�� ������ ���丮 ���� ����"  
echo "[U-34]  Ȩ ���丮�� ������ ���丮 ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: Ȩ ���丮�� ������ ���丮�� �ִ��� Ȯ���ϰ�, �ҹ����� �ų� �ǽɽ����� ���丮�� ���� ��� ���� ���� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
for U29 in `cat /etc/passwd | awk -F: 'length($6) > 0 && $3 > 500 || $3 == 500 { print $1 }'`
	do
		if [ -d `cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'` ]
			then
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
				echo "���� ID : $U29" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				TMP_HOMEDIR=`cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'`
				TMP_HOMEDIR2=`cat /etc/passwd | grep $U29 | awk -F: '{ print $3 }'`
				echo "Ȩ ���丮 : $TMP_HOMEDIR" >> $HOSTNAME.txt 2>&1
				echo "������ UID : $TMP_HOMEDIR2" >> $HOSTNAME.txt 2>&1
			   	echo " " >> $HOSTNAME.txt 2>&1
				echo "/etc/passwd�� ������ ���丮 $TMP_HOMEDIR ����.��ȣ" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
			else
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
				echo "���� ID : $U29" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				TMP_HOMEDIR=`cat /etc/passwd | grep $U29 | awk -F: '{ print $6":"$1 }' | grep -w $U29$ | awk -F: '{ print $1 }'`
				echo "Ȩ ���丮 : $TMP_HOMEDIR" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "/etc/passwd�� ������ ���丮 $TMP_HOMEDIR ����.���" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				echo "===========================================================================" >> $HOSTNAME.txt 2>&1
		fi
done
echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-34] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-35]  ������ ���� �� ���丮 �˻� �� ����"  
echo "[U-35]  ������ ���� �� ���丮 �˻� �� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  �ǽɽ��� ������ ���� �� ���丮�� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK]:  ������ ���� �� ��ȣ, ��� �Ǵ� �Ұ��ҽ� N/A ó��" >> $HOSTNAME.txt 2>&1
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
echo [U-35] ������ ���� �� ���丮 �˻� �� ���� TIP                  >> $HOSTNAME.txt 2>&1
echo �ǽɽ����� ������ ������ ã�´�.                                  >> $HOSTNAME.txt 2>&1
echo �������� ���н������� ������ ���ʻ�����¥�� ��ϵ��� �ʴ´�.                                    >> $HOSTNAME.txt 2>&1
echo �ֱ� ��¥���� ������ ���� �� ������ �׷� ������ �˼����� ����ڰ� ���Ե� ���� ���ַ� �м�       >> $HOSTNAME.txt 2>&1  
echo "-------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-36] Finger ���� ��Ȱ��ȭ"  
echo "[U-36] Finger ���� ��Ȱ��ȭ"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: Finger �׸��� Disable�Ǿ� �ְų� ������� ���� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
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
      echo "xinetd.d�� finger������ �����ϴ�" >> $HOSTNAME.txt 2>&1
fi

echo "netstat -na | grep tcp | grep 79 | grep LISTEN"  [79����Ʈ Ȯ��] >> $HOSTNAME.txt 2>&1
netstat -na | grep tcp | grep 79 | grep LISTEN         >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "chkconfig --list [���� ��������Ȯ��]"                                 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
chkconfig --list                                     >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-36] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-36] Finger ���� ��Ȱ��ȭ[TIP]                                       >> $HOSTNAME.txt 2>&1
echo finger-server�� �����Ǹ� TCP 79�� ��Ʈ�� ���µǸ�                        >> $HOSTNAME.txt 2>&1
echo /etc/xinetd.d/finger ������ �����ȴ�                                    >> $HOSTNAME.txt 2>&1
echo �ش� �׸��� finger-server �� �����Ǿ������� ���� �����̱⶧����          >> $HOSTNAME.txt 2>&1
echo 79����Ʈ�� ���¿� /etc/xinetd.d/finger ������ ���翩�θ� Ȯ���ؾ��� 			 >> $HOSTNAME.txt 2>&1
echo /etc/xinetd.d/finger ������ DISABLE = YES�� �����Ǿ��ִٸ� ��ȣ��                           >> $HOSTNAME.txt 2>&1
echo �׸��� ������ ���������� finger root@192.168.232.135 �� ���� �������                       >> $HOSTNAME.txt 2>&1
echo ���������� 79����Ʈ�� �̿��Ͽ� ���������� Ž���Ҽ��ִ� ������ �����ϱ�����                  >> $HOSTNAME.txt 2>&1
echo �� finger ��Ʈ�� 79�� ��Ʈ�� LISTEN�� �����ؾ���                                            >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-37] Anonymous FTP ��Ȱ��ȭ" 
echo "[U-37] Anonymous FTP ��Ȱ��ȭ" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : anonymous FTP ������ ������ ��� ��ȣ, /etc/passwd ���Ͽ� ftp ���� ����� ���" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : vsFTPD�� ��� anonymous_enable �ɼ��� NO�� �����Ǹ� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : TCP 21�� ��Ʈ�� ���µ��� �ʾ��� ��� N/Aó��" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "netstat -na | grep tcp | grep 21 | grep LISTEN"  [21����Ʈ Ȯ��] >> $HOSTNAME.txt 2>&1
netstat -na | grep tcp | grep 21 | grep LISTEN         >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "�Ϲ� FTP �� ProFTP Ȯ�� (ftp �������� Ȯ��)" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/passwd | grep ftp" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | grep ftp >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "vsFTP Ȯ��" >> $HOSTNAME.txt 2>&1
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
echo "[U-38]  r�迭 ���� ��Ȱ��ȭ"  
echo "[U-38]  r�迭 ���� ��Ȱ��ȭ"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] :rsh, rlogin, rexec (shell, login, exec) ���񽺰� ��Ȱ��ȭ �Ǿ��ְų� ������� ������쿡 ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
SERVICE_INETD="rsh|rlogin|rexec"

echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/xinetd.d ���� " >> $HOSTNAME.txt 2>&1
echo "------------------ " >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/xinetd.d | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV ����" >> $HOSTNAME.txt 2>&1
         cat /etc/xinetd.d/$VVV | grep -i "disable" >> $HOSTNAME.txt 2>&1
         echo "   " >> $HOSTNAME.txt 2>&1
        done
  else
      echo "xinetd.d�� ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/inet ���� " >> $HOSTNAME.txt 2>&1
echo "------------------ " >> $HOSTNAME.txt 2>&1
if [ `ls -alL /etc/inet | egrep $SERVICE_INETD | wc -l` -gt 0 ]
  then
     for VVV in `ls -alL /etc/inet | egrep $SERVICE_INETD | grep -v "ssf" | awk '{print $9}'`
        do
         echo " $VVV ����" >> $HOSTNAME.txt 2>&1
         cat /etc/inet/$VVV >> $HOSTNAME.txt 2>&1
         echo "   " >> $HOSTNAME.txt 2>&1
        done
  else
      echo "inet�� ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/xinetd.d or inetd.conf�� ���� " >> $HOSTNAME.txt 2>&1

SERVICE_INETD="shell|login|exec"

if [ -f /etc/inetd.conf ]
  then
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/inetd.conf ������ �������� �ʽ��ϴ�." >> $HOSTNAME.txt 2>&1
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
           echo "���" >> $HOSTNAME.txt 2>&1
          else
           echo "��ȣ" >> $HOSTNAME.txt 2>&1
        fi
        done
    else
      echo "��ȣ" >> $HOSTNAME.txt 2>&1
    fi
 elif [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | egrep -v "grep|klogin|kshell|kexec" |wc -l` -eq 0 ]
     then
        echo "��ȣ"    >> $HOSTNAME.txt 2>&1
     else
        echo "���"    >> $HOSTNAME.txt 2>&1
    fi
  else
     echo "��ȣ"        >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "chkconfig --list [���񽺻���Ȯ��]"		>> $HOSTNAME.txt 2>&1
chkconfig --list					 >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1

echo "�߰� Ȯ�� : 512(rexec), 513(rlogin), 514(rsh) ��Ʈ ���� Ȯ��" >> $HOSTNAME.txt 2>&1
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
echo [U-38] r�迭 ���� ��Ȱ��ȭ[TIP]                                                         >> $HOSTNAME.txt 2>&1
echo rsh-server �� ��ġ�ϰԵǸ� /etc/xinetd.d/rsh , rlogin, rexe �� ��ġ�Ǹ�                   >> $HOSTNAME.txt 2>&1
echo ������ ��Ʈ�� ���� ���µȴ� ��Ʈ��ȣ�� �Ʒ��� ����.                                       >> $HOSTNAME.txt 2>&1
echo TCP 512����Ʈ = rexec ����[etc/xinetd.d/rexec                                           >> $HOSTNAME.txt 2>&1
echo TCP 513����Ʈ = rlogin ����[etc/xinetd.d/rlogin               			       >> $HOSTNAME.txt 2>&1
echo TCP 514����Ʈ = rsh ����[etc/xinetd.d/rsh                                               >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-39]  cron���� ������ �� ���� ����"  
echo "[U-39]  cron���� ������ �� ����  ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : cron.allow �� cron.deny ������ ������ 640�̸����� �����Ǿ� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : cron.allow������ ������ ��� cron.deny ������ ��� ����" >> $HOSTNAME.txt 2>&1
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
echo "[U-40]  DoS ���ݿ� ����� ���� ��Ȱ��ȭ"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] :echo, discard, daytime, chargen ���񽺰� ��Ȱ��ȭ �Ǿ��ְų� ������� ������쿡 ��ȣ" >> $HOSTNAME.txt 2>&1
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
        echo " /etc/xinetd.d ���丮�� DOS���ݿ� ����� ���񽺰� ����" >> $HOSTNAME.txt 2>&1
      else
        ls -alL /etc/xinetd.d | egrep $DOS_INETD >> $HOSTNAME.txt 2>&1
    fi
  else
     echo "/etc/xinetd.d ���丮�� �������� �ʽ��ϴ�. " >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/inetd.conf ]
  then
	echo "# cat /etc/inetd.conf | grep -v '^ *#' | egrep $DOS_INETD" >> $HOSTNAME.txt 2>&1
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $DOS_INETD >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/inetd.conf ������ �������� ���� " >> $HOSTNAME.txt 2>&1
fi
echo " " >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "7 9 13 19�� ��Ʈ LISTEN����Ȯ��"			>> $HOSTNAME.txt 2>&1
netstat -na | grep ":7 " | grep LISTEN | grep tcp           >> $HOSTNAME.txt 2>&1
netstat -na | grep ":9 " | grep LISTEN | grep tcp           >> $HOSTNAME.txt 2>&1
netstat -na | grep ":13 " | grep LISTEN | grep tcp          >> $HOSTNAME.txt 2>&1
netstat -na | grep ":19 " | grep LISTEN | grep tcp          >> $HOSTNAME.txt 2>&1
echo "/etc/services ���� " >> $HOSTNAME.txt 2>&1
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
echo [U-40] DoS ���ݿ� ����� ���� ��Ȱ��ȭ[TIP]								      >> $HOSTNAME.txt 2>&1
echo "���� �ش缭�񽺸� ��ġ�Ϸ��� rsh-server ��Ű������ġ�ؾ��ϸ� ���񽺸� �����ϰԵǸ� ������ "                     >> $HOSTNAME.txt 2>&1
echo "��Ʈ���� ���µǰ� �Ǵµ� ����Ʈ�� ���� DOS ������ �õ��ɼ��ִ�.PORT�� ���µ��� ������ DOS������ �Ҽ�����"       >> $HOSTNAME.txt 2>&1
echo "���� ������� �����Ұ��� ���� ��Ʈ�� ���µǾ��ִ��� Ȯ���� ���񽺱������θ� Ȯ���Ѵ�. "                       >> $HOSTNAME.txt 2>&1
echo "/etc/xinetd.d/��ο��� ������ DISABLE �����ϴ��� /etc/service ���� ���񽺸� �ּ�ó���Ͽ� �����ص��ȴ�"          >> $HOSTNAME.txt 2>&1
echo "�߿��Ѱ��� ��Ʈ�� �����Ǿ������� �ȵȴ�."									      >> $HOSTNAME.txt 2>&1
echo "echo      = TCP�� UDP ������ ���� 7����Ʈ�� ����ϸ� �̰��� ����� �� ���� ������ �����Ǿ�����"			>> $HOSTNAME.txt 2>&1
echo "������ �����͸� �۽��� ȣ��Ʈ�� ���� ������ �۾��� ����, ���� ���� �ź� ���� ���ɼ��� �ſ����"                   >> $HOSTNAME.txt 2>&1
echo "daytime	= time�� ���� ����� ���������� ����� �б� ���� ���·� �����ϴ� ���� �ٸ�, �̼��񽺴� 13����Ʈ���� ���� "   >> $HOSTNAME.txt 2>&1                                                  
echo "chargen    = 19�� ��Ʈ���� �����ϸ� tcp��udp�� ����� tcp���� �����ϴ� ���� ������ ��ٸ��ٰ� �����̵Ǹ� ������ ��û��" >> $HOSTNAME.txt 2>&1
echo " ������ ������ ���� ������ ������ ��Ʈ���� ��� �۽��Ѵ�. udp �󿡼� ������ ��쿡�� ������ �׷��� ���ŵǱ⸦ "        >> $HOSTNAME.txt 2>&1
echo "��ٸ���. �ϳ��� �����ͱ׷��� ���ŵǸ�0~512�� ���ڷ� �̷���� ������ �׷����� �����Ѵ�. ���� �ź� ���ݿ� ���� ���"  >> $HOSTNAME.txt 2>&1
echo "discard    = 9�� ��Ʈ�� ���ؼ� TCP �� UDP ���� ���� �̰��� ����� �����μ� ���ߵǾ���. ���� �뵵�� �����ϴ� ��� �����͸� ������ ���̴�."    >> $HOSTNAME.txt 2>&1                                                                             >> $HOSTNAME.txt 2>&1
echo "/etc/service ���� ���񽺸� �ּ�ó���Ͽ��ٸ� �ݵ�� xinetd ���񽺸� ������ؾ� ��Ʈ�� ��������."			  >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"                         >> $HOSTNAME.txt 2>&1
echo " "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-41]  NFS ���� ��Ȱ��ȭ"  
echo "[U-41]  NFS ���� ��Ȱ��ȭ"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : ���ʿ��� NFS ���� ���� ������ ��Ȱ��ȭ �Ǿ� �ִ� ���" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "���μ��� ��������Ȯ��"			   >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep mountd | grep -v grep"			   >> $HOSTNAME.txt 2>&1
ps -ef | grep mountd | grep -v grep				   >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep nfsd | grep -v grep [nfs����]"			   >> $HOSTNAME.txt 2>&1
ps -ef | grep nfsd | grep -v grep					  >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep statd | grep -v grep"			  >> $HOSTNAME.txt 2>&1
ps -ef | grep statd | grep -v grep					  >> $HOSTNAME.txt 2>&1
echo "nfs ������Ʈ Ȯ��"			 >> $HOSTNAME.txt 2>&1
echo "netstat -na | grep :2049 | grep LISTEN"   >> $HOSTNAME.txt 2>&1
netstat -na | grep :2049 | grep LISTEN		 >> $HOSTNAME.txt 2>&1
echo "rpcinfo Ȯ��"				>> $HOSTNAME.txt 2>&1
rpcinfo -p localhost				>> $HOSTNAME.txt 2>&1

echo "[U-41] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-42]  NFS ��������"  
echo "[U-42]  NFS ��������" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : NFS ���� everyone ������ ������ ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep "nfs" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -gt 0 ]
 then
  if [ -f /etc/exports ]
   then
    grep -v '^ *#' /etc/exports  >> $HOSTNAME.txt 2>&1
   else
    echo "/etc/exports ������ �������� ����"  >> $HOSTNAME.txt 2>&1
  fi
 else
  echo "NFS ���񽺰� ��������Դϴ�." >> $HOSTNAME.txt 2>&1
fi


echo " " >> $HOSTNAME.txt 2>&1


if [ `ps -ef | egrep "nfs" | egrep -v "grep|statdaemon|automountd" | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "��ȣ" >> $HOSTNAME.txt 2>&1
 else
  if [ -f /etc/exports ]
    then
     if [ `cat /etc/exports | grep everyone | grep -v "^ *#" | wc -l` -eq 0 ]
       then
         echo "��ȣ" >> $HOSTNAME.txt 2>&1
       else
         echo "���" >> $HOSTNAME.txt 2>&1
     fi
    else
     echo "/etc/exports ������ �����ϴ�."  >> $HOSTNAME.txt 2>&1
  fi
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "############ �Ʒ� ���� ���� ##############" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/dfs/dfstab" >> $HOSTNAME.txt 2>&1
cat /etc/dfs/dfstab >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-42] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-43]  automountd ����"  
echo "[U-43]  automountd ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : automountd�� ������ ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo "  " >> $HOSTNAME.txt 2>&1
echo "automountd Ȯ�� " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep automountd | egrep -v "grep|rpc|statdaemon|emi" | grep -v grep | wc -l` -eq 0 ]
  then
    echo "automount ������ �����ϴ�." >> $HOSTNAME.txt 2>&1
  else
     ps -ef | grep automountd | egrep -v "grep|rpc|statdaemon|emi" | grep -v grep >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


if [ `ps -ef | grep automountd | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "��ȣ" >> $HOSTNAME.txt 2>&1
  else
     echo "���" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "automount ���μ��� Ȯ��"   >> $HOSTNAME.txt 2>&1
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
echo [U-43]  automountd ����[TIP]                                                         >> $HOSTNAME.txt 2>&1
echo automountd�� �����ϱ����ؼ� autofs ��Ű���� ��ġ�ؾ��Ѵ�.                    >> $HOSTNAME.txt 2>&1
echo automountd �� �����Ǿ��ִٸ� ��� rpc���񽺿� nfs ���񽺿� �ʼ������� ���õǱ⶧���� �ش����μ����� �����Ǿ����� Ȯ���̳���. >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-44] RPC ���� Ȯ��"
echo "[U-44] RPC ���� Ȯ��" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ���ʿ��� rpc ���� ���񽺰� �������� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
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
        echo " /etc/xinetd.d ���丮�� ���ʿ��� ���񽺰� ����" >> $HOSTNAME.txt 2>&1
      else
        ls -alL /etc/xinetd.d | egrep $SERVICE_INETD >> $HOSTNAME.txt 2>&1
    fi
  else
     echo "/etc/xinetd.d ���丮�� �������� �ʽ��ϴ�. " >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

if [ -f /etc/inetd.conf ]
  then
	echo "# cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD" >> $HOSTNAME.txt 2>&1
    cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD >> $HOSTNAME.txt 2>&1
  else
    echo "/etc/inetd.conf ������ �������� ���� " >> $HOSTNAME.txt 2>&1
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
           echo "���" >> rpc.txt
          else
           echo "��ȣ" >> rpc.txt
        fi
        done
    else
      echo "��ȣ" >> rpc.txt
    fi
fi

if [ -f /etc/inetd.conf ]
  then
    if [ `cat /etc/inetd.conf | grep -v '^ *#' | egrep $SERVICE_INETD | wc -l` -eq 0 ]
              then
                 echo "��ȣ" >> rpc.txt
              else
                 echo "���" >> rpc.txt
    fi
fi


if [ `cat rpc.txt | grep "���" | wc -l` -eq 0 ]
 then
  echo "��ȣ" >> $HOSTNAME.txt 2>&1
 else
  echo "���" >> $HOSTNAME.txt 2>&1
fi

rm -rf rpc.txt

echo "���λ��� ���� Ȯ�� " >> $HOSTNAME.txt 2>&1
echo "ls -ail /etc/xinetd.d"  >> $HOSTNAME.txt 2>&1
ls -alL /etc/xinetd.d  >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-44] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo [U-44] RPC ���� Ȯ��[TIP]                                                                     >> $HOSTNAME.txt 2>&1
echo �������� inetd.conf���Ͽ� �����Ǿ��ִ� ��İ� /etc/xinetd.d/ ���丮�ȿ� �������·� �����Ǿ��ִ� 2���� ����� �����Ѵ�.  >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-45]  NIS, NIS+ ����"  
echo "[U-45]  NIS, NIS+ ���� �ۼ� �ʿ�"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: NIS disable�̰ų� ����� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
   then
    echo "NIS, NIS+ ���񽺰� ��������Դϴ�." >> $HOSTNAME.txt 2>&1
   else
    echo "#ps -ef | egrep \$SERVICE | grep -v grep" >> $HOSTNAME.txt 2>&1
    ps -ef | egrep $SERVICE | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1


SERVICE="ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd"

if [ `ps -ef | egrep $SERVICE | grep -v "grep" | wc -l` -eq 0 ]
     then
        echo "��ȣ" >> $HOSTNAME.txt 2>&1
     else
        echo "���" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "�������μ��� ã��[ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated|rpc.nisd]"  >> $HOSTNAME.txt 2>&1
echo "ps -ef | grep ���μ����� | grep -v grep"  >> $HOSTNAME.txt 2>&1
ps -ef | grep ypserv | grep -v grep   >> $HOSTNAME.txt 2>&1
ps -ef | grep ypbind | grep -v grep   >> $HOSTNAME.txt 2>&1
ps -ef | grep ypxfrd | grep -v grep    >> $HOSTNAME.txt 2>&1
ps -ef | grep rpc.yppasswdd | grep -v grep >> $HOSTNAME.txt 2>&1
ps -ef | grep rpc.ypupdated | grep -v grep >> $HOSTNAME.txt 2>&1
ps -ef | grep rpc.nisd  | grep -v grep    >> $HOSTNAME.txt 2>&1
echo "[U-45] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-46] Tftp, Talk Ȱ��ȭ ����"  
echo "[U-46] Tftp, Talk Ȱ��ȭ ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: tftp , tallk ���񽺸� ��Ȱ��ȭ ������ ��� ��ȣ  " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "Tftp Ȯ��" >> $HOSTNAME.txt 2>&1
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
		echo "/etc/inetd.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
		echo "/etc/xinetd.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1	
	echo " " >> $HOSTNAME.txt 2>&1			
fi
echo "tftp ���μ��� �� ���� ���� Ȯ��"  >> $HOSTNAME.txt 2>&1
echo "ls -al /etc/xinetd.d | grep tftp"              >> $HOSTNAME.txt 2>&1
ls -al /etc/xinetd.d | grep tftp                   >> $HOSTNAME.txt 2>&1
echo "netstat -al | grep tftp"			  >> $HOSTNAME.txt 2>&1
netstat -al | grep tftp				>> $HOSTNAME.txt 2>&1
echo "netstat -na | grep :69 | grep udp"	 >> $HOSTNAME.txt 2>&1
netstat -na | grep :69 | grep udp                  >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "Talk Ȯ��" >> $HOSTNAME.txt 2>&1
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
		echo "/etc/inetd.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
		echo "/etc/xinetd.conf ������ �����ϴ�" >> $HOSTNAME.txt 2>&1	
		echo " " >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1

echo "talk ���μ��� �� ���� ���� Ȯ��"  >> $HOSTNAME.txt 2>&1
echo "ls -al /etc/xinetd.d | grep talk"              >> $HOSTNAME.txt 2>&1
ls -al /etc/xinetd.d | grep talk                   >> $HOSTNAME.txt 2>&1
echo "netstat -al | grep talk"			  >> $HOSTNAME.txt 2>&1
netstat -al | grep talk				>> $HOSTNAME.txt 2>&1
echo "netstat -na | grep :517 | grep udp"	 >> $HOSTNAME.txt 2>&1
netstat -na | grep :517 | grep udp                  >> $HOSTNAME.txt 2>&1




echo "[U-46] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-47] Sendmail ���� ����"
echo "[U-47] Sendmail ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : sendmail ���� Ȯ�� �� �ֽŹ����� ��(2013��5������ �ֽŹ��� 8.13.8 �̻� �ǰ�)" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE] : " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "sendmail ���μ��� Ȯ��" >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep sendmail | grep -v "grep" | wc -l` -eq 0 ]
 then
  echo "Sendmail ���񽺰� ��������Դϴ�.��ȣ" >> $HOSTNAME.txt 2>&1
  touch sendmail_tmp 
 else
  ps -ef | grep sendmail | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
if [ -f sendmail_tmp ]
	then
	echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "sendmail ����Ȯ��" >> $HOSTNAME.txt 2>&1
		if [ -f /etc/mail/sendmail.cf ]
			then
				grep -v '^ *#' /etc/mail/sendmail.cf | grep DZ >> $HOSTNAME.txt 2>&1
			else
				echo "/etc/mail/sendmail.cf ���� ����" >> $HOSTNAME.txt 2>&1
		fi
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "sendmail ��ġ���� �� �������� Ȯ��"   >> $HOSTNAME.txt 2>&1
echo "rpm -qa sendmail"                     >> $HOSTNAME.txt 2>&1
rpm -qa sendmail                            >> $HOSTNAME.txt 2>&1
echo "ls -al /etc/mail | grep "sendmail""   >> $HOSTNAME.txt 2>&1
ls -al /etc/mail | grep "sendmail"  >> $HOSTNAME.txt 2>&1
echo "netstat -na | grep LISTEN | grep tcp | grep :25"    >> $HOSTNAME.txt 2>&1
netstat -na | grep LISTEN | grep tcp | grep :25          >> $HOSTNAME.txt 2>&1
echo "postfix ���ϼ��� ��������"                           >> $HOSTNAME.txt 2>&1
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
echo [U-47] Sendmail ���� ����[TIP]                                                                     >> $HOSTNAME.txt 2>&1
echo Sendmail�� ��ġ���� �ʾҴµ� 25����Ʈ�� LISTEN�ϰ� �ִٸ� CentOS6, REDHOT �ֽŹ����� sendmail�� �ƴ� postfix ��� ���ϼ��񽺸� �����   >> $HOSTNAME.txt 2>&1
echo postfix �� ������ü�� Sendmail�� �ٸ��Ƿ� Sendmail �׸�� ���缭 �����ϱ�� �����  N/Aó����      >> $HOSTNAME.txt 2>&1
echo "--------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo   >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-48]  ���� ���� ������ ����"  
echo "[U-48]  ���� ���� ������ ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : ���� ���� ������ ���� ������ �� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/mail/access ��åȮ��" >> $HOSTNAME.txt 2>&1 

if [ -f sendmail_tmp ]
	then
		echo "Sendmail ���񽺰� ����� ���Դϴ�" >> $HOSTNAME.txt
		echo " " >> $HOSTNAME.txt
	else
		if [ -f /etc/mail/access ]
			then
				echo "#cat /etc/mail/access" >> $HOSTNAME.txt 2>&1
				cat /etc/mail/access >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
			else
				echo "/etc/mail/access ������ �����ϴ�.���" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
fi
	
echo " " >> $HOSTNAME.txt 2>&1
echo "/etc/mail/sendmail.cf ��å����Ȯ��" 											>> $HOSTNAME.txt 2>&1 
echo "/etc/mail/sendmail.cf | egrep REJECT|OK|RELAY" >> $HOSTNAME.txt 2>&1
cat /etc/mail/sendmail.cf | egrep "REJECT|OK|RELAY" >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "."													 >> $HOSTNAME.txt 2>&1
echo "�Ʒ� /etc/mail/sendmail.cf ���ϳ��� ���ο� Addr=127.0.0.1 ������ ���ų� 0.0.0.0���� �Ǿ��ִٸ�  ��� IP�� ��������� ����� "					 >> $HOSTNAME.txt 2>&1
echo "cat /etc/mail/sendmail.cf | grep O DaemonPortOptions"							>> $HOSTNAME.txt 2>&1
cat /etc/mail/sendmail.cf | grep "O DaemonPortOptions"								  >> $HOSTNAME.txt 2>&1
echo "[U-48] End"												>> $HOSTNAME.txt 2>&1
echo " "													 >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "-----------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo [U-48]  ���� ���� ������ ����[TIP]											>> $HOSTNAME.txt 2>&1
echo "�Ϻ� relay �� Ǯ�� �ֱ� ���ؼ� sendamil.cf �� ���� �ϴ� ������� �ִµ� �̷� ��� spammer ���� ǥ���� �Ǿ�  "		>> $HOSTNAME.txt 2>&1
echo "�ٸ� ���� ������ ���� reject �� ���Ҽ��� ������ sendmail.cf �� �����Ͽ� ��ü relay �� Ǫ�� �ȵ�."	 >> $HOSTNAME.txt 2>&1
echo "OK = [host����������] ������ ������ ���[relay]�Ѵ�. "									>> $HOSTNAME.txt 2>&1
echo "RELAY = [host����������]������ ����/�߽��� ����Ѵ�."									>> $HOSTNAME.txt 2>&1
echo "REJECT = [host����������]������ ����/�߽��� �ź��Ѵ�."									>> $HOSTNAME.txt 2>&1
echo "DISCARD = /etc/sendmail.cf�� ������ $#discard mailer�� �����Ȱ����� ������ �����.(�߽��ڴ� ������ �߽ŵȰ����� �˰Ե�."  >> $HOSTNAME.txt 2>&1
echo "501 <message> ������ user@host �� �߽����� �ּҰ� ��ü Ȥ�� �κ������� ��ġ�� ��� �̸����� ���� �ʴ´�. "			 >> $HOSTNAME.txt 2>&1
echo "553 <message> �߽����� �ּҿ� ȣ��Ʈ���� ���� ��� ������ ���� �ʴ´�."							>> $HOSTNAME.txt 2>&1
echo "550 <message> ������ �����ΰ� ���õ� ������ ���� �ʴ´�."									>> $HOSTNAME.txt 2>&1
echo "���� ���� ������ ���μ� 111.111.111.111 �̶�� pc ���� ������ �߼��ϱ⸦ ���Ѵٸ�"					 >> $HOSTNAME.txt 2>&1
echo "111.111.111.111		RELAY"												 >> $HOSTNAME.txt 2>&1
echo "��� ������ ������ �ִ� ������ ������ �߼��� �Ҽ� �ִ�."									 >> $HOSTNAME.txt 2>&1
echo "����]  cyberspammer.com        REJECT"											 >> $HOSTNAME.txt 2>&1
echo "����]  sendmail.org            OK"  										 >> $HOSTNAME.txt 2>&1
echo "����]  128.32                  RELAY"											 >> $HOSTNAME.txt 2>&1
echo "����]  localhost.localdomain   RELAY"											 >> $HOSTNAME.txt 2>&1
echo "����]  localhost               RELAY"											 >> $HOSTNAME.txt 2>&1
echo "����]   127.0.0.1              RELAY"											 >> $HOSTNAME.txt 2>&1
echo "����]  linux.rootman.org                     REJECT"                                >> $HOSTNAME.txt 2>&1
echo "����]  linux.rootman.org                     501 Oh.. No.. linux.rootman.org"                                             >> $HOSTNAME.txt 2>&1
echo "����]  linux.rootman.org                     571 You are spammer.. "                                                     >> $HOSTNAME.txt 2>&1
echo "/etc/mail/access ���� RELAY ������ ��ģ �Ŀ��� access.db �� ������ ��� �Ѵ�."						 >> $HOSTNAME.txt 2>&1
echo "makemap hash /etc/mail/access < /etc/mail/access"									   >> $HOSTNAME.txt 2>&1
echo "����� �����Ͽ� ������ �Ҽ��� �ִ�. access ������ �����ÿ��� sendmail�� ����� ��"					   >> $HOSTNAME.txt 2>&1
echo "�ʿ�� ������ makemap �� �̿��Ͽ� access.db �� ������ �ָ� �ٷ� ������ �ȴ�."						  >> $HOSTNAME.txt 2>&1
echo "DB�� ���������� ����Ǿ����� Ȯ���ϴ� ��ɾ�� ������ ���� strings access.db | grep 192"					 >> $HOSTNAME.txt 2>&1
echo "---------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-49]  �Ϲݻ������ Sendmail ���� ����"  
echo "[U-49]  �Ϲݻ������ Sendmail ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : sendmail ���� ������ PrivacyOptions=authwarnings,restrictqrun ���� �����Ǿ� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
	then
		echo "Sendmail ���񽺰� ����� ���Դϴ�.��ȣ" >> $HOSTNAME.txt 2>&1
	else
		echo "#/etc/mail/sendmail.cf ������ �ɼ� Ȯ��" >> $HOSTNAME.txt 2>&1
			if [ -f /etc/mail/sendmail.cf ]
				then
					    if [ `cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn|restrictqrun" | grep -v "grep" | wc -l ` -eq 1 ]
							then
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn|restrictqrun" | grep -v "grep" >> $HOSTNAME.txt 2>&1
								echo " " >> $HOSTNAME.txt 2>&1
							else
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn|restrictqrun" | grep -v "grep" >> $HOSTNAME.txt 2>&1	
								echo "���" >> $HOSTNAME.txt 2>&1
						fi
				else
					echo "/etc/mail/sendmail.cf ���� ����." >> $HOSTNAME.txt 2>&1
					echo " " >> $HOSTNAME.txt 2>&1
			fi
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-49] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-50] DNS ���� ���� ��ġ"  
echo "[U-50] DNS ���� ���� ��ġ"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ���� �̿��� BIND ������ ����ϸ� ���(8.4.6, 8.4.7, 9.2.8-P1, 9.3.4-P1, 9.4.1-P1, 9.5.0a6)" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: DNS���񽺰� �������� ���� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
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
echo "[U-51]  DNS ZoneTransfer ����"  
echo "[U-51]  DNS ZoneTransfer ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : zone ���� ������ Ư�� ȣ��Ʈ�� ���� (allow-transfer { IP; }) �Ǿ� �ְų� options xfrnets IP�� �����Ǿ� �ִٸ� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "<DNS ���μ��� Ȯ��> " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
    echo "DNS�� ��������Դϴ�." >> $HOSTNAME.txt 2>&1
  else
    ps -ef | grep named | grep -v "grep" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/named.conf ������ allow-transfer Ȯ��" >> $HOSTNAME.txt 2>&1
   if [ -f /etc/named.conf ]
     then
      cat /etc/named.conf | grep 'allow-transfer' >> $HOSTNAME.txt 2>&1
     else
      echo "/etc/named.conf ���� ����" >> $HOSTNAME.txt 2>&1
   fi

echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/named.boot ������ xfrnets Ȯ��" >> $HOSTNAME.txt 2>&1
   if [ -f /etc/named.boot ]
     then
       cat /etc/named.boot | grep "\xfrnets" >> $HOSTNAME.txt 2>&1
     else
       echo "/etc/named.boot ���� ����" >> $HOSTNAME.txt 2>&1
   fi

echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep named | grep -v "grep" | wc -l` -eq 0 ]
  then
     echo "��ȣ" >> $HOSTNAME.txt 2>&1
  else
     if [ -f /etc/named.conf ]
       then
         if [ `cat /etc/named.conf | grep "\allow-transfer.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "^ *#" | wc -l` -eq 0 ]
            then
               echo "���" >> $HOSTNAME.txt 2>&1
            else
               echo "��ȣ" >> $HOSTNAME.txt 2>&1
          fi
        else
          if [ -f /etc/named.boot ]
           then
             if [ `cat /etc/named.boot | grep "\xfrnets.*[0-256].[0-256].[0-256].[0-256].*" | grep -v "^ *#" | wc -l` -eq 0 ]
            then
               echo "���" >> $HOSTNAME.txt 2>&1
            else
               echo "��ȣ" >> $HOSTNAME.txt 2>&1
            fi
           else
              echo "���" >> $HOSTNAME.txt 2>&1
          fi

     fi
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-51] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-52]  Apache ���丮 ������ ����"  
echo "[U-52]  Apache ���丮 ������ ����)"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : ���丮 ������ �ɼ�(Indexes)�� ��� ���丮���� ���� �Ǿ� ���� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
	     ps -ef | grep httpd | grep -v "grep"   >> $HOSTNAME.txt 2>&1
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) ��û �� ���� ����" >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-52] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-53]  Apache �� ���μ��� ���� ����"  
echo "[U-53]  Apache �� ���μ��� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : �ʱ� ������ httpd ������ ������ �� ���μ����� �����ڰ� Root�� �ƴҰ�� && �� ���μ��� ������ \bin\false �Ǵ� nologin�� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) ��û �� ���� ����" >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-53] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "##################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-54]  Apache ���� ���丮 ���� ����"  
echo "[U-54]  Apache ���� ���丮 ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : AllowOverride �������� �ɼ��� None �̸� ���, AuthConfig �� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) �� ���� ������ ���丮�� .htaccess ���� ��û �� ���� �Ǵ� �������� ����" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-54] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-55]  Apache ���ʿ��� ���� ����"  
echo "[U-55]  Apache ���ʿ��� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : �Ŵ��� ���� �� ���͸��� ���ŵǾ� �ִ� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "[Apache_home]/htdocs/manual �� [Apache_home]/manual ���� ���� ���� ���� Ȯ��" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-55] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-56]  Apache ��ũ ������"  
echo "[U-56]  Apache ��ũ ������"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : Options �� FollowSymLinks�� ���� �Ǿ� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) ��û �� ���� ����" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-56] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-57]  Apache ���� ���ε� �� �ٿ�ε� ����"  
echo "[U-57]  Apache ���� ���ε� �� �ٿ�ε� ���� �ۼ� �ʿ�"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : ���� ���ε� �� �ٿ�ε� �뷮�� �����丮���� ���ѽ� ��ȣ. �������� ������ ���" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) ��û �� ���� ����" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-57] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-58]  Apache �� ���� ������ �и�"  
echo "[U-58]  Apache �� ���� ������ �и�"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : DocumentRoot�� /usr/local/apache/htdocs�� �ƴ� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) ��û �� ���� ����" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-58] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###############################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-59] ssh �������� ���"  
echo "[U-59] ssh �������� ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ���� ���� �� SSH ���������� ����ϴ� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �� �Ǵܱ����� �����ϱ� ��ȣ�� ��� 22�� ��Ʈ�� ���µǾ� ������ ��ȣ ó��" >> $HOSTNAME.txt 2>&1
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
echo [U-59]  ssh �������� ��� TIP										             	>> $HOSTNAME.txt 2>&1
echo "telnet ���񽺰� �����Ѵٸ� ssh �� ������� �ʰ� telnet ��뿩���� ���ܵδ°��̹Ƿ� Ȯ���ʿ���"  >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"  >> $HOSTNAME.txt 2>&1
echo " "  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1





echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-60] ftp ���� Ȯ��"
echo "[U-60] ftp ���� Ȯ��" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: FTP ���񽺰� ��Ȱ��ȭ �Ǿ� �ִ� ��� ��ȣ  " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "21����Ʈ LISTEN ���� Ȯ��" >> $HOSTNAME.txt 2>&1 
echo "netstat -na | grep 21 | grep LISTEN | grep tcp"   >>  $HOSTNAME.txt 2>&1 
netstat -na | grep 21 | grep LISTEN | grep tcp >> $HOSTNAME.txt 2>&1 

echo "�Ϲ� FTP Ȯ��" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/inetd.conf | grep ftp" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "ProFTP Ȯ�� #ps -ef | grep proftpd | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep proftpd | grep -v grep >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "vsFTP Ȯ�� #ps -ef | grep vsftpd | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep vsftpd | grep -v grep >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-60] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-61]  ftp ���� shell ����"  
echo "[U-61]  ftp ���� shell ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ftp ������ shell �� /bin/false�� �ο��Ǿ� �ִ� ��� ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#cat /etc/passwd | grep ftp" >> $HOSTNAME.txt 2>&1
cat /etc/passwd | grep ftp >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1

echo "[U-61] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-62] Ftpusers ���� ������ �� ���Ѽ���"  
echo "[U-62] Ftpusers ���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: ������ root && 640 �����Ͻ� ��ȣ" >> $HOSTNAME.txt 2>&1
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
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "�۹̼��� 640�� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
				echo "���" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
		echo " " >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/ftpusers ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "�۹̼��� 640�� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
				echo "���" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/ftpd/ftpusers ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
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
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
			else
				echo "�۹̼��� 640�� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
				echo "���" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
		fi
	else
		echo "/etc/vsftpd/ftpusers ������ �����ϴ�" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-62] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "----------------------------------------------------------------------------------------"										>> $HOSTNAME.txt 2>&1
echo [U-62] Ftpusers ���� ������ �� ���Ѽ���[TIP]																					>> $HOSTNAME.txt 2>&1
echo "Ftpusers ������ ftp�� ����ϴ� �������� ������ ���ѶǴ� ����ϴ� �����ε� SFTP�� SSH�� �Բ� 22����Ʈ�� ���������"	     	>> $HOSTNAME.txt 2>&1
echo "FTPUSERS ������ �������� �ʴ´�. "												                                            >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"										>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-63] Ftpusers ���� ����"  
echo "[U-63] Ftpusers ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: FTP�� Ȱ��ȭ �Ǿ� �ִ� ��� root ���� ������ �������� ��츸 ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "�Ϲ� FTP Ȯ��" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/ftpusers" >> $HOSTNAME.txt 2>&1
cat /etc/ftpusers >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/ftpd/ftpusers" >> $HOSTNAME.txt 2>&1
cat /etc/ftpd/ftpusers >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "vsFTPD Ȯ��" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/vsftpd/ftpusers" >> $HOSTNAME.txt 2>&1
cat /etc/vsftpd/ftpusers >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "ProFTP Ȯ��" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "#cat /etc/proftpd.conf | grep -i rootlogin" >> $HOSTNAME.txt 2>&1
cat /etc/proftpd.conf | grep -i "rootlogin" >> $HOSTNAME.txt 2>&1
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-63] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "##########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-64] at���� ������ �� ���Ѽ���"  
echo "[U-64] at���� ������ �� ���Ѽ���"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: at.allow, at.deny ���� owner:root �Ǵ� bin�� �ý��� ����  && Permission:640�� -> OK " >> $HOSTNAME.txt 2>&1
echo "[CHECK]: at.allow �Ǵ� at.deny ���� �� �ϳ��� �����Ͽ��� ����" >> $HOSTNAME.txt 2>&1
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
echo "[U-65]  SNMP ���� ���� ����"  
echo "[U-65]  SNMP ���� ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : SNMP�� �����ǰ� ���� ������ ��ȣ" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : ���μ����� NAScenterAgent�� �ѱ������������߿� ��Ŵ-e ���񽺸� ���� ����ϴ� SNMP���� �̹Ƿ� ��ȣó��" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep snmp | grep -v "dmi" | grep -v "grep" | wc -l` -eq 0 ]
 then
   echo "SNMP�� ��������Դϴ�. ��ȣ"  >> $HOSTNAME.txt 2>&1
   echo " " >> $HOSTNAME.txt 2>&1
   echo "ps -ef | grep snmp | grep -v grep" >> $HOSTNAME.txt 2>&1
   ps -ef | grep snmp | grep -v grep       >> $HOSTNAME.txt 2>&1
   touch snmp_tmp
 else
   echo "ps -ef | grep snmp | grep -v dmi | grep -v grep"   >> $HOSTNAME.txt 2>&1
   ps -ef | grep snmp | grep -v "dmi" | grep -v "grep"  >> $HOSTNAME.txt 2>&1
   echo "SNMP�� ������ �Դϴ�. ���" >> $HOSTNAME.txt 2>&1
      echo " " >> $HOSTNAME.txt 2>&1

fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-65] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-66] SNMP ���� Ŀ�´�Ƽ��Ʈ���� ���⼺ ����"  
echo "[U-66] SNMP ���� Ŀ�´�Ƽ��Ʈ���� ���⼺ ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: Ŀ�´�Ƽ��Ʈ���� public �Ǵ� private�� �ƴҰ�� ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f snmp_tmp ]
	then
		echo "SNMP�� ��������Դϴ�.��ȣ" >> $HOSTNAME.txt 2>&1
	   
	else
		if [ `cat /etc/snmpd.conf | egrep -i "public|private" | grep -v "^ *#" | wc -l ` -eq 0 ]
			then
				echo "cat /etc/snmpd.conf | egrep -i 'public|private'" >> $HOSTNAME.txt 2>&1
				cat /etc/snmpd.conf | egrep -i 'public|private' >> $HOSTNAME.txt 2>&1
				echo "��ȣ" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				
			else
				echo "cat /etc/snmpd.conf | egrep -i 'public|private'" >> $HOSTNAME.txt 2>&1
				cat /etc/snmpd.conf | egrep -i 'public|private' >> $HOSTNAME.txt 2>&1
				echo "���" >> $HOSTNAME.txt 2>&1
				echo " " >> $HOSTNAME.txt 2>&1
				
		fi
fi
rm -rf snmp_tmp
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-66] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "#########################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-67]  �α׿� �� ��� �޽��� ����"  
echo "[U-67]  �α׿� �� ��� �޽��� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : issue.net && motd ������ ������ �⺻ �����̰ų� ������� ���" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : telnet ���񽺰� �����Ǿ� ������� /etc/issue.net ���� ���� ������� �ʾƵ� ��" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
if [ -f /etc/issue.net ]
	then
		echo "#cat /etc/issue.net" >> $HOSTNAME.txt 2>&1
		cat /etc/issue.net >> $HOSTNAME.txt 2>&1
	else
		echo "/etc/issue.net ������ �����ϴ�.���" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "������� : ssh ��� ��뿩�� Ȯ��" >> $HOSTNAME.txt 2>&1 
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
		echo "/etc/motd ������ �����ϴ�.���" >> $HOSTNAME.txt 2>&1
fi

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-67] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo "-------------------------------------------------------------------------------------"		>> $HOSTNAME.txt 2>&1
echo [U-67] �α׿� �� ��� �޽��� ����[TIP]																	>> $HOSTNAME.txt 2>&1
echo "���޼��� ������ ������ ���� ���Ͽ��� ó����"	     														>> $HOSTNAME.txt 2>&1
echo "issue.net = ����ڰ� �α������� ��µǴ� �޼���[ssh�� ���������ʿ���]"						                                          >> $HOSTNAME.txt 2>&1
echo "motd = ����ڰ� �α����Ŀ� ��µǴ¸޼��� "             														>> $HOSTNAME.txt 2>&1
echo "ssh�� ����Ѵٸ� /etc/ssh/sshd_config ���ϳ���  #Banner none  ������ �ּ��� ��������"                                     >> $HOSTNAME.txt 2>&1
echo "����]#Banner none ���� Banner /etc/issue.net ���� ���� ��θ�"   												 >> $HOSTNAME.txt 2>&1 
echo "�����Ͽ��߸� ssh�� �α����ҽ� ���ʰ� ��µȴ�."              															  >> $HOSTNAME.txt 2>&1 
echo "�� motd ������ �����Ŀ� �޼����� ����ϱ⶧���� ������ �������� telnet �� ssh ��� �޼����� ��µȴ�."                         >> $HOSTNAME.txt 2>&1 
echo "��ݽü� ����� �м��� ���ؿ��� SSH ��� �����κ��� ��޵��� �����Ƿ�, �������� �ʾƵ� ��ȣ ó���ϳ�, ������ �� �� �ǰ�������� ���."                         >> $HOSTNAME.txt 2>&1 
echo "--------------------------------------------------------------------------------------" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1


echo "######################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-68]  NFS ���� ���� ���� ����"  
echo "[U-68]  NFS ���� ���� ���� ����" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : NFS���������� ���ų� �۹̼��� 644������ ��� -> OK" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo "  " >> $HOSTNAME.txt 2>&1

echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "/etc/exports Ȯ��" >> $HOSTNAME.txt 2>&1
if [ -f /etc/exports ]
 then
	if [ `ls -alL /etc/exports | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
		then
			ls -alL /etc/exports >> $HOSTNAME.txt 2>&1
			echo "��ȣ" >> $HOSTNAME.txt 2>&1
		else
			ls -alL /etc/exports >> $HOSTNAME.txt 2>&1
			echo "���" >> $HOSTNAME.txt 2>&1
	fi

 else
    echo "/etc/exports ������ �����ϴ�." >> $HOSTNAME.txt 2>&1
fi

echo "���� : /etc/dfs/dfstab Ȯ��" >> $HOSTNAME.txt 2>&1
if [ -f /etc/dfs/dfstab ]
 then
	if [ `ls -alL /etc/dfs/dfstab | grep "...-.--.--.*root.*" | wc -l` -eq 1 ]
		then
			ls -alL /etc/dfs/dfstab >> $HOSTNAME.txt 2>&1
			echo "��ȣ" >> $HOSTNAME.txt 2>&1
		else
			ls -alL /etc/dfs/dfstab >> $HOSTNAME.txt 2>&1
			echo "���" >> $HOSTNAME.txt 2>&1
	fi

 else
    echo "/etc/dfs/dfstab ������ �����ϴ�." >> $HOSTNAME.txt 2>&1
fi

echo "." >> $HOSTNAME.txt 2>&1
echo "[U-68] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-69] expn, vrfy ��ɾ� ����" >> $HOSTNAME.txt 2>&1
echo "[CHECK]: PricacyOptions=authwarnings, goaway(noexpn,novrfy)�� �����ϰ� ������� ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ -f sendmail_tmp ]
	then
		echo "Sendmail ���񽺰� ����� ���Դϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "#/etc/mail/sendmail.cf ������ �ɼ� Ȯ��" >> $HOSTNAME.txt 2>&1
			if [ -f /etc/mail/sendmail.cf ]
				then
					    if [ `cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn" | grep -v "grep" | wc -l ` -eq 1 ]
							then
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn" | grep -v "grep" >> $HOSTNAME.txt 2>&1
								echo " " >> $HOSTNAME.txt 2>&1
							else
								cat /etc/mail/sendmail.cf | grep -v "^ *#" | egrep -i "O PrivacyOptions|authwarnings|goaway|novrfy|noexpn" | grep -v "grep" >> $HOSTNAME.txt 2>&1
								echo "���" >> $HOSTNAME.txt 2>&1
						fi
				else
					echo "/etc/mail/sendmail.cf ���� ����.���" >> $HOSTNAME.txt 2>&1
					echo " " >> $HOSTNAME.txt 2>&1
			fi
fi

rm -rf sendmail_tmp
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-69] End" >> $HOSTNAME.txt 2>&1  
echo " " >> $HOSTNAME.txt 2>&1

echo "#################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-70]  Apache ������ ���� ����"  
echo "[U-70]  Apache ������ ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK] : ��� ���丮���� �������� ���ų� ServerTokens �������� �ɼ��� Prod[uctOnly]�� �ƴҰ�� ���" >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

if [ `ps -ef | grep httpd | grep -v "grep" | wc -l` -eq 0 ]
	then
		echo "Apache�� �������� �ƴմϴ�." >> $HOSTNAME.txt 2>&1
	else
		echo "�ý��� ����ڿ��� Apache ȯ�漳������ (Httpd.conf) ��û �� ���� ����" >> $HOSTNAME.txt 2>&1
fi
echo "." >> $HOSTNAME.txt 2>&1
echo "[U-70] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo [U-70]  Apache ������ ���� ����[TIP]											>> $HOSTNAME.txt 2>&1
echo "ServerTokens Prod ���� �߰��ؾ��� "									>> $HOSTNAME.txt 2>&1
echo "ServerTokens Optisns ����"                                            >> $HOSTNAME.txt 2>&1 
echo "Prod : ������ ����  - Server:Apache"                                   >> $HOSTNAME.txt 2>&1 
echo "Min : Prod + ������ ���� - Server:Apache/1.3.0"                         >> $HOSTNAME.txt 2>&1 
echo "OS : MIN + �ü��  - Server:Apache/1.3.0(UNIX)"                      >> $HOSTNAME.txt 2>&1                                                   >> $HOSTNAME.txt 2>&1 
echo "Full: OS + ��ġ�� ������� - Server:Apache/1.3.0(UNX)"                  >> $HOSTNAME.txt 2>&1
echo "------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1



echo "###############################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-71] �ֽ� ������ġ �� ���� �ǰ���� ����"  
echo "[U-71] �ֽ� ������ġ �� ���� �ǰ���� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �������� " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "��������"  >> $HOSTNAME.txt 2>&1
uname -a          >> $HOSTNAME.txt 2>&1 
uname -r          >> $HOSTNAME.txt 2>&1 
cat /proc/version  >> $HOSTNAME.txt 2>&1 
cat /etc/*release  >> $HOSTNAME.txt 2>&1 

echo " " >> $HOSTNAME.txt 2>&1
echo "[U-71] End" >> $HOSTNAME.txt 2>&1

echo "####################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-72]  �α��� ������ ���� �� ����"  
echo "[U-72]  �α��� ������ ���� �� ����"  >> $HOSTNAME.txt 2>&1
echo "[CHECK]: �������� �α� �׸� ���� " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]: " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "�������� �α� �׸� ��"  >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "[U-72] End" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "###################################################################"  >> $HOSTNAME.txt 2>&1
echo "[U-73] ��å�� ���� �ý��� �α� ����"
echo "[U-73] ��å�� ���� �ý��� �α� ����" >> $HOSTNAME.txt 2>&1
echo "[CHECK] : �α� ��� ��å�� �Ʒ� ���ø� �����Ͽ� �����Ǿ� ������ ��ȣ " >> $HOSTNAME.txt 2>&1
echo "[COUNTERMEASURE]" >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "syslog ���μ���" >> $HOSTNAME.txt 2>&1
echo "#ps -ef | grep "syslog" | grep -v grep" >> $HOSTNAME.txt 2>&1
ps -ef | grep 'syslog' | grep -v grep >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo "----------------����----------------------" >> $HOSTNAME.txt 2>&1
echo "*.info;mail.none;authpriv.none;cron.none /var/log/messages" >> $HOSTNAME.txt 2>&1
echo "authpriv.* /var/log/secure" >> $HOSTNAME.txt 2>&1
echo "mail.* /var/log/maillog" >> $HOSTNAME.txt 2>&1
echo "cron.* /var/log/cron" >> $HOSTNAME.txt 2>&1
echo "*.alert /dev/console" >> $HOSTNAME.txt 2>&1
echo "*.emerg *" >> $HOSTNAME.txt 2>&1
echo "----------------------------------------- " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "�ý��� �α� ����" >> $HOSTNAME.txt 2>&1
echo "#cat /etc/syslog.conf" >> $HOSTNAME.txt 2>&1
cat /etc/syslog.conf >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1

echo "rsyslog �ý��� �α� ����" >> $HOSTNAME.txt 2>&1
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
echo [U-73] ��å�� ���� �ý��� �α� ����[TIP]																	>> $HOSTNAME.txt 2>&1
echo "�ֽŹ����� LINUX�� /etc/syslog.conf �� �ƴ� /etc/rsyslog.conf �� �����" 									>> $HOSTNAME.txt 2>&1
echo "�� ������� �ƴ� �űԻ���� ��κ� CentOS[����] �������� �� REDHAT[����] ���������� ��ġ������ �����ؾ���"           >> $HOSTNAME.txt 2>&1
echo "----------------------------------------------------------------------------------------"					>> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1
echo " " >> $HOSTNAME.txt 2>&1





