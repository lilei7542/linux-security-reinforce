#!/bin/bash
#system check
#author mal
#version 1.0

#show the system information
if [ $(id -u) != "0" ]; then
 `quit` "this script must be run on ROOT "
fi

check_system_information()
{
	echo "		The system basic information		"
	echo "The kernel is `uname -r`"
	if [ -f "/etc/redhat-release" ]
	then
		echo "The system version is `cat "/etc/redhat-release"`"
	fi
	echo "The hostname is `hostname`"
	echo
}

check_system_information

#only allow root's UID is zero
check_user_root()
{
	file="/etc/passwd"
	temp=` cat $file | awk -F: '($3=="0") {print $1":"$3}' |wc -l  `
	if [ $temp -ne 1 ]
	then
		echo "This system not only have a root"
		echo
	fi
}

check_user_root

#ssh no allow root load ,havs ssh Banner and the banner have warring information
check_ssh_config()
{	
	if [ `rpm -qa | grep "openssh-server" |wc -l` -lt 1 ]
	then
		echo "The ssh server is not install"
	fi
	
	file="/etc/ssh/sshd_config"
	if [ ! -f "$file" ]
	then
		echo "The $file is not exsit"
	fi
	
	if [ `cat $file | grep -c "^PermitRootLogin no" ` -ne 1 ]
	then
		echo "The root is allow use ssh load"
	fi

	if [ `netstat -antple | grep -i "listen" |grep "0.0.0.0:22" |wc -l  ` -eq 0 ]
	then
		echo "The ssh port are not listen"
	fi	
	

	temp=`grep -v ^# $file| grep -i "banner" | wc -l`
	if [ $temp -eq 0 ]
	then
		echo "The ssh is not set login Banner"
	else
		banner_file=`grep -v ^# "/etc/ssh/sshd_config"  | grep -i "banner" | awk '{print $2}'`
		if [ ! -f "$banner_file" ]
       		then
                	echo "The ssh banner file "$banner_file" is not extist"
        	fi

        	if [ ! -s "$banner_file" ]
        	then
                echo "The ssh banner file "$banner_file" is null"
        	fi
	fi 

}
check_ssh_config


#show who is not set passwd
check_user_password_who_is_null()
{
	file="/etc/shadow"
	temp=`egrep  "lp|nobody|uucp|games|rpm|smmsp|nfsnobody" /etc/shadow | awk -F: '($2=="*"){print $1}' |wc -l`
	if [ $temp -ne 0 ]
	then
		echo "Exsit user not set password"	
		echo "`egrep  "lp|nobody|uucp|games|rpm|smmsp|nfsnobody" /etc/shadow | awk -F: '($2=="*"){print $1}'` "
	fi
}

check_user_password_who_is_null

check_user_not_load()
{
	result=`egrep -w "lp|uucp|games|rpm|smmsp|nfsnobody" /etc/shadow |awk -F: '($2!~"!") {print $1":"$2}'|wc -l`
	if [ $result -ne 0 ]
	then
		echo "This user is not lock"
		egrep -w "lp|uucp|games|rpm|smmsp|nfsnobody" /etc/shadow |awk -F: '($2!~"!") {print $1}'
	fi
}

check_user_not_load


#show define passwd options
check_passwd_define()
{
	file="/etc/login.defs"
	pass_min_len=` grep "^PASS_MIN_LEN" "$file" | awk '{if($2<"8") print $2}' `
	if [ `echo $pass_min_len |wc -l` -ne 1 ]
	then
		echo "The PASS_MIN_LEN set is $pass_min_len is too short"
		echo "Set PASS_MIN_LEN >7"
	fi
	
	pass_max_days=` grep "^PASS_MAX_DAYS" "$file" | awk '{if($2>"90") print $2}' `
	if [ `echo $pass_max_days |wc -l` -ne 1 ]
	then
		echo "Ths PASS_MAX_DAYS is  $pass_max_days is too long"
		echo "Set PASS_MAX_DAYS <90"
	fi
	
	pass_warn_age=`grep "^PASS_WARN_AGE" "$file" | awk '{if($2>"7") print $2}' `
	echo 
	if [ `echo "$pass_warn_age"|wc -l ` -ne 1 ]
	then
		echo "The PASS_WARN_AGE is "$pass_warn_age" is too long"
		echo "Set PASS_WARN_AGE < 7"
	fi	
	
}
check_passwd_define

#check the /etc/passwd,/etc/shadow,/etc/group mode
check_passwd_file_mode()
{
	temp=` ls -l /etc/passwd | awk '($1 !="-rw-r--r--"){ print $1}' | wc -l `
	if [ $temp -ne 0 ]
	then
		echo "The /etc/passwd mode is error"
	fi

	temp=` ls -l /etc/shadow | awk '($1 !="----------"){ print $1}' | wc -l `
        if [ $temp -ne 0 ]
        then
                echo "The /etc/shadow mode is error"
        fi
	
        temp=` ls -l /etc/group | awk '($1 !="-rw-r--r--"){ print $1}' | wc -l `
        if [ $temp -ne 0 ]
        then
                echo "The /etc/group mode is error"
        fi
}
check_passwd_file_mode

#set define umask is 027
check_umask()
{
	temp=`umask`
	if [ $temp != "0027" ]
	then
		echo "umask is not 027"
		echo "Please exec "umask 027" "
	fi

	temp=` grep "umask 027" /etc/profile  |wc -l `
	if [ $temp -ne 1 ]
	then
		echo "The /etc/profile umask is not 027"
		echo "Set /etc/profile "umask 027""
	fi
	
	temp=` grep "umask 027" /etc/csh.login  |wc -l `
        if [ $temp -ne 1 ]
        then
                echo "The /etc/csh.login umask is not 027"
		echo "Set /etc/csh.login "umask 027""
        fi

	
	temp=` grep "umask 027" /etc/csh.cshrc |wc -l `
        if [ $temp -ne 1 ]
        then
                echo "The /etc/csh.cshrc umask is not 027"
		echo "Set /etc/csh.cshrc "umask 027""
        fi

	temp=` grep "umask 027" /etc/bashrc |wc -l `
        if [ $temp -ne 1 ]
        then
                echo "The /etc/bashrc umask is not 027"
		echo "Set /etc/bashrc "umask 027""
        fi	
}

check_umask

#check in /etc/init.d/* who mode not is 750
check_init_mode()
{
	temp=`ls -lR /etc/init.d/* | awk '{if($1!~"-rwxr-x---") print $1}'|wc -l`
	if [ $temp -ne 0 ]
	then
		echo "The /etc/init.d/* mode not is 750"
		echo "Exec "chmod -R 750 /etc/init.d/*" "
	fi

}

check_init_mode


#check directory /tmp mode
check_temp_mode()
{
	temp=`ls -ld /tmp | awk '{if($1=="drwxrwxrwt.") print $1}'|wc -l`
	if [ $temp -ne 1 ]
	then
		echo "The /tmp directory mode not is 1777"
		echo "Exec "chmod 1777 /tmp""
		echo
	fi
}
check_temp_mode


#check use tcp_Warppers
check_tcp_Wrappers()
{
	if [ ! -f "/etc/hosts.allow" ]
	then
		echo "Not have /etc/hosts.allow "
	elif [ ! -f "/etc/hosts.deny" ]
	then
		echo "Not have /etc/hosts.deny"
	fi
	
	temp=`cat /etc/hosts.allow | grep -v ^# | wc -l`
	temp2=`cat /etc/hosts.deny | grep -v ^# | wc -l`
	if [ $temp -eq 0 -o $temp2 -eq 0 ]
	then
		echo "The /etc/hosts.allow or /etc/hosts.deny is null"
	fi
}
check_tcp_Wrappers


#check kernel optional
check_kernel_options()
{
	temp=`cat /proc/sys/net/ipv4/tcp_syncookies`
	if [ $temp -ne 1 ]
	then
		echo "The tcp_suncookies not is 1"
		echo "Exec echo "net.ipv4.tcp_syncookies=1">>/etc/sysctl.conf Next sysctl -p"
	fi
	
	if [ `cat /proc/sys/net/ipv4/ip_forward` -ne 0 ]
	then
		echo "The ip_forward is open"
		echo "Exec echo "net.ipv4.ip_forward=0">>/etc/sysctl.conf Next sysctl -p"
	fi
	
	if [ `cat /proc/sys/net/ipv4/tcp_max_syn_backlog` -lt 2048 ]
	then
		echo "The tcp_max_syn_backlog is too small"]
		echo "Exec echo "net.ipv4.tcp_max_syn_backlog=3096">>/etc/sysctl.conf Next sysctl -p"
	fi
		
	if [ `sysctl  -n net.ipv4.conf.all.accept_redirects` -ne 0 ]
	then
		echo "The net.ipv4.conf.all.accept_redirects is not 0"
		echo "Exec echo "net.ipv4.conf.all.accept_redirects=0">>/etc/sysctl.conf Next sysctl -p"
	fi

	if [ `sysctl -n net.ipv4.conf.all.accept_source_route` -ne 0 ]
	then
		echo "The net.ipv4.conf.all.accept_source_route is not 0"
		echo "Exec echo "net.ipv4.conf.all.accept_source_route=0">>/etc/sysctl.conf Next sysctl -p "
	fi

		
}
check_kernel_options


#show load banner
check_information()
{
	if [ ` cat /etc/rc.local  | egrep -v "^#|^$" |wc -l` -ne 1 ]
	then
		echo "The /etc/rc.local is so big"
	fi
	
	if [ `cat /etc/issue | egrep "CentOS|Kernel" |wc -l ` -ne 0 ]
	then
		echo "The /etc/issue is not allow"
	fi

	if [ ! -s "/etc/motd" ]
	then
		echo "The /etc/motd is not set"
	fi

}
check_information

#Set TMOUT is 180
check_time_out()
{
	if [ `grep "TMOUT=180" /etc/profile |wc -l` -ne 1 ]
	then
		echo "Not set time_out_options"
		echo "Exec echo "TMOUT=180">>/etc/prifile Next source /etc/profile"
	fi
}

check_time_out

#check FTP running? ftp allow chroot_local_user;local_umask and anon_umask 
check_ftp()
{
	ftp_statue=` netstat -antple|grep -i "listen" | grep ":21" |wc -l`
	if [ $ftp_statue -ne 1 ]
	then
		echo "vsftpd is not run"
	fi
	
	if [ -f "/etc/vsftpd/vsftpd.conf" ]
	then
		ftp_conf="/etc/vsftpd/vsftpd.conf"
	fi
	
	if [ `egrep -v "^#|^$" $ftp_conf |grep "chroot_local_user=YES" |wc -l` -eq 0 ]
	then
		echo "vsftpd is set at $ftp_conf,check is not"
		echo "Set echo "chroot_local_user=YES">>$ftp_conf"
	fi
	
	local_umask=`egrep -v "^#|^$" $ftp_conf|grep -i "local_umask=022"|wc -l`
	anon_umask=`egrep -v "^#|^$" $ftp_conf|grep -i "anon_umask=022"|wc -l`
	result=$( expr $local_umask + $anon_umask )
	if [ $result -lt 2 ]
	then
		echo "FTP server umaks is error"
		echo "vi $ftp_conf Add local_umask=022 and anon_umask=022"
	fi

}

check_ftp

#check /usr/bin who has specail mode
check_bin_mode()
{
	result=`find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;|wc -l`
	if [ $result -ne 0 ]
	then
		echo "The '/use/bin' mode has question"
		find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \;
	fi
	
}

check_bin_mode

#check the server that start with system open
check_start()
{
	result=`chkconfig --list|egrep "amanda|chargen|chargen-udp|cups|cups-lpd|daytime|daytime-udp|echo|echo-udp|eklogin|ekrb5-telnet|finger|gssftp|imap|imaps|ipop2|ipop3|klogin|krb5-telnet|kshell|ktalk|ntalk|rexec|rsync|talk|tcpmux-server|telnet|tftp|time-dgram|time-stream uucp"|grep -w "on" |wc -l`
	if [ $result -ne 0 ]
	then
		echo "The server when system start has question" 
		chkconfig --list|egrep "amanda|chargen|chargen-udp|cups|cups-lpd|daytime|daytime-udp|echo|echo-udp|eklogin|ekrb5-telnet|finger|gssftp|imap|imaps|ipop2|ipop3|klogin|krb5-telnet|kshell|ktalk|ntalk|rexec|rsync|talk|tcpmux-server|telnet|tftp|time-dgram|time-stream uucp"|grep -w "on"
	fi
}

check_start

#check ntp that running and ntp config is right
check_ntp()
{
	ntp_status=`ps -ef | grep ntp | grep -v "grep ntp" |wc -l`
	if [ $ntp_status -lt 1 ]
	then
		echo "The ntp is not running"
	fi
		
	result=`grep ^server "/etc/ntp.conf" |grep -v "server 127.0.0.1" | wc -l`
	if [  $ntp_status -ne 1 -a $result -eq 0 ]
	then
		echo "The ntp is not set time server"
	fi

}
check_ntp

#check this system that have telnet-server
check_telnet_server()
{
	result=`netstat -anptleu |grep :23 | grep -i "listen" |wc -l`
	if [ $result -ne 0 ]
	then
		echo "Telnet is run, please instead telnet of ssh"
	fi
}


check_telnet_server


#check the passwd and login 
check_pam()
{
	if [ -f "/etc/centos-release" ]
	then
		file="/etc/pam.d/system-auth"
	fi

	minlen=`egrep -v "^#|^$" $file |grep "minlen" |sed 's/^.*minlen=//g'|sed 's/\s.*$//g'`
	if [ $minlen -lt 8 ]
	then
		echo "Ths passwd min length < 8"
	fi

	
	minclass=`egrep -v "^#|^$" $file |grep "minclass" |sed 's/^.*minclass=//g'|sed 's/\s.*$//g'`
	if [ $minclass -lt 2 ]
	then
		echo "Ths passwd min class < 8"
	fi
	
	
	maxrepeat=`egrep -v "^#|^$" $file |grep "maxrepeat" |sed 's/^.*maxrepeat=//g'|sed 's/\s.*$//g'`
	if [ $maxrepeat -gt 4 ]
	then
		echo "Ths passwd min repeat > 4 "
	fi

	lock=`egrep -v "^#|^$" $file | grep "pam_tally2.so"|wc -l`
	if [ $lock -eq 0 ]
	then
		echo "It is not set user lock"
		return 0
	fi
		

	lock_time=`egrep -v "^#|^$" $file | grep "pam_tally2.so"|sed 's/^.*unlock_time=//g'|sed 's/\s.*$//g'`
	if [ $lock_time -lt 300 ]
	then
		echo "The user lock time is < 300s"
	fi
	

	deny=`egrep -v "^#|^$" $file | grep "pam_tally2.so"|sed 's/^.*deny=//g'|sed 's/\s.*$//g'`
        if [ $deny -gt 4 ]
        then
                echo "The user is allow too many time input passwd"
        fi

}
check_pam


#check syslog what have send local log to log server
check_log()
{

	if [ `ps -ef | grep rsyslog  |grep -v "grep rsyslog"|wc -l` -eq 0 ]
	then
		echo "The syslog is not running"
	fi

	if [ -f "/etc/rsyslog.conf" ]
	then
		log_conf="/etc/rsyslog.conf"
	elif [ -f "/etc/syslog.conf" ]
	then
		log_conf="/etc/syslog.conf"
	fi

	result=`  egrep -v "^#|^$" $log_conf  | awk '($2~"@"){print $1":"$2}' | wc -l`
	if [ $result -eq 0 ]
	then
		echo "The server is not set other server as log_server"
		echo "Exec like echo "*.*	@IP">>$log_conf"
	fi

}
check_log


#check /etc/default/*,/etc/init.d/*,/etc/rc.d/*,/tmp/*,/etc/cron* mode
check_other_mode()
{
	if [ `ls -l /etc/default/* /etc/init.d/* /etc/rc*.d/* /tmp/* /etc/cron*|grep "\-rwxrwxrwx" |wc -l` -ne 0 ]
	then
		echo "The mode has error"
		ls -l /etc/default/* /etc/init.d/* /etc/rc*.d/* /tmp/* /etc/cron*|grep "\-rwxrwxrwx"
	fi
}
check_other_mode
