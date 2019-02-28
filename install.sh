#/bin/bash
#security install
#author lilei
#version 1.0

#check root
if [ $(id -u) != "0" ]; then
 `quit` "this script must be run on ROOT "
sleep 5

#Disable SeLinux
sed -i '/SELINUX/s/enforcing/disabled/' /etc/selinux/config 
echo "selinux is disabled,you must reboot!"
sleep 5

#User Config
user_cf=/etc/login.defs
sed -i 's/^PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t60/'  $user_cf
sed -i 's/^PASS_MIN_LEN\t5/PASS_MIN_LEN\t8/' $user_cf
echo "Password max days is 60day , mix len is 8;"
sleep 5




#user del
for i in adm lp sync shutdown halt mail news uucp ope rator games gopher ftp ;do userdel $i ;done
for i in adm lp mail news uucp games dip pppusers pop users slipusers ;do groupdel $i ;done
echo "Del unuseful user and group :adm,lp,sync,shutdown,halt,mail,news,uucp,ope,rator,games,gopher;OK"
sleep 5

#update yum
#cat >> /etc/yum.repos.d/dag.repo <<EOF
#[dag]
#name=Dag RPM Repository for Red Hat Enterprise Linux
#baseurl=http://apt.sw.be/redhat/el\$releasever/en/\$basearch/dag
#gpgcheck=1
#gpgkey=http://dag.wieers.com/rpm/packages/RPM-GPG-KEY.dag.txt
#enabled=1
#EOF
#echo "Add dag yum,OK"
#sleep 5

#update system
#yum clean all
#yum -y install ntp vim-enhanced gcc gcc-c++ gcc-g77 flex bison autoconf automake bzip2-devel ncurses-devel zlib-devel libjpeg-devel libpng-devel libtiff-devel freetype-devel libXpm-devel gettext-devel  pam-devel
#yum -y install yum install -y rrdtool perl-rrdtool rrdtool-devel
#sleep 5

#EPEL
#rpm -ivh http://mirrors.ustc.edu.cn/fedora/epel/6/x86_64/epel-release-6-8.noarch.rpm
#rpm --import /etc/pki/rpm-gpg/RPM-GPG-KEY-EPEL-6
#echo "Epel add OK"

#Set timezone
rm -rf /etc/localtime
ln -s /usr/share/zoneinfo/Asia/Shanghai /etc/localtime
ntpdate -d cn.pool.ntp.org
date
echo "Timezone is OK"
sleep 5

#set locale
cat >/etc/sysconfig/i18n <<EOF
LANG="zh_CN.UTF-8"
EOF
echo "zh_CN.UTF-8 is OK"
sleep 5

#set sysctl
cat >> /etc/sysctl.conf << EOF
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_tw_recycle = 1
net.ipv4.ip_local_port_range = 4096 65000
net.ipv4.tcp_max_tw_buckets = 5000
net.ipv4.tcp_max_syn_backlog = 4096
net.core.netdev_max_backlog =  10240
net.core.somaxconn = 2048
net.core.wmem_default = 8388608
net.core.rmem_default = 8388608
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 2
net.ipv4.tcp_tw_recycle = 1
net.ipv4.tcp_max_orphans = 3276800
net.ipv4.tcp_mem = 94500000 915000000 927000000
#net.ipv4.tcp_mem[0]
#net.ipv4.tcp_mem[1]
#net.ipv4.tcp_mem[2]
EOF
/sbin/sysctl -p
echo "kernel is OK"
sleep 5

#disable ctrl+alt+del
#sed -i "s/ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/#ca::ctrlaltdel:\/sbin\/shutdown -t3 -r now/" /etc/inittab
#mv /etc/init/control-alt-delete.conf /etc/init/control-alt-delete.conf.bak
#echo "disable ctrlaltdel"
#sleep 5

#ulimit
#echo "ulimit -SHn 102400">> /etc/rc.local
#echo "ulimit -SHn 65535" >> /etc/profile


#限制进程数
cat >> /etc/security/limits.conf << EOF
* soft nofile 65535
* hard nofile 65535
EOF
echo "ulimit configure is OK"
sleep 5


#set lock purview 
chattr +i /etc/services 
chattr +i /etc/passwd 
chattr +i /etc/shadow 
chattr +i /etc/group 
chattr +i /etc/fstab
chattr +i /etc/sudoers
echo "purview configure is OK"
sleep 5

#disable ipv6
echo "alias net-pf-10 off" >> /etc/modprobe.conf
echo "alias ipv6 off" >> /etc/modprobe.conf
chkconfig --level 35 ip6tables off
echo "ipv6 is disable;"
sleep 5

#init_ssh
#ssh_cf="/etc/ssh/sshd_config" 
#sed -i "s/#ServerKeyBits 768/ServerKeyBits 1024/" $ssh_cf
#sed -i "s/#PermitRootLogin yes/PermitRootLogin no/" $ssh_cf
#sed -i "s/#PermitEmptyPasswords no/PermitEmptyPasswords no/" $ssh_cf
#sed -i "s/#Port 22/Port 60022/" $ssh_cf
#sed -i "s/UseDNS yes/UseDNS no/" $ssh_cf
#hosts
#echo "sshd:ALL" >> /etc/hosts.deny
#echo "sshd:10.210.">> /etc/host.allow
#service sshd restart
#echo "sshd service is OK"
#sleep 5
 
#chkser
#tunoff services
for i in `ls /etc/rc3.d/S*`
do
CURSRV=`echo $i|cut -c 15-`
echo $CURSRV
case $CURSRV in
( atd | auditd | iptables | crond | haldaemon | irqbalance | mdmonitor | lvm2-monitor | messagebus | network | rpcbind | sshd | rsyslog | udev-post | vmware-tools | vmware-tools-thinprint | local )
echo "Base services, Skip!"
;;
*)
echo "change $CURSRV to off"
chkconfig --level 235 $CURSRV off
chkconfig --del $CURSRV
;;
esac
done
echo "service is init is ok.............."
sleep 10

#ROOT honey
#cat >>/root/.bash_profile <<EOF
#clear
#while [  "\$p" != "123" ]; do
#echo "Access denied"
#echo -n "login as:"
#read p
#stty intr undef
#done
#stty intr ^c
#EOF
#sleep 5


#cat >>/etc/profile <<EOF
#alias cls='clear'
#EOF
#sleep 5


#set login timeout
cat >>/etc/profile <<EOF
export TMOUT=60
EOF
sleep 5


#disable ip spoof
cat >>/etc/host.conf <<EOF
order bind , hosts
multi off
nospoof on
EOF
echo "ip spoof is disable;"
sleep 5


#iptables
iptables -F
iptables -Z
iptables -X
iptables -P INPUT DROP
iptables -P OUTPUT ACCEPT
iptables -P FORWARD DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 53 -j ACCEPT
iptables -A INPUT -p udp --sport 80 -j ACCEPT
iptables -A INPUT -p icmp -j ACCEPT
iptables -A INPUT -i lo -p all -j ACCEPT
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
/etc/rc.d/init.d/iptables save
service iptables restart
echo "iptables is ready,you can change what you need "
sleep 5


#禁止启动snmp服务
/etc/init.d/snmpd stop
sleep 5


#重要目录或文件权限设置
chmod 700 /etc/xinetd.conf
chmod 744 /etc/group
chmod 700 /etc/shadow
chmod 744 /etc/services
chmod 700 /etc/security
chmod 744 /etc/passwd
chmod 700 /etc/grub.conf
chmod 700 /boot/grub/grub.conf
chmod 700 /etc/lilo.conf
sleep 5

#记录帐户登录日志
touch /var/log/authlog
echo "auht.info       /var/log/authlog" >>/etc/syslog.conf
sleep 5

终端添加监控
echo "you have been watched ">>/etc/motd


