# notsodeep
Active DPI circumvention utility for Linux


What does it do?
--------------------
Bypass the blocking of http and https web-sites in countries like Russia, Iran.


How it works?
--------------------
DPI rules written for standart software omitting all possible cases that are acceptable by standards, there are some gaps in deep packet inspection. For instance some DPI stumbles, when the "Host:" header is written in a case-insensetive manner. (RFC 2616) This software simply exploits some of that gaps.

**Note:** You may need [DnsCrypt](https://github.com/jedisct1/dnscrypt-proxy).

iptables Rules
--------------------

```bash
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t raw -I PREROUTING -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 200 --queue-bypass
```

`--queue-bypass` may not work below Linux kernel 2.6.39 and 3.10 to 3.12

Requirements
--------------------

#### Arch

```bash
sudo pacman -S libnetfilter_queue
```

#### Debian

```bash
sudo apt-get install libnetfilter-queue-dev
```

Compilation and Running
--------------------
```bash
git clone https://github.com/farukuzun/notsodeep.git
cd notsodeep
make
sudo ./notsodeep
```


**Note:** If you don't want to run the binary with root privileges: `sudo setcap cap_net_admin=ep ./notsodeep`

Newbie Friendly Persistent Usage
--------------------

```bash
cd /tmp
git clone https://github.com/farukuzun/notsodeep.git
cd notsodeep
make
cd ..
sudo su
cp -R notsodeep /opt
cp /opt/notsodeep/notsodeep.service /etc/systemd/system/
systemctl enable notsodeep.service
iptables -A INPUT -p tcp --tcp-flags SYN,ACK SYN,ACK --sport 443 -j NFQUEUE --queue-num 200 --queue-bypass
iptables -t raw -I PREROUTING -p tcp --sport 80 --tcp-flags SYN,ACK SYN,ACK -j NFQUEUE --queue-num 200 --queue-bypass
iptables-save > /etc/iptables/iptables.rules
systemctl enable iptables
systemctl start iptables
systemctl start notsodeep.service
```

Contact
--------------------

``mail[at]notsodeep.farukuzun.com``
