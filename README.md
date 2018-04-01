# notsodeep
Active DPI circumvention utility for Linux


What is it do?
--------------------
Bypass the blocking of http and even ssl web-sites in countries like Russia, Iran.


How it works?
--------------------
There are some gaps in deep packet inspection, because of DPI rules written for standart software, omitting all possible cases that are acceptable by standards. (E.g rfc2616) For instance some DPI stumbles, when the "Host:" header is written in a case-insensetive manner. Also TCP fragmentation by modifying TCP window size for bypassing DPI on SSL requests.


iptables Rules
--------------------

```bash
iptables -A OUTPUT -p tcp --tcp-flags SYN,ACK SYN,ACK --sport 443 -j NFQUEUE --queue-num 100 --queue-bypass
iptables -t mangle -I POSTROUTING -p tcp --dport 80 -j NFQUEUE --queue-num 200 --queue-bypass
```

`--queue-bypass` may not work below Linux kernel 2.6.39 and 3.10 to 3.12

Requirements
--------------------

#### Arch

```bash
pacman -S libnetfilter_queue
```

#### Debian

```bash
apt-get install libnetfilter-queue-dev
```

---

Compilation
--------------------
```bash
make
sudo ./notsodeep
```


**Note:** If you do not want to run the binary with root privileges: `sudo setcap cap_net_admin=ep ./notsodeep`


Contact
--------------------

``mail[at]notsodeep.farukuzun.com``