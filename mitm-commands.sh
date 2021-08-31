sudo iptables -A FORWARD -s 192.168.0.61 -j ACCEPT
sudo iptables -A FORWARD -d 192.168.0.61 -j ACCEPT

sudo iptables -t nat -A POSTROUTING -s 192.168.0.61 -j MASQUERADE

sudo iptables -A FORWARD -s 192.168.0.62 -j ACCEPT
sudo iptables -A FORWARD -d 192.168.0.62 -j ACCEPT

sudo echo 1 > /proc/sys/net/ipv4/ip_forward