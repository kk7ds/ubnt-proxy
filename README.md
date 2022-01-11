ubnt-proxy
==========

A somewhat universal ubnt discovery proxy service. This attempts to make ubiquiti discovery
work across subnets, at least for UnifiProtect.

This is based on work from others:

 * https://github.com/bahamas10/unifi-proxy
 * https://github.com/sashkab/unifi-proxy

 The goal of this implementation is to be more automatic and "just
 work" instead of recording and replaying a single packet. The idea is
 you run this on one machine that spans both the subnet that the unifi
 gear is on, as well as the one the mobile device is attempting to
 discover them on. It does its own discovery on the unifi subnet,
 maintains a list of devices, and when it receives a discovery
 request, it feeds information about the discovered devices to the
 requester.
 
 Preparation
 -----------
 
 This requires `scapy` to be installed, because the Android app will
 only recognize discovery responses if they are sent from the same IP
 as the original device. Thus, we need to use `scapy` to send raw
 ethernet packets with the spoofed source address, and it also
 requires that we run as root.
 
 On Debian or Ubuntu:
 
 ``` console
 $ sudo apt-get install python3-scapy
 ```
 
 On something else, probably this will get you what you need:
 
 ```console
 $ sudo pip3 install scapy
 ```
 
 Running
 -------
 
 Pretty much all you should need is the IP of the interface that sits
 on the unifi subnet. Assume for the example that this is
 192.168.10.1. Run the proxy like this:
 
 ``` console
$ sudo ./ubnt-proxy 192.168.10.1
INFO:unifi_proxy:Sending discover
INFO:unifi_proxy:New device found at 192.168.10.86
INFO:unifi_proxy:New device found at 192.168.10.52
INFO:unifi_proxy:New device found at 192.168.10.45
INFO:unifi_proxy:New device found at 192.168.10.18
INFO:unifi_proxy:New device found at 192.168.10.15
INFO:unifi_proxy:New device found at 192.168.10.37
INFO:unifi_proxy:New device found at 192.168.10.57
INFO:unifi_proxy:New device found at 192.168.10.39
INFO:unifi_proxy:Feeding 8 discovered devices to 192.168.20.117:51416
```

This shows us discovering eight devices on the unifi subnet, and a
request packet from a different subnet (`192.168.20.117`), to which we
forward the info.

**NOTE:** This only proxies the discovery packets. The device doing
the discovery will attempt to contact the targets themselves, and must
have a path through the firewall to do so.
