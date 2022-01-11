#!/usr/bin/env python3

import argparse
import socket
import logging
import select
import sys
import time

import scapy.all

REQUEST = bytes([1, 0, 0, 0])
LOG = logging.getLogger('unifi_proxy')


class Device:
    """A single discovered device"""

    def __init__(self, ip, data):
        self.ip = ip
        self.data = data
        self.heartbeat()

    @property
    def age(self):
        return time.time() - self.ts

    def heartbeat(self):
        self.ts = time.time()

    def __hash__(self):
        return self.ip


class DiscoveryProxy:
    """A cross-subnet Unifi Discovery proxy"""

    def __init__(self, protect_if, mcast_group, disc_port, interval=10):
        self._protect_if = protect_if
        self._disc_port = disc_port
        self._interval = interval

        self.mcast_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.mcast_s.bind(('', self._disc_port))
        mreq = socket.inet_aton(mcast_group) + socket.inet_aton('0.0.0.0')
        self.mcast_s.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP,
                                mreq)

        self.disc_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.disc_s.bind((self._protect_if, 0))
        self.disc_s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

        self._last_discover = 0
        self._discovered = {}

    def discovery_tick(self):
        # If enough time has passed since our last attempt, do a discovery
        if time.time() - self._last_discover > self._interval:
            LOG.info('Sending discover')
            self.disc_s.sendto(REQUEST, ('255.255.255.255', self._disc_port))
            self._last_discover = time.time()

        # Expire any devices that we have not heard from in three
        # intervals
        now = time.time()
        for ip, device in list(self._discovered.items()):
            if (now - device.ts) > (self._interval * 3):
                LOG.info('Expiring device at %s' % device.ip)
                del self._discovered[device.ip]

    def feed_discovery(self, remote):
        if not self._discovered:
            LOG.warning('No discovered devices to report to %s:%i' % remote)
            return

        LOG.info('Feeding %i discovered devices to %s:%i' % (
            len(self._discovered), *remote))
        # Feed all our discovered devices to a remote requester
        for device in self._discovered.values():
            packet = (scapy.all.IP(src=device.ip, dst=remote[0]) /
                      scapy.all.UDP(sport=10001, dport=remote[1]) /
                      device.data)
            # This requires root, but avoids the problem of android
            # devices needing to see the packet coming from the same
            # address as the actual device.
            try:
                scapy.all.send(packet, verbose=False)
            except PermissionError:
                LOG.error('Unable to send spoofed packet; am I root?')
                break

    def process_loop(self):
        while True:
            r, _w, _x = select.select([self.mcast_s, self.disc_s], [], [], 10)
            if self.mcast_s in r:
                data, remote = self.mcast_s.recvfrom(1024)
                LOG.debug('Multicast %s from %s:%i' % (
                    data == REQUEST and 'request' or 'response', *remote))
                if data == REQUEST and remote[0] != self._protect_if:
                    # If this is a request packet from someone other
                    # than ourselves, we feed them the devices we know
                    # about. We also trigger another discovery if it
                    # has been long enough. Doing it here means we
                    # don't constantly discover devices if nothing is
                    # looking for them, but it also means we won't
                    # respond to the first request packet in a long
                    # time with a fresh list.
                    self.feed_discovery(remote)
                    self.discovery_tick()
            if self.disc_s in r:
                data, remote = self.disc_s.recvfrom(1024)
                LOG.debug('Discovery %s from %s:%i' % (
                    data == REQUEST and 'request' or 'response', *remote))
                if data != REQUEST:
                    device = Device(remote[0], data)
                    if device.ip in self._discovered:
                        self._discovered[device.ip].heartbeat()
                    else:
                        LOG.info('New device found at %s' % device.ip)
                        self._discovered[device.ip] = device


def main():
    p = argparse.ArgumentParser()
    p.add_argument('unifi_if', help='IP of the interface on the unifi subnet')
    p.add_argument('-q', '--quiet', action='store_true',
                   help='Only report errors')
    p.add_argument('-d', '--debug', action='store_true',
                   help='Debug output')
    p.add_argument('--multicast-group', default='233.89.188.1',
                   help='Multicast group to which discoveries are sent')
    p.add_argument('--discovery-port', default=10001,
                   help='Discovery port')
    p.add_argument('--discovery-interval', default=10,
                   help='How often to trigger our own discovery')
    args = p.parse_args()

    if args.debug:
        level = logging.DEBUG
    elif args.quiet:
        level = logging.WARNING
    else:
        level = logging.INFO
    logging.basicConfig(level=level)

    try:
        proxy = DiscoveryProxy(args.unifi_if, args.multicast_group,
                               args.discovery_port,
                               interval=args.discovery_interval)
    except OSError as e:
        LOG.error('Unable to start proxy: %s' % e)
        return 1

    try:
        proxy.process_loop()
    except KeyboardInterrupt:
        return 0


if __name__ == '__main__':
    sys.exit(main())
