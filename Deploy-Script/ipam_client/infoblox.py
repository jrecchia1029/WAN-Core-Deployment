#!/usr/bin/env python

# Copyright (c) 2019, Arista Networks EOS+
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# * Redistributions of source code must retain the above copyright notice, this
#   list of conditions and the following disclaimer.
#
# * Redistributions in binary form must reproduce the above copyright notice,
#   this list of conditions and the following disclaimer in the documentation
#   and/or other materials provided with the distribution.
#
# * Neither the name of the Arista nor the names of its
#   contributors may be used to endorse or promote products derived from
#   this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
# pylint: disable=unused-argument
"""
Infoblox IPAM Python Client Library class
"""
import logging
import urllib3
import json, re
from infoblox_client import connector
from infoblox_client import objects

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class Infoblox(object):
    """
    Infoblox class defines the Infoblox IPAM Client library methods
    """

    def __init__(self):
        """
        Initializer / Instance attributes
        Args:
            test (boolean): Optional used for testing
        """
        super(Infoblox, self).__init__()
        self.conn = {}
        logging.basicConfig(level=logging.DEBUG)

    def login(self, address, username, password):
        """
        Log in to IPAM server
        Args:
            address (string): Address of Infoblox
            username (string): Username
            password (String): Password
        """
        # Build the connection
        opts = {'host': address, 'username': username, 'password': password}
        self.conn = connector.Connector(opts)
        # print('conn: {}'.format(self.conn))

    def allocate_next_ip(self, view, network, hostname, mac=None):
        """
        Allocate the next IP from a given Network
        Args:
            view (string): cidr
            network (string):
            hostname (string):
            mac (string):
        Returns:
            string: IP address as string
        """
        next_ip = objects.IPAllocation.next_available_ip_from_cidr(view,
                                                                   network)
        print('next_ip: {}'.format(next_ip))
        if mac is None or mac == "":
            mac = "00:00:00:00:00:00"

        host = objects.FixedAddress.create(self.conn,
                                           cidr=network,
                                           mac=mac,
                                           comment=hostname,
                                           network_view=view,
                                           ip=next_ip)
        return host.ip

    def deallocate_ip(self, view, network, ip_address):
        """
        Deallocate IP from given Network
        Args:
            view (string): configuration
            network (string):
            ip_address (string):
        Returns:
            response from api
        """
        host = objects.FixedAddress.search(self.conn,
                                           cidr=network,
                                           ip=ip_address,
                                           network_view=view)
        if host == []:
            raise Exception('deallocate_ip: IP $s not found' % ip_address)

        resp = host.delete()
        return resp

    def find_subnetwork(self, view, network, name):
        """
        Find Subnetwork
        Args:
            view (string):
            network (string):
            name (string):
        Returns:
            string: child as string
        """
        net = objects.Network.search(self.conn,
                                     network_view=view,
                                     cidr=network)
        if net is None or net == []:
            net = objects.NetworkContainer.search(self.conn,
                                     network_view=view,
                                     cidr=network)
            return net.network
            if net is None or net == []:
                return None
                raise Exception('find_subnetwork: network %s not found' % name)

        return net.cidr

    def find_subnetworks_by_regex(self, view, network, regex):
        matched_subnets = []
        network_container = objects.NetworkContainer.search(self.conn,
                                     network_view=view,
                                     network=network.split("/")[0])

        if network_container is None:
            return matched_subnets

        subnets = objects.Network.search_all(self.conn,
                                     network_view=view,
                                     network_container=network_container.network)
        if subnets is None:
            return matched_subnets

        for subnet in subnets:
            if subnet.comment is not None and re.search(regex, subnet.comment):
                matched_subnets.append(subnet.network)
        return matched_subnets

    def get_host_ipv4_address(self, view, network, hostname):
        """
        Get Host IPv4 Address
        Args:
            view (string): cidr
            network (string):
            hostname (string):
        Returns:
            string: IP address as string
        """
        host = objects.FixedAddress.search(self.conn,
                                           network=network,
                                           comment=hostname,
                                           network_view=view)

        if host is None:
            return None

        if host == []:
            raise Exception('get_host_ipv4_address: host %s not found' %
                            hostname)

        return host.ip

    def allocate_child_subnet(self, view, parent, child_name, prefix_len):
        """
        Allocate child subnet from parent
        Args:
            view (string): cidr
            parent (string):
            child_name (string):
            prefix_len (int):
        Returns:
            string: cidr as string
        """
        # cidr_s = ("func:nextavailablenetwork:%s,%s,%d" %
        #           (parent, view, prefix_len))
        # print('cidr_s: {}'.format(cidr_s))

        next_subnet = self.get_next_available_child_subnet(view, parent, prefix_len)
        if next_subnet is not None:
            network = objects.Network.create(self.conn,
                                        network_view=view,
                                        network=next_subnet,                                        #,
                                        comment=child_name)
            return network.cidr
        else:
            raise Exception('unable to get next network in IP block %s' % parent)

    def update_host_ipv4_address(self, view, network, ip_address, new_name):
        """
        Update host IPv4 address
        Args:
            view (string): cidr
            network (string):
            ip_address (string):
            new_name (string):
        Returns:
        """
        host = objects.FixedAddress.create(self.conn,
                                           comment=new_name,
                                           ip=ip_address,
                                           network=network,
                                           network_view=view,
                                           update_if_exists=True)
        if host == []:
            raise Exception('update_host_ipv4_address: IP %s not found' %
                            ip_address)

        return host.comment

    def get_network_vlan(self, view, network):
        """
        Get Network VLAN
        Args:
            view (string): cidr
            network (string):
        Returns:
            int: vlan as int
        """
        vlan = 0
        net = self.conn.get_object('network',
                                   {'network': network, 'network_view': view})

        if 'EA' in net[0]:
            vlan = net.EA['VLAN']

        return vlan

    def get_network_gateway(self, view, network):
        """
        Get Network's default gateway
        Args:
            view (string): configuration
            network (string):
        Returns:
            string: default gateway as string
        """
        gateway = '0.0.0.0'
        return_fields = ["options"]
        resp = self.conn.get_object('network',
                                   {'network': network, 'network_view': view}, return_fields=return_fields)
        
        if 'options' in resp[0].keys():
            options = resp[0]["options"]
            for opt in options:
                if opt['name'] == 'routers':
                    gateway = opt['value']
                    break

        return gateway.split(",")[0]

    def get_next_available_child_subnet(self, view, parent_cidr, prefix_len):
        network_container = objects.NetworkContainer.search(self.conn,
                                     network_view=view,
                                     network=parent_cidr.split("/")[0])

        next_subnet = network_container.next_available_network({"cidr":prefix_len})
        if next_subnet is not None:
            return next_subnet["networks"][0]
        return next_subnet

    def allocate_next_available_ip_from_cidr(self, view, cidr):       
        next_ip = objects.IPAllocation.next_available_ip_from_cidr(view,
                                                                   cidr)
        my_ip = objects.IP.create(ip=next_ip, mac='aa:bb:cc:11:22:33', configure_for_dhcp=True)

        return my_ip

    def create_network(self, view, cidr):
        #Check to see if network already exists
        network = objects.Network.create(self.conn,
                                        network_view=view,
                                        network=cidr
                                        )

        return network

    def create_network_container(self, view, cidr):
        network_container = objects.NetworkContainer.create(self.conn,
                                        network_view=view,
                                        network=cidr
                                        )
    
        return network_container