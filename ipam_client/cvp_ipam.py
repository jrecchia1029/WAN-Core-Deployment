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
# pylint: disable=too-many-arguments, unused-argument, no-self-use

"""
CVP IPAM Python Client Library class
"""
import json
import requests
# import responses
import re

class CvpIpam(object):
    """
    CvpIpam class defines the CVP IPAM Client library methods
    """

    def __init__(self, test=False):
        """
        Initializer / Instance attributes
        Args:
            test (boolean): Optional used for testing
        """
        super(CvpIpam, self).__init__()
        self.test = test
        self.address = ""
        self.session_id = ""
        self.token = ""

    def login(self, address, username, password, filename='', code=200):
        """
        Log in to IPAM server
        Args:
            address (string): Address of CVP
            username (string): Username
            password (String): Password
        """
        # Build the url
        data = {'username': username, 'password': password}
        url = ('http://{}/cvp-ipam-api/login'.format(address))

        # Send the request
        if self.test:
            response = self._mock_request('POST', url, filename, code)
        else:
            response = requests.post(url, data=json.dumps(data))

        if response.status_code != 200:
            # Login failed with unexpected status
            raise Exception('Login failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # Login was not successful
            raise Exception('Login to CVP IPAM @ {} failed'.format(address))

        # Login successful
        self.address = address
        self.session_id = resp['session_id']
        self.token = resp['token']

    def _get_network(self, network, filename='', code=200):
        """[summary]

        Args:
            network ([type]): [description]
            filename (str, optional): [description]. Defaults to ''.
            code (int, optional): [description]. Defaults to 200.
        """
        # Build the url
        params = {'session_id': self.session_id,
                  'token': self.token,
                  'name': network}
        url = ('http://{}/cvp-ipam-api/network'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url, params=params)

        if response.status_code != 200:
            # Get Pool failed with unexpected status
            raise Exception('_get_network failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _get_pool was not successful
            return None
            raise Exception('_get_network: network %s not found in IPAM %s' %
                            (network))

        return resp["data"]



    def _get_pool(self, network, cidr, filename='', code=200):
        """
        Get network pool by cidr
        Args:
            network (string):
            cidr (string):
        Returns:
            pool (Object)
        """
        # Build the url
        params = {'session_id': self.session_id,
                  'token': self.token,
                  'network': network,
                  'cidr': cidr}
        url = ('http://{}/cvp-ipam-api/networkpoolbycidr'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url, params=params)

        if response.status_code != 200:
            # Get Pool failed with unexpected status
            raise Exception('_get_pool failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _get_pool was not successful
            return None
            raise Exception('_get_pool: cidr %s not found in datacenter %s' %
                            (cidr, network))

        return resp['pool']

    def _get_pools(self, network, subnet=None, filename='', code=200):
        """
        Get network pool by cidr
        Args:
            network (string):
        Returns:
            pool (Object)
        """
        # Build the url
        if subnet != None:
            subnet = self._get_pool(network, subnet)
            params = {'session_id': self.session_id,
                    'token': self.token,
                    'id': subnet["id"]
            }
        else:
            params = {'session_id': self.session_id,
                    'token': self.token,
                    'id': network
            }
        url = ('http://{}/cvp-ipam-api/pools'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url, params=params)

        if response.status_code != 200:
            # Get Pool failed with unexpected status
            raise Exception('_get_pools failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _get_pool was not successful
            raise Exception('_get_pools: network %s not found in datacenter %s' %
                            (cidr, network))
        
        return resp['data']

    def allocate_next_ip(self, view, network, hostname):
        """
        Allocate the next IP from a given Network
        Args:
            view (string):
            network (string): cidr
            hostname (string):
        Returns:
            string: IP address as string
        """
        # Get the pool and parent_id
        pool = self._get_pool(view, network)
        parent_id = pool['id']

        # Get the next allocation
        response = self._get_next_allocation(parent_id, hostname)

        return response['allocation']['address']

    def _get_next_allocation(self,
                             parent_id,
                             description,
                             filename='',
                             code=200):
        """
        Allocate the next IP from a given Network
        Args:
            parent_id (string): cidr
            description (string):
        Returns:
            next allocation (Object)
        """
        # Build the url
        params = {'session_id': self.session_id, 'token': self.token}
        data = {'parentid': parent_id, 'description': description}
        url = ('http://{}/cvp-ipam-api/nextallocation'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('POST', url, filename, code)
        else:
            response = requests.post(url, params=params, data=json.dumps(data))

        if response.status_code != 200:
            # Get next allocation failed with unexpected status
            raise Exception('_get_next_allocation failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # get_next allocation was not successful
            raise Exception(
                '_get_next_allocation: next allocation failed for %s' %
                parent_id)

        return resp

    def _get_reservations(self, pool_id, filename='', code=200):
        """
        Get list of reservations within a pool
        Args:
            pool_id (string):
        Returns:
            array object with list of reservations
        """
        # Build the url
        params = {'session_id': self.session_id,
                  'token': self.token,
                  'id': pool_id}
        url = ('http://{}/cvp-ipam-api/reservations'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url, params=params)

        if response.status_code != 200:
            # Get reservations failed with unexpected status
            raise Exception('_get_reservations failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _get_reservations was not successful
            raise Exception('_get_reservations: no reservations found')

        return resp['data']

    def deallocate_ip(self, view, network, ip_address):
        """
        Deallocate IP from given Network
        Args:
            view (string):
            network (string):
            ip_address (string):
        Returns:
            response from api
        """
        # Get the pool and parent_id
        pool = self._get_pool(view, network)
        parent_id = pool['id']

        # Get the reservations
        reservations = self._get_reservations(parent_id)

        # Assert ip_address is reserved in given network
        delete_id = ""
        for res in reservations:
            if (res['size'] == "1" and res['start'] == ip_address):
                delete_id = res['id']
                break

        if delete_id == "":
            raise Exception('deallocate_ip: IP %s not reserved from %s in %s' %
                            (ip_address, network, view))

        resp = self._delete_ip(delete_id)

        return resp

    def _delete_ip(self, delete_id, filename='', code=200):
        """
        Delete IP with given id
        Args:
            delete_id (string):
        Returns:
            response from api
        """
        # Build the url
        params = {'session_id': self.session_id, 'token': self.token}
        data = {'id': delete_id}
        url = ('http://{}/cvp-ipam-api/reservation'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('DELETE', url, filename, code)
        else:
            response = requests.delete(url,
                                       params=params,
                                       data=json.dumps(data))

        if response.status_code != 200:
            # Delete_ip failed with unexpected status
            raise Exception('_delete_ip failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _delete_ip was not successful
            raise Exception('Failed to delete %s' % delete_id)

        return resp

    def _get_child_pool(self, parent_id, name, filename='', code=200):
        """
        Get list of pools within a network or parent pool
        Args:
            parent_id (string):
            name (string):
        Returns:
            pool Object
        """
        # Build the url
        params = {'session_id': self.session_id,
                  'token': self.token,
                  'id': parent_id}
        url = ('http://{}/cvp-ipam-api/pools'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url, params=params)

        if response.status_code != 200:
            # Get child pool failed with unexpected status
            raise Exception('_get_child_pool failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _get_child_pool was not successful
            raise Exception('_get_child_pool: Parent/Child [%s/%s] not found' %
                            (parent_id, name))

        pools = resp['data']
        if pools is not None:
            for pool in pools:
                if pool['name'] == name:
                    return pool

        return None

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
        # Get the pool and parent_id
        pool = self._get_pool(view, network)
        parent_id = pool['id']

        # lookup child with given name and return if we already are created
        child_pool = self._get_child_pool(parent_id, name)
        if child_pool is None:
            return None

        return child_pool['range']

    def find_subnetworks_by_regex(self, view, network, regex):
        matched_subnets = []
        subnets = self._get_pools(view, subnet=network)
        if subnets is None:
            return matched_subnets
        for subnet in subnets:
            if re.search(regex, subnet["name"]):
                matched_subnets.append(subnet)
        return matched_subnets

    def _get_host_ip_from_pool(self, pool, hostname):
        """
        Get Host IP From Pool
        Args:
            pool (Object):
            hostname (string):
        Returns:
            string: IP address as string
        """
        # Get reservations
        reservations = self._get_reservations(pool['id'])
        if reservations is None:
            return None

        for res in reservations:
            allocations = res['allocations']
            length = len(allocations)
            if length == 0:
                continue
            for alloc in allocations:
                if alloc['description'] == hostname:
                    return alloc['name']

        # Return empty string if not found
        return None

    def get_host_ipv4_address(self, view, network, hostname):
        """
        Get Host IPv4 Address
        Args:
            view (string):
            network (string):
            hostname (string):
        Returns:
            string: IP address as string
        """
        # Get the pool
        pool = self._get_pool(view, network)

        # Get the IP address
        ip_address = self._get_host_ip_from_pool(pool, hostname)

        return ip_address

    def _format_name(self, name):
        """
        Format names with special characters
        """
        new_name = name.replace('-', '_')
        new_name = new_name.replace('|', ':')
        new_name = new_name.replace('/', '.')
        return new_name

    def allocate_child_subnet(self, view, parent, child_name, prefix_len):
        """
        Allocate child subnet from parent
        Args:
            view (string):
            parent (string):
            child_name (string):
            prefix_len (int):
        Returns:
            string: IP address as string
        """
        # Format the name
        formatted = self._format_name(child_name)

        # Get the pool
        pool = self._get_pool(view, parent)
        parent_id = pool['id']

        # Convert the length
        size = str(prefix_len)

        # Get next subnet
        ip_address = self._get_next_subnet(parent_id, formatted, size)

        return ip_address

    def _get_next_subnet(self,
                         parent,
                         child_name,
                         size,
                         filename='',
                         code=200):
        """
        Get next child subnet from parent
        Args:
            parent (string):
            child_name (string):
            size (int):
        Returns:
            string: IP address as string
        """
        # Build the url
        params = {'session_id': self.session_id, 'token': self.token}
        data = {'parentid': parent,
                'name': child_name,
                'size': size,
                'description': ""}
        url = ('http://{}/cvp-ipam-api/nextsubnet'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('POST', url, filename, code)
        else:
            response = requests.post(url, params=params, data=json.dumps(data))

        if response.status_code != 200:
            # Allocation failed with unexpected status
            raise Exception('_get_next_subnet failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # allocate child subnet was not successful
            raise Exception('_get_next_subnet: nextsubnet failed for %s' %
                            parent)

        return resp['subnet']['subnet']

    def _update_allocation_description(self,
                                       alloc_id,
                                       description,
                                       filename='',
                                       code=200):
        """
        Update allocation description
        Args:
            alloc_id (string):
            description (string):
        Returns:
            response from api
        """
        # Build the url
        params = {'session_id': self.session_id, 'token': self.token}
        data = {'id': alloc_id, 'description': description}
        url = ('http://{}/cvp-ipam-api/allocation'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('PATCH', url, filename, code)
        else:
            response = requests.patch(url,
                                      params=params,
                                      data=json.dumps(data))

        if response.status_code != 200:
            # Update failed with unexpected status
            raise Exception('update_allocation failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # update allocation was not successful
            raise Exception('_update_allocation_description failed for %s' %
                            alloc_id)

        return resp

    def update_host_ipv4_address(self, view, network, ip_address, new_name):
        """
        Update host IPv4 address
        Args:
            view (string):
            network (string):
            ip_address (string):
            new_name (string):
        Returns:
            response from _update_allocation_description
        """
        # Get the pool and parent_id
        pool = self._get_pool(view, network)

        # Get reservations
        reservations = self._get_reservations(pool['id'])

        update_id = ""

        for res in reservations:
            allocations = res['allocations']
            length = len(allocations)
            if length == 0:
                continue
            for alloc in allocations:
                if alloc['name'] == ip_address:
                    update_id = alloc['id']
                    break

        if update_id == "":
            raise Exception(
                'update_host_ipv4_address: IP %s not reserved from %s in %s' %
                (ip_address, network, view))

        response = self._update_allocation_description(update_id, new_name)
        return response

    def get_network_vlan(self, view, network):
        """
        Get Network VLAN
        Args:
            view (string):
            network (string):
        Returns:
            int: vlan as int
        """
        # Get the pool
        pool = self._get_pool(view, network)

        # Return the vlan
        if pool['vlan'] == "":
            return 0

        return int(pool['vlan'])

    def get_network_asns(self, view):
        """
        Args:
            view (str): network name
        """
        pools = self._get_pools(view)
        for pool in pools:
            if pool["name"] == "asns":
                return pool
        return None

    def get_asn_reservations(self, view):
        """Retrieve ASN reservations for a given network

        Args:
            view (str): network name

        Returns:
            [{}]: List of dictionaries of ASN reservations and their info
        """
        asn_pool = self.get_network_asns(view)
        asn_ranges = self._get_reservations(asn_pool["id"])
        return asn_ranges

    def get_network_gateway(self, view, network):
        """
        Get Network's default gateway
        Args:
            view (string):
            network (string):
        Returns:
            string: default gateway as string
        """
        # Get the pool
        pool = self._get_pool(view, network)

        # Return the network gateway
        return pool['gateway']

    def _create_pool(self, data, filename='', code=200):
        """
        Create pool with given data
        Args:
            data (object):
        Returns:
            response from api
        """
        # Build the url
        params = {'session_id': self.session_id, 'token': self.token}
        url = ('http://{}/cvp-ipam-api/pool'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('POST', url, filename, code)
        else:
            response = requests.post(url, params=params, data=json.dumps(data))

        if response.status_code != 200:
            # create pool failed with unexpected status
            raise Exception('_create_pool failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp['success'] is not True:
            # _create_pool was not successful
            raise Exception('_create_pool: _create_pool failed: %s' % resp)

        return resp

    # # pylint: disable=no-member
    # @responses.activate
    # def _mock_request(self, req_type, url, filename, status_code):
    #     """
    #     Private function to mock requests when test=True
    #     Args:
    #         req_type (string):
    #         url (string):
    #         filename (string):
    #         status_code (int):
    #     Returns:
    #         response from mock request
    #     """
    #     # Load the json response from fixtures
    #     if status_code != 200:
    #         response = {}
    #     else:
    #         with open(filename) as file_contents:
    #             response = json.load(file_contents)

    #     # Mock the request
    #     if req_type == 'POST':
    #         responses.add(responses.POST,
    #                       url,
    #                       json=response,
    #                       status=status_code)
    #         resp = requests.post(url)
    #     elif req_type == 'GET':
    #         responses.add(responses.GET,
    #                       url,
    #                       json=response,
    #                       status=status_code)
    #         resp = requests.get(url)
    #     elif req_type == 'DELETE':
    #         responses.add(responses.DELETE,
    #                       url,
    #                       json=response,
    #                       status=status_code)
    #         resp = requests.delete(url)
    #     elif req_type == 'PATCH':
    #         responses.add(responses.PATCH,
    #                       url,
    #                       json=response,
    #                       status=status_code)
    #         resp = requests.patch(url)

    #     return resp