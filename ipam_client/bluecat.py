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
BlueCat IPAM Python Client Library class
"""
import json
import requests
# import responses
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class BlueCat(object):
    """
    BlueCat class defines the BlueCat IPAM Client library methods
    """

    def __init__(self, test=False):
        """
        Initializer / Instance attributes
        Args:
            test (boolean): Optional used for testing
        """
        super(BlueCat, self).__init__()
        self.test = test
        self.address = ""
        self.token = ""

    def login(self, address, username, password, filename='', code=200):
        """
        Log in to IPAM server
        Args:
            address (string): Address of BlueCat
            username (string): Username
            password (String): Password
        """
        # Build the url
        params = {'username': username, 'password': password}
        url = ('https://{}/Services/REST/v1/login?'.format(address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url, params=params, verify=False)

        if response.status_code != 200:
            # Login failed with unexpected status
            raise Exception('Login failed with status %s' %
                            response.status_code)

        resp = response.json()

        if 'Session Token' not in resp:
            # No Token found on response
            raise Exception('BlueCat login: No token found in login payload')

        # Login successful
        array = resp.split()
        token = array[3]
        self.address = address
        self.token = token

    def _find_config_id(self, config, filename='', code=200):
        """
        Find the id of the given configuration
        Args:
            config (string): configuration
        Returns:
            string: The configuration id
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        params = {"keyword": config,
                  "category": "CONFIGURATION",
                  "start": "0",
                  "count": "10"}
        url = ('https://%s/Services/REST/v1/searchByCategory?' % self.address)

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url,
                                    headers=headers,
                                    params=params,
                                    verify=False)

        if response.status_code != 200:
            # _find_config_id failed with unexpected status
            raise Exception('_find_config_id failed with status %s' %
                            response.status_code)

        resp = response.json()

        conf_id = ''
        for conf in resp:
            if conf['name'] == config:
                conf_id = conf['id']

        if conf_id == '':
            raise Exception('_find_config_id: not found %s' % config)

        return str(conf_id)

    def _search_obj_type(self, keyword, obj_type, filename='', code=200):
        """
        Search by object type with given keyword
        Args:
            keyword (string):
            obj_type (string):
        Returns:
            array object with results
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        params = {"keyword": keyword,
                  "types": obj_type,
                  "start": "0",
                  "count": "10"}
        url = ('https://%s/Services/REST/v1/searchByObjectTypes?' %
               self.address)

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url,
                                    headers=headers,
                                    params=params,
                                    verify=False)

        if response.status_code != 200:
            # _search_obj_type failed with unexpected status
            raise Exception('_search_obj_type failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp == []:
            # No results found
            raise Exception('_search_obj_type: No results found for %s' %
                            keyword)

        return resp

    def _if_config_this(self, network_id, config_id, filename='', code=200):
        """
        Check if id from getParent matches config_id
        Args:
            config_id (string): configuration
            network_id (string):
        Returns:
            boolean:
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        params = {"entityId": network_id}
        url = ('https://{}/Services/REST/v1/getParent?'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url,
                                    headers=headers,
                                    params=params,
                                    verify=False)

        if response.status_code != 200:
            # getParent failed with unexpected status
            raise Exception('_if_config_this:getParent failed with status %s' %
                            response.status_code)

        resp = response.json()

        parent_id = str(resp['id'])
        if parent_id == config_id:
            return True
        elif parent_id == "0":
            return False

        return self._if_config_this(parent_id, config_id)

    def _find_network_id(self, config, network, object_type):
        """
        Find the network id of the given configuration
        Args:
            config (string): configuration
            network (string):
            object_type (string):
        Returns:
            int: The network id, -1 if failed
        """
        # Search by object_type with given network as keyword
        resp = self._search_obj_type(network, object_type)

        # Find configuration id
        conf_id = self._find_config_id(config)

        for obj in resp:
            obj_id = str(obj['id'])
            found = self._if_config_this(obj_id, conf_id)
            if found:
                return obj['id']

        return -1

    def allocate_next_ip(self, view, network, hostname, mac):
        """
        Allocate the next IP from a given Network
        Args:
            view (string): configuration
            network (string):
            hostname (string):
            mac (string):
        Returns:
            string: IP address as string
        """
        # Find configuration id and network id
        conf_id = self._find_config_id(view)
        net_id = self._find_network_id(view, network, "IP4Network")

        # Allocate next ip from network
        resp = self._allocate_helper(conf_id, str(net_id), hostname)

        # Extract ip address from response
        ip_address = self._extract_field(resp, "address")

        return ip_address

    def _allocate_helper(self,
                         conf_id,
                         net_id,
                         hostname,
                         filename='',
                         code=200):
        """
        Helper method for allocate_next_ip
        Args:
            conf_id (string): configuration id
            net_id (string): network id
            hostname (string):
        Returns:
            properties object from api response
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        properties = "name={}".format(hostname)
        params = {"configurationId": conf_id,
                  "parentId": net_id,
                  "action": "MAKE_STATIC",
                  "hostinfo": hostname,
                  "properties": properties}
        url = ('https://%s/Services/REST/v1/assignNextAvailableIP4Address?' %
               self.address)

        # Send the request
        if self.test:
            response = self._mock_request('POST', url, filename, code)
        else:
            response = requests.post(url,
                                     headers=headers,
                                     params=params,
                                     verify=False)

        if response.status_code != 200:
            # _allocate_helper failed with unexpected status
            raise Exception('_allocate_helper: Post failed with status %s' %
                            response.status_code)

        resp = response.json()

        if resp == {}:
            # IP not available
            raise Exception('_allocate_helper: IP not available')

        return resp['properties']

    def _extract_field(self, properties, field):
        """
        Extract given field from properties String
        Args:
            properties (string):
            field (string):
        Returns:
            value at given field
        """
        props = properties.split('|')
        prop_map = {}
        for prop in props:
            if prop == '':
                break
            line = prop.split('=')
            prop_map[line[0]] = line[1]

        return prop_map[field]

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
        # Search ip address to delete
        resp = self._search_obj_type(ip_address, 'IP4Address')

        # Find configuration id
        conf_id = self._find_config_id(view)

        for addr in resp:
            addr_id = str(addr['id'])
            found = self._if_config_this(addr_id, conf_id)
            if found:
                del_resp = self._delete_ip(addr_id)
                return del_resp

        # Ip was not found in configuration
        raise Exception('deallocate_ip: ip %s was not found in %s' %
                        (ip_address, view))

    def _delete_ip(self, delete_id, filename='', code=200):
        """
        Delete IP with given id
        Args:
            delete_id (string):
        Returns:
            response from api
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        params = {"objectId": delete_id}
        url = ('https://{}/Services/REST/v1/delete?'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('DELETE', url, filename, code)
        else:
            response = requests.delete(url,
                                       headers=headers,
                                       params=params,
                                       verify=False)

        if response.status_code != 200:
            # _delete_ip failed with unexpected status
            raise Exception('_delete_ip: Delete failed with status %s' %
                            response.status_code)

        resp = response.json()
        return resp

    def find_subnetwork(self, view, network, name):
        """
        Find Subnetwork
        Args:
            view (string): configuration
            network (string):
            name (string):
        Returns:
            string: child as string
        """
        # Search for network
        resp = self._search_obj_type(network, 'IP4Network')

        # Find configuration id
        conf_id = self._find_config_id(view)

        for net in resp:
            net_id = str(net['id'])
            found = self._if_config_this(net_id, conf_id)
            if found:
                return net['name']

        # Network not found
        raise Exception('find_subnetwork: network %s not found in %s' %
                        (network, view))

    def get_host_ipv4_address(self, view, network, hostname):
        """
        Get Host IPv4 Address
        Args:
            view (string): configuration
            network (string):
            hostname (string):
        Returns:
            string: IP address as string
        """
        ip_address = self._search_ipv4_addr(hostname)
        if ip_address == '':
            # Ip address not found
            raise Exception(
                'get_host_ipv4_address: ip with name %s not found' %
                hostname)
        return ip_address

    def _search_ipv4_addr(self, name):
        """
        Search IPv4 Address by given name
        Args:
            name (string):
        Returns:
            string: IP address as string
        """
        # Search for ip address by given name
        resp = self._search_obj_type(name, 'IP4Address')
        for addr in resp:
            if name == addr['name']:
                return self._extract_field(addr['properties'], 'address')

        # Return empty string if not found
        return ''

    def allocate_child_subnet(self, view, parent, child_name, prefix_len):
        """
        Allocate child subnet from parent
        Args:
            view (string): configuration
            parent (string):
            child_name (string):
            prefix_len (int):
        Returns:
            string: cidr as string
        """
        # Find the network id
        net_id = self._find_network_id(view, parent, "IP4Block")

        # Format size
        size = 2 ** (32 - prefix_len)

        # Get next available network
        network = self._get_next_network(net_id, size)

        # Update the name of the newly created Network
        self._update_name(network, child_name, "IP4Network")

        # Get entity properties and return cidr
        entity = self._get_entity(network)
        cidr = self._extract_field(entity['properties'], "CIDR")
        return cidr

    def _get_next_network(self, net_id, size, filename='', code=200):
        """
        Get next available network
        Args:
            net_id (string): network id
            size (string):
        Returns:
            next available network
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        params = {"parentId": net_id,
                  "size": size,
                  "isLargerAllowed": "false",
                  "autoCreate": "true"}
        url = ('https://%s/Services/REST/v1/getNextAvailableIP4Network?' %
               self.address)

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url,
                                    headers=headers,
                                    params=params,
                                    verify=False)

        if response.status_code != 200:
            # get next network failed with unexpected status
            raise Exception('_get_next_network: GET failed with status %s' %
                            response.status_code)

        resp = response.json()
        return resp

    def _update_name(self, obj_id, name, obj_type, filename='', code=200):
        """
        Update the name for IP4Network or IP4Address
        Args:
            obj_id (int): Id of ip address or network
            name (string):
            obj_type (string):
        Returns:
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        data = {"id": obj_id,
                "type": obj_type,
                "name": name}
        url = ('https://{}/Services/REST/v1/update'.format(self.address))

        # Send the request
        if self.test:
            response = self._mock_request('PUT', url, filename, code)
        else:
            response = requests.put(url,
                                    headers=headers,
                                    data=json.dumps(data),
                                    verify=False)

        if response.status_code != 200:
            # _update_name failed with unexpected status
            raise Exception('_update_name: PUT failed with status %s' %
                            response.status_code)

        resp = response.json()
        return resp

    def _get_entity(self, entity_id, filename='', code=200):
        """
        Get Entity by id
        Args:
            entity_id (int):
        Returns:
            entity object
        """
        # Build the url
        headers = {
            'Authorization': 'BAMAuthToken: {}'.format(self.token)
        }
        params = {"id": entity_id}
        url = ('https://%s/Services/REST/v1/getEntityById?' % self.address)

        # Send the request
        if self.test:
            response = self._mock_request('GET', url, filename, code)
        else:
            response = requests.get(url,
                                    headers=headers,
                                    params=params,
                                    verify=False)

        if response.status_code != 200:
            # _get_entity failed with unexpected status
            raise Exception('_get_entity: GET failed with status %s' %
                            response.status_code)

        resp = response.json()
        return resp

    def update_host_ipv4_address(self, view, network, ip_address, new_name):
        """
        Update host IPv4 address
        Args:
            view (string): configuration
            network (string):
            ip_address (string):
            new_name (string):
        Returns:
        """
        # search for ip address
        resp = self._search_obj_type(ip_address, 'IP4Address')

        # find the network id
        config_id = self._find_config_id(view)

        for addr in resp:
            addr_id = str(addr['id'])
            found = self._if_config_this(addr_id, config_id)
            if found:
                # IP found, update it
                update_resp = self._update_name(addr['id'],
                                                new_name,
                                                'IP4Address')
                return update_resp

        # Ip not found
        raise Exception('update_host_ipv4_address: IP %s not found to update' %
                        ip_address)

    def get_network_vlan(self, view, network):
        """
        Get Network VLAN
        Args:
            view (string): configuration
            network (string):
        Returns:
            int: vlan as int
        """
        return 0

    def get_network_gateway(self, view, network):
        """
        Get Network's default gateway
        Args:
            view (string): configuration
            network (string):
        Returns:
            string: default gateway as string
        """
        # Search for network
        resp = self._search_obj_type(network, 'IP4Network')

        # Find Configuration id
        config_id = self._find_config_id(view)

        for net in resp:
            net_id = str(net['id'])
            found = self._if_config_this(net_id, config_id)
            if found:
                gateway = self._extract_field(net['properties'], "gateway")
                return gateway

        # Gateway not found
        raise Exception('get_network_gateway: Gateway not found in network %s'
                        % network)

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
    #         if filename == "string_response":
    #             response = ""
    #         else:
    #             with open(filename) as file_contents:
    #                 response = json.load(file_contents)

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
    #     elif req_type == 'PUT':
    #         responses.add(responses.PUT,
    #                       url,
    #                       json=response,
    #                       status=status_code)
    #         resp = requests.put(url)

    #     return resp
