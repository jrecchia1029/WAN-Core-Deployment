import pyeapi
from filters.natural_sort import natural_sort
from jinja2 import Environment, FileSystemLoader
import json, string, random, re

#Set up templates
env = Environment(loader=FileSystemLoader('templates'))
env.filters["natural_sort"] = natural_sort

mgmt_values = {
    "vrf_name": "mgmt",
    "vrf_description": "management VRF",
    "interface": "Management1",
    "interface_description": "oob management"
}

bgp_values = {
    "underlay_peer_group": "WANCORE",
    "overlay_peer_group": "WC-EVPN-TRANSIT",
    "bgp_defaults":[
        "maximum-paths 4 ecmp 4",
        "no bgp default ipv4-unicast"
    ],
    "peer_groups": {
        "WANCORE" :{
            "description":"WAN Core ipv4 underlay peering group",
            "bfd": True,
            "maximum_routes": 12000
        },
            "WC-EVPN-TRANSIT":{
            "description":"WAN Core evpn overlay peering group",
            "bfd": False,
            "maximum_routes": 0,
            "update_source": "Loopback0",
            "ebgp_multihop": "",
            "send_coommunity": True
        }
    },
    "core_redistribution_routes":{
        "connected": {}
    },
    "service_redistribution_routes":{
        "connected": {}
        # "learned": {}
    },
    "service_vrfs":{
        "maximum_routes": 0
    },
    "address_family_evpn": {
        "peer_groups": {
            "WC-EVPN-TRANSIT":{
                "activate": True
            }
        }
    },
    "address_family_ipv4": {
        "peer_groups": {
            "WANCORE":{
                "activate": True
            }
        }
    }
}

class CoreRouter():
    """
    Class to act as an EOS Switch object.  Uses Netmiko (SSH) or jsonrpclib (EAPI) to execute switch functions. 
    """
    def __init__(self, ip_address=None, hostname=None, username=None, password=None):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.hostname = hostname
        self.core_interfaces = None
        self.site_interfaces = None
        self.loopback0_ip = None
        self.loopback1_ip = None
        self.asn = None
        self.core_bgp_neighbors = None
        self.mgmt_gateway = None

    def __str__(self):
        output = ""
        output += "CoreRouter: {}\n".format(self.hostname)
        # output += "  {:15} {}\n".format("FQDN:", self.fqdn)
        output += "  {:15} {}\n".format("IP address:", self.ip_address)
        # output += "  {:15} {}\n".format("MAC address:", self.mac_address)
        # output += "  {:15} {}\n".format("EOS version:", self.eos_version)
        # output += "  {:15} {}\n".format("Serial Number:", self.serial_number)
        output += "  {:15} {}\n".format("Lo0 IP address:", self.loopback0_ip)
        output += "  {:15} {}\n".format("Lo1 IP address:", self.loopback1_ip)
        output += "  {:15} {}\n".format("BGP ASN:", self.asn)
        output += "  {:15} {}\n".format("Mgmt Gateway:", self.mgmt_gateway)
        return output

    # writing and defining a function that we can re-use which will send commands to a switch running Arista EOS
    def send_commands_via_eapi(self, commands, encoding="json", enable=True):
        """
        Uses the Server class from jsonrpclib to make API calls to the Arista EAPI running on switches
            Inputs:
                ip_address ( str ): IP address
                username ( str ): username for switch
                password ( str ): password for switch
                cmds ( [str] ):  A list of commands to be executed on the switch
            
            Outputs:
                Returns a list of dictionariesc( [{}] ) with a single key/value pair of command/output
        """
        if type(commands) == str:
            commands = [commands]

        try:
            switch = pyeapi.connect(host=self.ip_address.split("/")[0], username=self.username, password=self.password)
            if enable==True:
                commands.insert(0, "enable")
            response = switch.execute(commands, encoding=encoding)
        except Exception as e:
            print("Error:", e)
            return None
        else:
            result = response["result"]
            if enable==True:
                result.pop(0)
            return result

    def mergeConfigs(self, configs):
        """
        Args:
            configs ([str]): list of configs to merge

        Returns merged config via config session
        """
        # print("Merging configs")
        letters_and_digits = string.ascii_letters + string.digits
        session_id = ''.join((random.choice(letters_and_digits) for i in range(10)))
        commands = [
            "enable",
            "configure session {}".format(session_id),
            "rollback clean-config"
            ]
        for config in configs:
            for line in config.split("\n"):
                commands.append(line)
            commands += ["end", "configure session {}".format(session_id)]
        commands += ["show session-config", "abort"]
        
        response = self.send_commands_via_eapi(commands, encoding="text")

        if response is None:
            self.send_commands_via_eapi(["configure session {} abort".format(session_id)])
            print("Error merging config")
            return None

        merged_config = response[-2]["output"]
        merged_config = "\n".join(merged_config.split("\n")[10:])
        cleaned_merged_config = ""

        #Remove empty interface section from merged_config
        for section in re.split(r'!\n(?=interface)', merged_config):
            if not re.match(r'^interface\s+Ethernet\d+$', section.strip()):
                cleaned_merged_config += section + "!\n"

        #Strip off last 7 characters which are '\n,e,n,d,\n,!,\n'
        return cleaned_merged_config[:-7]

    def getManagementInfo(self, routing_details, ipam, ipam_network):
        self.ip_address = get_management_address_from_ipam(ipam, ipam_network, routing_details["management subnet"], self.hostname)
        self.mgmt_gateway = get_management_gateway(ipam, ipam_network, routing_details["management subnet"])

    def getCoreInterfaces(self, core_rtrs):
        core_interfaces = {}
        lldp_neighbors = self.getLLDPNeighbors()
        for rtr in core_rtrs:
            for neighbor in lldp_neighbors:
                if rtr.hostname in neighbor["neighborDevice"]:
                    core_interfaces[ neighbor["port"] ] = {
                            "neighbor hostname": rtr.hostname,
                            "neighbor interface": neighbor["neighborPort"]
                        }
        self.core_interfaces = core_interfaces

    def getAddressesForCoreFabric(self, routing_details, ipam, ipam_network):
        for interface, details in self.core_interfaces.items():
            connection_info = {
                "hostname": self.hostname,
                "local interface": interface,
                "neighbor hostname": details["neighbor hostname"],
                "neighbor interface": details["neighbor interface"]
            }
            interface_ip = get_transit_ip_from_ipam(ipam, ipam_network, routing_details["core to core subnet"], connection_info)
            self.core_interfaces[interface]["ip address"] = interface_ip
        
        self.loopback0_ip = get_loopback_ip_from_ipam(ipam, ipam_network, routing_details["loopback0 subnet"], self.hostname)
        self.loopback1_ip = get_loopback_ip_from_ipam(ipam, ipam_network, routing_details["loopback1 subnet"], self.hostname)
        asn_start = routing_details["asn range"].split("-")[0].strip()
        asn_end = routing_details["asn range"].split("-")[-1].strip()
        self.asn = get_asn_from_ipam(ipam, ipam_network, asn_start, asn_end, self.hostname)

    def getCoreBGPNeighborInfo(self, core_rtrs):
        underlay_pg_name = bgp_values["underlay_peer_group"]
        overlay_pg_name = bgp_values["overlay_peer_group"]
        bgp_neighbors = {}
        for rtr in core_rtrs:
            if rtr.hostname != self.hostname:
                for interface_details in rtr.core_interfaces.values():
                    if interface_details["neighbor hostname"] == self.hostname:
                        bgp_neighbors[interface_details["ip address"].split("/")[0]] = {
                            "asn": rtr.asn,
                            "peer group": underlay_pg_name
                        }
                        break
                bgp_neighbors[rtr.loopback1_ip.split("/")[0]] = {
                    "asn": rtr.asn,
                    "peer group": overlay_pg_name
                }
        self.core_bgp_neighbors = bgp_neighbors

    def getSiteInterfaces(self, site_rtrs, ipam, ipam_network):
        site_interfaces = {}
        lldp_neighbors = self.getLLDPNeighbors()
        for rtr in site_rtrs:
            for neighbor in lldp_neighbors:
                if rtr.hostname in neighbor["neighborDevice"]:
                    # Add site link to core_rtr.site_interfaces
                    site_interfaces[ neighbor["port"] ] = {
                            "neighbor router": rtr,
                            "neighbor interface": neighbor["neighborPort"],
                            "ip address": None,
                            "neighbor ip address": None,
                            "subnet": None,
                        }
                    for service in rtr.site.services:
                        site_interfaces["{}.{}".format(neighbor["port"], service["subinterface vlan"])] = {
                                "neighbor router": rtr,
                                "neighbor interface": "{}.{}".format(neighbor["neighborPort"], service["subinterface vlan"]),
                                "ip address": None,
                                "neighbor ip address": None,
                                "vlan":  service["subinterface vlan"],
                                "vrf": service["vrf"],
                                "subnet": service["subinterface subnet"]
                            }
        # #Get IP Address for site interfaces
        for interface, details in site_interfaces.items():
            if details["subnet"] is None:
                continue
            connection_info = {
                "hostname": self.hostname,
                "local interface": interface,
                "neighbor hostname": details["neighbor router"].hostname,
                "neighbor interface": details["neighbor interface"]
            }
            local_interface_ip = get_transit_ip_from_ipam(ipam, ipam_network, details["subnet"], connection_info)
            site_interfaces[interface]["ip address"] = local_interface_ip
            neighbor_connection_info = {
                "hostname": details["neighbor router"].hostname,
                "local interface": details["neighbor interface"],
                "neighbor hostname": self.hostname,
                "neighbor interface": interface
            }
            neighbor_interface_ip = get_transit_ip_from_ipam(ipam, ipam_network, details["subnet"], neighbor_connection_info)
            site_interfaces[interface]["neighbor ip address"] = neighbor_interface_ip
        self.site_interfaces = site_interfaces

    def getLLDPNeighbors(self):
        return self.send_commands_via_eapi(["show lldp neighbors"])[0]["lldpNeighbors"]

    def produceManagementConfig(self):
        #Format variables for templates
        mgmt_vrf = mgmt_values["vrf_name"]
        mgmt_interface = mgmt_values["interface"]
        data = {
            "vrfs":{
                mgmt_vrf:{
                    "description": mgmt_values["vrf_description"],
                    "ip_routing": False
                }
            },
            "management_interfaces":{
                mgmt_interface: {
                    "vrf": mgmt_vrf,
                    "ip_address": self.ip_address,
                    "description": mgmt_values["interface_description"]
                }
            },
            "management_api_http":{
                "enable_https": True,
                "enable_vrfs": {
                    mgmt_vrf: {}
                }
            },
            "static_routes":[{
                "vrf": mgmt_vrf,
                "destination_address_prefix": "0.0.0.0/0",
                "gateway": self.mgmt_gateway
            }
            ]
        }
        template = env.get_template('management-configlet.j2')
        return formatConfig( template.render(data) )

    def produceCoreFabricConfig(self, services):
        #Format variables for templates
        #Format Service VRFs
        vrfs = {}
        for service in services:
            vrfs[service["vrf"]] = {
                "ip_routing":True,
                "description": service["description"]
                }

        #Format core transit interfaces
        ethernet_interfaces = {}
        for iface, details in self.core_interfaces.items():
            ethernet_interfaces[iface] = {
                "description": "Connection to {} : {}".format(details["neighbor hostname"], details["neighbor interface"]),
                "type": "routed",
                "ip_address": details["ip address"]
            }

        #Format loopback interfaces
        loopback_interfaces = {
            "Loopback0": {
                "description": "EVPN Peering Source",
                "ip_address": self.loopback0_ip
            },
            "Loopback1":{
                "description": "VXLAN Tunnel Source",
                "ip_address": self.loopback1_ip                
            }
        }

        #Format Vxlan interface
        vxlan_interface = {
            "Vxlan1":{
                "source_interface": "Loopback1",
                "vxlan_udp_port": 4789,
                "vxlan_vni_mappings":{
                    "vrfs": {}
                }
            }
        }
        for service in services:
            vxlan_interface["Vxlan1"]["vxlan_vni_mappings"]["vrfs"][service["vrf"]] = {
                "vni": service["vni"]
            }
        #Format BGP info
        router_bgp = {
            "as": self.asn,
            "router_id": self.loopback0_ip.split("/")[0],
            "bgp_defaults": bgp_values["bgp_defaults"],
            "peer_groups": bgp_values["peer_groups"],
            "neighbors": {},
            "redistribute_routes": bgp_values["core_redistribution_routes"],
            "address_family_evpn": bgp_values["address_family_evpn"],
            "address_family_ipv4": bgp_values["address_family_ipv4"],
            "vrfs": {}
        }
        for neighbor, info in self.core_bgp_neighbors.items():
            router_bgp["neighbors"][neighbor] = {
                "peer_group": info["peer group"],
                "remote_as": info["asn"]
            }
        for service in services:
            router_bgp["vrfs"][ service["vrf"] ] = {
                "rd": "{}:{}".format(self.loopback0_ip.split("/")[0], service["vni"]),
                "route_targets":{
                    "import":{
                        "evpn": [ "{}:{}".format(service["vni"], service["vni"]) ]
                    },
                    "export":{
                        "evpn": [ "{}:{}".format(service["vni"], service["vni"]) ]
                    }
                },
                "router_id": self.loopback0_ip.split("/")[0],
                "redistribute_routes": bgp_values["service_redistribution_routes"],
                "neighbors": {}
            }
            for neighbor, info in self.core_bgp_neighbors.items():
                if info["peer group"] == bgp_values["overlay_peer_group"]:
                    router_bgp["vrfs"][ service["vrf"] ]["neighbors"][ neighbor ] = {
                        "remote_as": info["asn"],
                         #Max routes for service VRF neighbors
                        "maximum_routes": bgp_values["service_vrfs"]["maximum_routes"]
                    }
        
        data = {
            "vrfs": vrfs,
            "ethernet_interfaces": ethernet_interfaces,
            "loopback_interfaces": loopback_interfaces,
            "vxlan_tunnel_interface": vxlan_interface,
            "ip_routing": True,
            "router_bgp": router_bgp
        }
        template = env.get_template('core-fabric-configlet.j2')
        return formatConfig( template.render(data) )
    
    def produceCoreToSiteConfig(self):
        #Format variables for templates
        ethernet_interfaces = {}
        for iface, details in self.site_interfaces.items():
            ethernet_interfaces[iface] = {
                "description": "Connection to {} : {}".format(details["neighbor router"].hostname, details["neighbor interface"]),
                "ip_address": details["ip address"],
                "type": "routed"
            }
            if "." in iface:
                ethernet_interfaces[iface]["type"] = "subinterface"
                ethernet_interfaces[iface]["vrf"] = details["vrf"]
                ethernet_interfaces[iface]["vlans"] = details["vlan"]
        
        #Format BGP & VRF variables 
        router_bgp = {
            "as": self.asn,
            "vrfs": {}
        }
        for interface, details in self.site_interfaces.items():
            for service in details["neighbor router"].site.services:
                if details["neighbor ip address"] is not None:
                    #If no service vrf exists in routger_bgp["vrfs"] details yet create one 
                    if service not in list(router_bgp["vrfs"].keys()):
                        router_bgp["vrfs"][ service["vrf"] ] = {
                            "route_targets": {},
                            "neighbors": {},
                            "description": service["description"],
                            "ip_routing": True
                        }
                    router_bgp["vrfs"][ service["vrf"] ]["neighbors"][details["neighbor ip address"].split("/")[0]] = {
                        "remote_as": details["neighbor router"].site.asn,
                         #Max routes for service VRF neighbors
                         "maximum_routes": bgp_values["service_vrfs"]["maximum_routes"]
                    }
        data = {
            "ip_routing": True,
            "vrfs": router_bgp["vrfs"],
            "ethernet_interfaces": ethernet_interfaces,
            "router_bgp": router_bgp
        }
        template = env.get_template('core-to-site-configlet.j2')
        return formatConfig( template.render(data) )

def get_transit_ip_from_ipam(cvp_ipam, view, transit_block, connection):
    '''
    Gets the Transit IP address from CVP IPAM for a device's interface based on connection details.
    If the IP Address for the Device's Interface does not exist in IPAM, it gets the next available from a dedicated subnet
    
    view: CVP IPAM network 
    transit_block: cidr
    connection: dictionary of connection details for interface
        {
            "hostname": hostname,
            "local interface": local_interface,
            "neighbor hostname": neighbor_hostname,
            "neighbor interface": neighbor_interface
        }
    '''
    child_subnet_re = "{}:{}".format(connection["hostname"], connection["local interface"]) #endpointA:interfaceA
    child_subnet_re = child_subnet_re.replace("-", "_") #CVP IPAM converts "-" to "_"
    allocation_name = child_subnet_re
    #Check to see if child subnet exists
    subnets = cvp_ipam.find_subnetworks_by_regex(view, transit_block, child_subnet_re)
    if len(subnets) == 1:
        subnet = subnets[0]["range"]
        #Check to see if address exists
        ip_address = cvp_ipam.get_host_ipv4_address(view, subnet, allocation_name)
        if ip_address is not None:
            return ip_address + "/31"
    else:
        #Create child_subnet name
        child_subnet_name = "{}:{}::{}:{}".format(connection["hostname"], connection["local interface"], connection["neighbor hostname"], connection["neighbor interface"]) #endpointA:interfaceA::endpointB:interfaceB
        #Create new child subnet
        subnet = cvp_ipam.allocate_child_subnet(view, transit_block, child_subnet_name, 31)

    #Allocate next available IP address for connection-interface on that subnet
    next_allocation = cvp_ipam.allocate_next_ip(view, subnet, allocation_name)

    return cvp_ipam.get_host_ipv4_address(view, subnet, allocation_name) + "/31"

def get_loopback_ip_from_ipam(cvp_ipam, view, loopback_range, hostname):
    '''
    Gets the Loopback IP address from CVP IPAM for a device's Loopback interface based on the loopback range.
    If the IP Address for the Device's Loopback Interface does not exist in IPAM, it gets the next available from the loopback range

    view: CVP IPAM network 
    loopback_range: cidr notation
    hostname: hostname of switch
    '''
    #Check to see if host already has an IP address assigned to loopback
    ip_address = cvp_ipam.get_host_ipv4_address(view, loopback_range, hostname)
    if ip_address is not None:
        return ip_address + "/32"
    #Allocate next available IP address for connection-interface on that subnet
    next_allocation = cvp_ipam.allocate_next_ip(view, loopback_range, hostname)
    return cvp_ipam.get_host_ipv4_address(view, loopback_range, hostname) + "/32"

def get_management_address_from_ipam(cvp_ipam, view, management_range, hostname):
    '''
    Gets the Management IP address from CVP IPAM for a device's Management interface based on the management range.
    If the IP Address for the Device's Management Interface does not exist in IPAM, it gets the next available from the management range

        cvp_ipam (ipam): CVP IPAM client
        view (str): CVP IPAM network 
        management_range (str): cidr notation
        hostname (str): hostname of switch
    '''
    netmask = management_range.split("/")[-1]
    #Check to see if host already has an IP address assigned to 
    ip_address = cvp_ipam.get_host_ipv4_address(view, management_range, hostname)
    if ip_address is not None:
        return "{}/{}".format(ip_address, netmask)
    #Allocate next available IP address for connection-interface on that subnet
    next_allocation = cvp_ipam.allocate_next_ip(view, management_range, hostname)
    return "{}/{}".format(cvp_ipam.get_host_ipv4_address(view, management_range, hostname), netmask)

def get_management_gateway(cvp_ipam, view, management_range):
    '''
    Gets the Management gateway IP from management subnet

        cvp_ipam (ipam): CVP IPAM client
        view (str): CVP IPAM network 
        management_range (str): cidr notation
    '''
    mgmt_network = cvp_ipam._get_pool(view, management_range)
    if mgmt_network is not None:
        return mgmt_network["gateway"]

def get_asn_from_ipam(cvp_ipam, view, asn_start, asn_end, hostname):
    """[summary]

    Args:
        cvp_ipam (ipam): CVP IPAM client
        view (str): CVP IPAM network 
        asn_range (str): asn range to get allocations from
        hostname (str): hostname of switch
    """
    #Find reservation by asn range
    reservation = None
    reservations = cvp_ipam.get_asn_reservations(view)
    for rezzy in reservations:
        if rezzy["start"] == asn_start and rezzy["end"] == asn_end:
            reservation = rezzy
            break
    #If ASN range doesn't exist return None
    if reservation is None:
        return None
    #For allocation in allocations
    for allocation in reservation["allocations"]:
        #If the hostname is found in the description of the allocation within the reservation
        if hostname in [ x.strip() for x in allocation["description"].split(":") ]:
            #Return the ASN value
            return allocation["value"]
    #Allocate the next available asn_value
    response = cvp_ipam._get_next_allocation(reservation["id"], hostname)

    return response['allocation']['value']

def formatConfig(config):
    return "\n".join([line for line in config.split("\n") if line.strip() != ""])
