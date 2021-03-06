import pyeapi
from ipam_client.infoblox import Infoblox
from ipam_client.cvp_ipam import CvpIpam
from filters.natural_sort import natural_sort
from jinja2 import Environment, FileSystemLoader
import ipaddress, yaml, json, string, random, re, os
import logging

logger = logging.getLogger('main.switch')

path = os.path.abspath(os.path.dirname(__file__))


#Set up templates
env = Environment(loader=FileSystemLoader('{}/templates'.format(path)), extensions=['jinja2.ext.do'])
env.filters["natural_sort"] = natural_sort

class CoreRouter():
    """
    Class to act as an EOS Switch object.  Uses Netmiko (SSH) or jsonrpclib (EAPI) to execute switch functions. 
    """
    def __init__(self, ip_address=None, hostname=None, username=None, password=None, serial_number=None):
        self.ip_address = ip_address
        self.username = username
        self.password = password
        self.hostname = hostname
        self.serial_number = serial_number
        self.core_interfaces = None
        self.site_interfaces = None
        self.loopback0_ip = None
        self.loopback1_ip = None
        self.asn = None
        self.core_bgp_neighbors = None
        self.mgmt_gateway = None
        self.logger = logging.getLogger("main.switch.CoreRouter")

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
            # self.logger.debug("Connecting to switch using {} and the username {}".format(self.ip_address.split("/")[0], self.username))
            switch = pyeapi.connect(host=self.ip_address.split("/")[0], username=self.username, password=self.password)
            if enable==True:
                commands.insert(0, "enable")
            response = switch.execute(commands, encoding=encoding)
        except Exception as e:
            self.logger.error(e)
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
        self.logger.debug("Merging configs")
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

        black_list_lines = ["service routing protocols model ribd\n!\n", "spanning-tree mode mstp\n!\n", "no aaa root\n!\n"]
        for line in black_list_lines:
            merged_config = merged_config.replace(line, "")

        merged_config = "\n".join(merged_config.split("\n")[4:])
        cleaned_merged_config = ""

        black_list_lines = ["spanning-tree mode mstp", "no aaa root"]

        #Remove empty interface section from merged_config
        for section in re.split(r'\n(?=interface)', merged_config):
            section = re.sub(r'^interface\s+(Ethernet|Port-Channel|Management|Vlan|Vxlan)\d+(\/\d+)*\n!', '', section)
            if section.strip() != "":
                if section[0] == "\n":
                    section = section[1:]
                cleaned_merged_config += section + "\n"
        
        #Append last "!" for aesthetic reasons
        cleaned_merged_config += "!"

        #Strip off last 7 characters which are '\n,e,n,d,\n,!,\n'
        return cleaned_merged_config[:-7]

    def getManagementInfo(self, routing_details, ipam, ipam_network):
        mgmt_settings = yaml.load(open("{}/settings/config_defaults/management.yml".format(path)), Loader=yaml.FullLoader)
        self.logger.debug("Getting management info for {}".format(self.hostname))
        if mgmt_settings["management_plane"] == "inband":
            self.ip_address = get_management_address_from_ipam(ipam, ipam_network, routing_details["ib management subnet"], self.hostname)
            self.mgmt_gateway = get_management_gateway(ipam, ipam_network, routing_details["ib management subnet"])
        else:
            self.ip_address = get_management_address_from_ipam(ipam, ipam_network, routing_details["oob management subnet"], self.hostname)
            self.mgmt_gateway = get_management_gateway(ipam, ipam_network, routing_details["oob management subnet"])

    def getCoreInterfaces(self, core_rtrs):
        self.logger.debug("Setting core_interfaces for {}".format(self.hostname))
        core_interfaces = {}
        lldp_neighbors = self.getLLDPNeighbors()
        if lldp_neighbors is None:
            return
        for rtr in core_rtrs:
            for neighbor in lldp_neighbors:
                if rtr.hostname in neighbor["neighborDevice"]:
                    core_interfaces[ neighbor["port"] ] = {
                            "neighbor hostname": rtr.hostname,
                            "neighbor interface": neighbor["neighborPort"]
                        }
        self.core_interfaces = core_interfaces

    def getAddressesForCoreFabric(self, routing_details, ipam, ipam_network):
        self.logger.debug("Getting IP addresses for core fabric for {}".format(self.hostname))
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
        
    def getBGPASN(self, routing_details, ipam, ipam_network):
        self.logger.debug("Getting ASN for {}".format(self.hostname))
        asn_start = routing_details["core asn range"].split("-")[0].strip()
        asn_end = routing_details["core asn range"].split("-")[-1].strip()
        self.asn = get_asn_from_ipam(ipam, ipam_network, asn_start, asn_end, self.hostname)

    def getCoreBGPNeighborInfo(self, core_rtrs):
        #Load default values
        bgp_values = yaml.load(open("{}/settings/config_defaults/bgp.yml".format(path)), Loader=yaml.FullLoader)

        self.logger.debug("Setting core_bgp_neighbors for {}".format(self.hostname))
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
                bgp_neighbors[rtr.loopback0_ip.split("/")[0]] = {
                    "asn": rtr.asn,
                    "peer group": overlay_pg_name
                }
        self.core_bgp_neighbors = bgp_neighbors

    def getSiteInterfaces(self, site_rtrs, ipam, ipam_network):
        sites_peering_on_svis = yaml.load(open("{}/settings/sites.yml".format(path)), Loader=yaml.FullLoader)["sites_peering_on_svis"]
        self.logger.debug("Getting site_interfaces for {}".format(self.hostname))
        site_interfaces = {}
        lldp_neighbors = self.getLLDPNeighbors()
        if lldp_neighbors is None:
            return
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
        site_interfaces = self.createPortChannelInterfaces(site_interfaces)
        # self.logger.info("Site Interfaces After Port Channel Creation:\n")
        # for iface, iface_details in site_interfaces.items():
        #     self.logger.info({}: iface_details["neighbor"])
        tmp_site_interfaces = site_interfaces.copy()
        for iface, iface_details in tmp_site_interfaces.items():
            rtr = iface_details["neighbor router"]
            for service in rtr.site.services:
                if "{}.{}".format(iface, service["subinterface vlan"]) not in site_interfaces.keys():
                    #If CE site requires peering on SVI
                    self.logger.info("{} ---- {}".format(rtr.site.name, list(sites_peering_on_svis.keys())))
                    if sites_peering_on_svis.get(rtr.site.name) is not None and sites_peering_on_svis[ rtr.site.name ]["core_routers"][ self.hostname ][ "services" ].get(service["vrf"]) is not None:
                        subinterface_vlan_tag = sites_peering_on_svis[ rtr.site.name ]["core_routers"][ self.hostname ]["services"][ service["vrf"] ]["subinterface_vlan_tag"]
                        site_interfaces[ "{}.{}".format(iface, service["subinterface vlan"]) ] = {
                                "neighbor router": rtr,
                                "neighbor interface": "{}.{}".format(iface_details["neighbor interface"], subinterface_vlan_tag),
                                # "neighbor interface": "{}.{}".format(neighbor["neighborPort"], subinterface_vlan),
                                "ip address": None,
                                "neighbor ip address": None,
                                "vlan":  subinterface_vlan_tag,
                                "vrf": service["vrf"],
                                "subnet": service["subinterface subnet"]
                            }
                        self.logger.info("Added {} to site_interfaces".format("{}.{}".format(iface, service["subinterface vlan"])))
                        self.logger.info("Neighbor router is {}".format(rtr.hostname))
                    #If CE site peering will be done on subinterfaces (This is the standard)
                    else:
                        site_interfaces["{}.{}".format(iface, service["subinterface vlan"])] = {
                                "neighbor router": rtr,
                                "neighbor interface": "{}.{}".format(iface_details["neighbor interface"], service["subinterface vlan"]),
                                # "neighbor interface": "{}.{}".format(neighbor["neighborPort"], service["subinterface vlan"]),
                                "ip address": None,
                                "neighbor ip address": None,
                                "vlan":  service["subinterface vlan"],
                                "vrf": service["vrf"],
                                "subnet": service["subinterface subnet"]
                            }
                        self.logger.info("Added {} to site_interfaces".format("{}.{}".format(iface, service["subinterface vlan"])))
                        self.logger.info("Neighbor router is {}".format(rtr.hostname))

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
            local_interface_ip = get_transit_ip_from_ipam(ipam, ipam_network, details["subnet"], connection_info, subnet_mask=30)
            site_interfaces[interface]["ip address"] = local_interface_ip
            neighbor_connection_info = {
                "hostname": details["neighbor router"].hostname,
                "local interface": details["neighbor interface"],
                "neighbor hostname": self.hostname,
                "neighbor interface": interface
            }
            neighbor_interface_ip = get_transit_ip_from_ipam(ipam, ipam_network, details["subnet"], neighbor_connection_info, subnet_mask=30)
            site_interfaces[interface]["neighbor ip address"] = neighbor_interface_ip

        # self.logger.debug(site_interfaces)
        self.logger.debug("Setting site_interfaces for {}".format(self.hostname))
        self.site_interfaces = site_interfaces

    def getLLDPNeighbors(self):
        self.logger.debug("Retrieving LLDP neighbors for {}".format(self.hostname))
        return self.send_commands_via_eapi(["show lldp neighbors"])[0]["lldpNeighbors"]

    def createPortChannelInterfaces(self, site_interfaces):
        """If there are duplicate connections to the samee CE router, this script will make those connections a port channel,

        Args:
            site_interfaces ({}]): {
                local interface: {
                            "neighbor router": rtr,
                            "neighbor interface": neighbor["neighborPort"],
                            "ip address": None,
                            "neighbor ip address": None,
                            "subnet": None,
                          **"vlan":  service["subinterface vlan"],
                          **"vrf": service["vrf"],
                          **"subnet": service["subinterface subnet"]
                        }
                    }
        """
        port_channel_id = 300
        ce_port_channels = {} 
        interfaces_already_in_port_channels = []
        """
            port_channel_id : {
                "neighbor router": rtr,
                "neighbor interfaces": [ neighbor["neighborPort"] ],
                "member interfaces" : [ Ethernet12, ... ]
                "ip address": None,
                "neighbor ip address": None,
                "subnet": None,
                **"vlan":  service["subinterface vlan"],
                **"vrf": service["vrf"],
                **"subnet": service["subinterface subnet"]
            }
        """
        #get port-channels already configured on device
        try:
            port_channels_allocated = self.send_commands_via_eapi(["show interfaces Port-Channel 1-$"])[0]["interfaces"]
        except:
            port_channels_allocated = {}
        #Check to see out of the already configured port-channels if any of the site interfaces are members
        for pc, pc_details in port_channels_allocated.items():
            for iface in pc_details["memberInterfaces"].keys():
                if iface in site_interfaces.keys():
                    if pc not in ce_port_channels:
                        ce_port_channels[pc] = {
                            "neighbor router": site_interfaces[iface]["neighbor router"],
                            "neighbor interface": pc,
                            "member interfaces" : [iface],
                            "ip address": None,
                            "neighbor ip address": None,
                            "subnet": None,
                        }
                    else:
                        ce_port_channels[pc]["member interfaces"].append(iface)
                    interfaces_already_in_port_channels.append(iface)

        # Create more port-channels for remaining site interfaces
        for site_interface_1, iface_details_1 in site_interfaces.items():
            while "Port-Channel{}".format(port_channel_id) in ce_port_channels.keys() or "Port-Channel{}".format(port_channel_id) in port_channels_allocated.keys():
                port_channel_id += 1
            for site_interface_2, iface_details_2 in site_interfaces.items():
                #Make sure you are comparing different interfacea (i.e. [Ethernet13 and Ethernet14] and not [Ethernet13 and Ethernet13)
                if site_interface_1 == site_interface_2 or (site_interface_1 in interfaces_already_in_port_channels and site_interface_2 in interfaces_already_in_port_channels):
                    continue
                #If the same type of interface has the same neighbor router
                if iface_details_1["neighbor router"] == iface_details_2["neighbor router"]:
                    self.logger.debug("{} and {} have the same LLDP neighbor, {}".format(site_interface_1, site_interface_2, iface_details_1["neighbor router"].hostname))
                    
                    interface_already_in_port_channel = False
                    for pc, pc_info in ce_port_channels.items():
                        if site_interface_1 in pc_info["member interfaces"]:
                            ce_port_channels[pc]["member interfaces"].append(site_interface_2)
                            interfaces_already_in_port_channels.append(site_interface_2)
                            interface_already_in_port_channel = True
                            break
                        elif site_interface_2 in pc_info["member interfaces"]:
                            ce_port_channels[pc]["member interfaces"].append(site_interface_1)
                            interfaces_already_in_port_channels.append(site_interface_1)
                            interface_already_in_port_channel = True
                            break
                    if interface_already_in_port_channel == True:
                        continue

                    ce_port_channels["Port-Channel{}".format(port_channel_id)] = {
                        "neighbor router": iface_details_1["neighbor router"],
                        "neighbor interface": "Port-Channel{}".format(port_channel_id),
                        "member interfaces" : [site_interface_1, site_interface_2],
                        "ip address": None,
                        "neighbor ip address": None,
                        "subnet": None,
                    }
                    interfaces_already_in_port_channels.append(site_interface_1)
                    interfaces_already_in_port_channels.append(site_interface_2)

            if site_interface_1 not in interfaces_already_in_port_channels:
                ce_port_channels["Port-Channel{}".format(port_channel_id)] = {
                    "neighbor router": iface_details_1["neighbor router"],
                    "neighbor interface": "Port-Channel{}".format(port_channel_id),
                    "member interfaces" : [site_interface_1],
                    "ip address": None,
                    "neighbor ip address": None,
                    "subnet": None,
                }
                interfaces_already_in_port_channels.append(site_interface_1)

        #Delete member interfaces from site_interfaces:
        interfaces_already_in_port_channels = list(set(interfaces_already_in_port_channels))

        # self.logger.debug("Interfaces already in Port-Channels: {}".format(interfaces_already_in_port_channels))
        # self.logger.debug(site_interfaces)
        # for iface in interfaces_already_in_port_channels:
        #     del site_interfaces[iface]
        # self.logger.debug(site_interfaces)
        # self.logger.debug(ce_port_channels)
        # print("\n\n\n")
        # print(site_interfaces)
        # print("\n\n\n")
        return ce_port_channels

    def produceManagementConfig(self):
        #Load default values
        mgmt_values = yaml.load(open("{}/settings/config_defaults/management.yml".format(path)), Loader=yaml.FullLoader)

        #Format variables for templates
        mgmt_vrf = mgmt_values["vrf_name"]
        mgmt_interface = mgmt_values["interface"]
        include_terminattr = mgmt_values["include_terminattr"]
        cvp_ips = mgmt_values["cvp"]["node_ips"]
        ingestauth_key = mgmt_values["cvp"]["ingest_auth_key"] if mgmt_values["cvp"]["ingest_auth_key"] is not None else ""
        data = {
            "hostname": self.hostname,
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
            }
        }
        if mgmt_vrf != "default":
            data["vrfs"] = {
                mgmt_vrf:{
                    "description": mgmt_values["vrf_description"],
                    "ip_routing": False
                }
            }
        if self.mgmt_gateway is not None and self.mgmt_gateway.strip() != "":
            data["static_routes"] = [
                {
                    "vrf": mgmt_vrf,
                    "destination_address_prefix": "0.0.0.0/0",
                    "gateway": self.mgmt_gateway
                }
            ]
        if include_terminattr == True:
            data["daemon_terminattr"] = {
                "ingestgrpcurl":{
                    "ips": cvp_ips,
                    "port": "9910"
                },
                "ingestauth_key": ingestauth_key,
                "smashexcludes": "ale,flexCounter,hardware,kni,pulse,strata",
                "ingestexclude": "/Sysdb/cell/1/agent,/Sysdb/cell/2/agent",
                "ingestvrf": mgmt_vrf,
                "cvsourceip": self.ip_address.split("/")[0]
            }
        template = env.get_template('management-configlet.j2')
        rendered_config = template.render(data)
        self.logger.info("Rendered management config for {}".format(self.hostname))
        return formatConfig(rendered_config)

    def produceCoreFabricConfig(self, services, routing_details):
        #Load default values
        bgp_values = yaml.load(open("{}/settings/config_defaults/bgp.yml".format(path)), Loader=yaml.FullLoader)
        mcast_values = yaml.load(open("{}/settings/config_defaults/mcast.yml".format(path)), Loader=yaml.FullLoader)
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
                "description": "to {} : {}".format(details["neighbor hostname"], details["neighbor interface"]),
                "type": "routed",
                "ip_address": details["ip address"],
                "mtu": 9214,
                "logging":{
                    "event": {
                        "link_status": True
                    }
                }
            }
            if mcast_values["multicast"] == True:
                ethernet_interfaces[iface]["igmp_static_groups"] = mcast_values["igmp_static_groups"]
                ethernet_interfaces[iface]["pim"] = {
                    "ipv4": {
                        "sparse_mode": True
                    }
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
            if service["vrf"] != "default":
                vxlan_interface["Vxlan1"]["vxlan_vni_mappings"]["vrfs"][service["vrf"]] = {
                    "vni": service["vni"]
                }

        #Format Prefix lists
        prefix_lists = {
             bgp_values["prefix_list_names"]["loopbacks_pl_name"]:{
                "sequence_numbers":{
                    10: {
                        "action": "permit {} eq 32".format(routing_details["loopback0 subnet"])
                    },
                    20: {
                        "action": "permit {} eq 32".format(routing_details["loopback1 subnet"])
                    },
                    #Advertise Management Subnet if using inband management
                    30: {
                        "action": "permit {} eq 32".format(routing_details["oob management subnet"])
                    },
                    40: {
                        "action": "permit {} eq 32".format(routing_details["ib management subnet"])
                    }
                }
            },
            bgp_values["prefix_list_names"]["transit_pl_name"]:{
                "sequence_numbers":{
                    10: {
                        "action": "permit {} le 31".format(routing_details["core to core subnet"])
                    }
                }
            }
        }

        for i, service in enumerate(services):
            prefix_lists[bgp_values["prefix_list_names"]["transit_pl_name"]]["sequence_numbers"][(i + 2) * 10] = {
                        "action": "permit {} le 31".format(service["subinterface subnet"]) 
                    }

        if mcast_values["multicast"] == True:
            for pl_name, pl_info in mcast_values["prefix_lists"].items():
                prefix_lists[pl_name] = pl_info

        #Format Route Maps info
        route_maps = {
            bgp_values["core_redistribution_routes"]["connected"]["route_map"]:{
                "sequence_numbers":{
                    10:{
                        "type": "permit",
                        "match": ["ip address prefix-list {}".format(bgp_values["prefix_list_names"]["loopbacks_pl_name"])]
                    },
                    20:{
                        "type": "permit",
                        "match": ["ip address prefix-list {}".format(bgp_values["prefix_list_names"]["transit_pl_name"])]
                    }
                }
            }
        }
        if mcast_values["multicast"] == True:
            for rm_name, rm_info in mcast_values["route_maps"].items():
                route_maps[rm_name] = rm_info

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
            if service["vrf"] != "default":
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

        if mcast_values["multicast"] == True:
            router_multicast = mcast_values["router_multicast"]
            router_pim_sparse_mode = mcast_values["router_pim_sparse_mode"]
        else:
            router_multicast = None
            router_pim_sparse_mode = None

        data = {
            "service_routing_protocols_model": "multi-agent",
            "vrfs": vrfs,
            "ethernet_interfaces": ethernet_interfaces,
            "loopback_interfaces": loopback_interfaces,
            "vxlan_tunnel_interface": vxlan_interface,
            "ip_routing": True,
            "prefix_lists": prefix_lists,
            "route_maps": route_maps,
            "router_bgp": router_bgp,
            "router_multicast": router_multicast,
            "router_pim_sparse_mode": router_pim_sparse_mode
        }
        template = env.get_template('core-fabric-configlet.j2')
        rendered_config = template.render(data)
        self.logger.info("Rendered core-to-core config for {}".format(self.hostname))
        return formatConfig(rendered_config)
    
    def produceCoreToSiteConfig(self):
        #Load default values
        bgp_values = yaml.load(open("{}/settings/config_defaults/bgp.yml".format(path)), Loader=yaml.FullLoader)
        mcast_values = yaml.load(open("{}/settings/config_defaults/mcast.yml".format(path)), Loader=yaml.FullLoader)

        #Format variables for templates
        ethernet_interfaces = {}
        port_channel_interfaces = {}
        for iface, details in self.site_interfaces.items():
            if "Ethernet" in iface:
                ethernet_interfaces[iface] = {
                    "description": "to {} : {}".format(details["neighbor router"].hostname, details["neighbor interface"]),
                    "type": "routed",
                    "mtu": 9214,
                    "logging":{
                        "event": {
                            "link_status": True
                        }
                    }
                }
                if "." in iface:
                    ethernet_interfaces[iface]["type"] = "subinterface"
                    ethernet_interfaces[iface]["vrf"] = details["vrf"]
                    ethernet_interfaces[iface]["vlans"] = details["vlan"]
                    ethernet_interfaces[iface]["ip_address"] = details["ip address"]
                    if mcast_values["multicast"] == True:
                        ethernet_interfaces[iface]["igmp_version"] = mcast_values["igmp_version"]
                        ethernet_interfaces[iface]["igmp_static_groups"] = mcast_values["igmp_static_groups"]
                        ethernet_interfaces[iface]["pim"] = {
                            "ipv4": {
                                "sparse_mode": True,
                                "dr_priority": 100
                            }
                        }
            elif "Port-Channel" in iface:
                port_channel_interfaces[iface] = {
                    "description": "to {} : {}".format(details["neighbor router"].hostname, details["neighbor interface"]),
                    "type": "routed",
                    "mtu": 9214,
                    "logging":{
                        "event": {
                            "link_status": True
                        }
                    }
                }
                if "." in iface:
                    port_channel_interfaces[iface]["type"] = "subinterface"
                    port_channel_interfaces[iface]["vrf"] = details["vrf"]
                    port_channel_interfaces[iface]["vlans"] = details["vlan"]
                    port_channel_interfaces[iface]["ip_address"] = details["ip address"]
                if mcast_values["multicast"] == True:
                    port_channel_interfaces[iface]["igmp_version"] = mcast_values["igmp_version"]
                    port_channel_interfaces[iface]["igmp_static_groups"] = mcast_values["igmp_static_groups"]
                    port_channel_interfaces[iface]["pim"] = {
                        "ipv4": {
                            "sparse_mode": True,
                            "dr_priority": 100
                        }
                    }
                if "member interfaces" in details.keys():
                    for member in details["member interfaces"]:
                        ethernet_interfaces[member] = {
                            "description": "to {}".format(details["neighbor router"].hostname),
                            "type": "routed",
                            "mtu": 9214,
                            "channel_group": {
                                "id": re.match(r'Port-Channel(\d+)', iface).group(1),
                                "mode": "active"
                            },
                            "logging":{
                                "event": {
                                    "link_status": True
                                }
                            }
                        }

        #Format BGP & VRF variables 
        router_bgp = {
            "as": self.asn,
            "neighbors": {},
            "vrfs": {}
        }
        for interface, details in self.site_interfaces.items():
            if details["neighbor ip address"] is not None:
                if "vrf" not in details.keys():
                    router_bgp["neighbors"][details["neighbor ip address"].split("/")[0]] = {
                        "remote_as": details["neighbor router"].site.asn,
                        "peer_group": bgp_values["core_to_site_peer_group"],
                        "description": "{}".format(details["neighbor router"].hostname)
                    }
                else:
                    #If no service vrf exists in routger_bgp["vrfs"] details yet create one
                    if details["vrf"] not in list(router_bgp["vrfs"].keys()):
                        router_bgp["vrfs"][ details["vrf"] ] = {
                            "route_targets": {},
                            "neighbors": {},
                            "ip_routing": True
                        }
                    router_bgp["vrfs"][ details["vrf"] ]["neighbors"][details["neighbor ip address"].split("/")[0]] = {
                        "remote_as": details["neighbor router"].site.asn,
                        "peer_group": bgp_values["core_to_site_peer_group"],
                        "description": "{}".format(details["neighbor router"].hostname),
                        #Max routes for service VRF neighbors
                        "maximum_routes": bgp_values["service_vrfs"]["maximum_routes"],
                        "maximum_routes_warning_limit": bgp_values["service_vrfs"]["maximum_routes_warning_limit"]
                    }
                    if details["vrf"] == "default":
                        router_bgp["vrfs"][ details["vrf"] ]["neighbors"][details["neighbor ip address"].split("/")[0]]["route_map_out"] = list(mcast_values["route_maps"].keys())[0]
                    else:
                        router_bgp["vrfs"][ details["vrf"] ]["neighbors"][details["neighbor ip address"].split("/")[0]]["route_map_out"] = list(mcast_values["route_maps"].keys())[1]
        data = {
            "ip_routing": True,
            "vrfs": router_bgp["vrfs"],
            "ethernet_interfaces": ethernet_interfaces,
            "port_channel_interfaces": port_channel_interfaces,
            "router_bgp": router_bgp
        }
        template = env.get_template('core-to-site-configlet.j2')
        rendered_config = template.render(data)
        self.logger.info("Rendered core-to-site config for {}".format(self.hostname))
        return formatConfig(rendered_config)

def get_transit_ip_from_ipam(ipam_client, view, transit_block, connection, subnet_mask=31):
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
    logger.debug("Getting IP address from {} network container for {}:{}".format(transit_block, connection["hostname"], connection["local interface"]))
    child_subnet_re = "{}:{}".format(connection["hostname"], connection["local interface"]) #endpointA:interfaceA
    child_subnet_re = child_subnet_re.replace("-", "_") #CVP IPAM converts "-" to "_"
    allocation_name = child_subnet_re
    #Check to see if child subnet exists
    subnets = ipam_client.find_subnetworks_by_regex(view, transit_block, child_subnet_re)
    if len(subnets) > 0:
        if len(subnets) != 1:
            logger.warning("Multiple subnets found for regex '{}' in network container {}".format(allocation_name, transit_block))
            #Search for endpointB:interfaceB
            secondary_re = "{}:{}".format(connection["neighbor hostname"], connection["neighbor interface"]) #endpointA:interfaceA
            secondary_re = secondary_re.replace("-", "_") #CVP IPAM converts "-" to "_"
            secondary_subnets = ipam_client.find_subnetworks_by_regex(view, transit_block, secondary_re)
            if len(secondary_subnets) > 0:
                for sec_sub in secondary_subnets:
                    if sec_sub in subnets:
                        subnets = [ sec_sub ]
                        break
        else:
            logger.debug("Found existing subnet {} from network container {} for {}".format(subnets[0], transit_block, allocation_name))
        subnet = subnets[0]
        #Check to see if address exists
        ip_address = ipam_client.get_host_ipv4_address(view, subnet, allocation_name)
        if ip_address is not None:
            logger.debug("Found existing IP address ({}) for {} in {}".format(ip_address, allocation_name, subnet))
            return ip_address + "/" + str(subnet_mask)
    else:
        #Create child_subnet name
        logger.debug("Could not find an existing subnet from network container {} for {}".format(transit_block, allocation_name))
        child_subnet_name = "{}:{}::{}:{}".format(connection["hostname"], connection["local interface"], connection["neighbor hostname"], connection["neighbor interface"]) #endpointA:interfaceA::endpointB:interfaceB
        child_subnet_name = child_subnet_name.replace("-", "_") #CVP IPAM converts "-" to "_"
        #Create new child subnet
        subnet = ipam_client.allocate_child_subnet(view, transit_block, child_subnet_name, subnet_mask)
        logger.debug("Created subnet {} from {} for {}".format(subnet, transit_block, allocation_name))

    #Allocate next available IP address for connection-interface on that subnet
    logger.debug("Allocating IP Address for {} from {}".format(allocation_name, subnet))
    next_allocation = ipam_client.allocate_next_ip(view, subnet, allocation_name)
    logger.debug("Allocated {} for {} in subnet {}".format(next_allocation, allocation_name, subnet))

    return ipam_client.get_host_ipv4_address(view, subnet, allocation_name) + "/" +str(subnet_mask)

def get_loopback_ip_from_ipam(ipam_client, view, loopback_range, hostname):
    '''
    Gets the Loopback IP address from CVP IPAM for a device's Loopback interface based on the loopback range.
    If the IP Address for the Device's Loopback Interface does not exist in IPAM, it gets the next available from the loopback range

    view: CVP IPAM network 
    loopback_range: cidr notation
    hostname: hostname of switch
    '''
    logger.debug("Getting IP address from {} network for {}".format(loopback_range, hostname))
    #Check to see if host already has an IP address assigned to loopback
    ip_address = ipam_client.get_host_ipv4_address(view, loopback_range, hostname)
    if ip_address is not None:
        logger.debug("Found existing IP address ({}) for {} in {}".format(ip_address, hostname, loopback_range))
        return ip_address + "/32"
    #Allocate next available IP address for connection-interface on that subnet
    logger.debug("Allocating IP Address for {} from {}".format(hostname, loopback_range))
    next_allocation = ipam_client.allocate_next_ip(view, loopback_range, hostname)
    logger.debug("Allocated {} for {} in subnet {}".format(next_allocation, hostname, loopback_range))
    return ipam_client.get_host_ipv4_address(view, loopback_range, hostname) + "/32"

def get_management_address_from_ipam(ipam_client, view, management_range, hostname):
    '''
    Gets the Management IP address from CVP IPAM for a device's Management interface based on the management range.
    If the IP Address for the Device's Management Interface does not exist in IPAM, it gets the next available from the management range

        ipam_client (ipam): CVP IPAM client or Infoblox IPAM
        view (str): CVP IPAM network 
        management_range (str): cidr notation
        hostname (str): hostname of switch
    '''
    netmask = management_range.split("/")[-1]
    #Check to see if host already has an IP address assigned to
    ip_address = ipam_client.get_host_ipv4_address(view, management_range, hostname)
    if ip_address is not None:
        logger.debug("Found existing IP Address for {}".format(hostname))
        return "{}/{}".format(ip_address, netmask)
    #Allocate next available IP address for connection-interface on that subnet
    logger.debug("Could not find an existing IP Address for {}".format(hostname))
    next_allocation = ipam_client.allocate_next_ip(view, management_range, hostname)
    logger.debug("Allocated new IP address ({}) for {} from {}".format(next_allocation, hostname, management_range))

    return "{}/{}".format(ipam_client.get_host_ipv4_address(view, management_range, hostname), netmask)

def get_management_gateway(ipam_client, view, management_range):
    '''
    Gets the Management gateway IP from management subnet

        ipam_client (ipam): CVP IPAM client
        view (str): CVP IPAM network 
        management_range (str): cidr notation
    '''
    logger.debug("Retrieving default gateway for {}".format(management_range))
    gateway = ipam_client.get_network_gateway(view, management_range)
    return gateway

def get_asn_from_ipam(cvp_ipam_client, view, asn_start, asn_end, hostname):
    """[summary]

    Args:
        ipam_client (ipam): CVP IPAM client - Only takes CVP IPAM client
        view (str): CVP IPAM network 
        asn_range (str): asn range to get allocations from
        hostname (str): hostname of switch
    """
    logger.debug("Getting BGP ASN for {}".format(hostname))
    #Make sure IPAM client is CVP IPAM type
    if type(cvp_ipam_client) is not CvpIpam:
        return None

    #Find reservation by asn range
    reservation = None
    reservations = cvp_ipam_client.get_asn_reservations(view)
    for rezzy in reservations:
        if rezzy["start"] == asn_start and rezzy["end"] == asn_end:
            reservation = rezzy
            break
    #If ASN range doesn't exist return None
    if reservation is None:
        logger.error("Could not find an ASN range for {} in IPAM".format(hostname))
        return None
    logger.debug("Retrieved ASN reservation for {}".format(hostname))
    #For allocation in allocations
    for allocation in reservation["allocations"]:
        #If the hostname is found in the description of the allocation within the reservation
        if hostname in [ x.strip() for x in allocation["description"].split(":") ]:
            #Return the ASN value
            logger.debug("Found existing allocation (AS {}) for {}".format(allocation["value"], hostname))
            return allocation["value"]
    #Allocate the next available asn_value
    logger.debug("Allocating next available ASN from {}".format(reservation["id"]))
    response = cvp_ipam_client._get_next_allocation(reservation["id"], hostname)
    logger.debug("Allocated AS {} for {}".format(response['allocation']['value'], hostname))
    return response['allocation']['value']

def formatConfig(config):
    return "\n".join([line for line in config.split("\n") if line.strip() != ""])