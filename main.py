import json, yaml, os, glob
from cvprac.cvp_client import CvpClient
from cvprac.cvp_client_errors import CvpClientError
from parsers.Core import parseCoreConnections, parseRoutingDetails
from parsers.Services import parseServices
from parsers.Sites import parseSites, parseSiteRouters
from ipam_client.ipam import ipam
from switch import CoreRouter
from sites import Site, SiteRouter
from datetime import datetime

import logging
logging.basicConfig(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler = logging.FileHandler('Deployment.log', mode='w+')
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)

username, password = None, None

def getTestRouter():
    global username, password
    return CoreRouter(hostname="DC2-LF09", username=username, password=password)

def printConfiglet(configlet_dictionary):
    print("_"*50)
    print(configlet_dictionary["name"])
    print("-"*50)
    print(configlet_dictionary["config"])
    print("-"*50, "\n")

def getCoreRouterInfoFromCVP(cvp, core_rtrs):
    cvp_core_rtr_info = {}
    devices = cvp.api.get_inventory()
    for device in devices:
        for core_rtr in core_rtrs:
            if device["hostname"] == core_rtr.hostname:
                cvp_core_rtr_info[device["hostname"]] = device
    return cvp_core_rtr_info

def updateConfigletInCVP(cvp, configlet_name, config, core_rtr=None):
    """[summary]

    Args:
        cvp (CvpClient): CVP API client
        configlet_name (str): configlet name
        config (str): configuration for configlet
        core_rtr (CoreRouter): Core Router object which will be used to merge configs if an existing configlet exists
    
    Returns: The configlet object from CVP
    """
    try:
        configlet = cvp.api.get_configlet_by_name(configlet_name)
    except CvpClientError as e:
        configlet = None
    if configlet is not None:
        #Merge configlets
        existing_config = configlet["config"]
        if core_rtr is not None:
            try:
                config = core_rtr.mergeConfigs([existing_config, config])
            except:
                print("Error merging configuration for {}".format(configlet_name))
                return
        try:
            update_status = cvp.api.update_configlet(config, configlet["key"], configlet_name)
        except CvpClientError as e:
            print(e)
            return
    else:
        try:
            configlet_key = cvp.api.add_configlet(configlet_name, config)
        except CvpClientError as e:
            print(e)
            return

    return cvp.api.get_configlet_by_name(configlet_name)

def configureDeviceWithCVP(cvp, device_info, configlets_to_apply, apply=False, container=None):
    """[summary]

    Args:
        cvp (CvpClient): [description]
        device_info ({}): response from CVP for get_inventory()/get_device_by_hostname(<hostname>)
        configlets_to_apply ([ {"name": str, "config":str } ]): list of configlet info dictionaries to apply to switch
        container (str, optional): name of container in CVP to move container to. Defaults to None.

    Returns: list of task Ids if there are any else None
    """
    global username, password
    core_rtr = CoreRouter(ip_address=device_info["ipAddress"], username=username, password=password) if device_info is not None else None
    updated_configlets = []
    for configlet in configlets_to_apply:
        updated_configlet = updateConfigletInCVP(cvp, configlet["name"], configlet["config"], core_rtr=core_rtr)
        if updated_configlet is not None:
            updated_configlets.append(updated_configlet)
        else:
            print("Error updating {} in CVP".format(configlet["name"]))
    
    if apply == True:
        if device_info is None:
            print("Unable to find {} in CVP inventory".format(device.hostname))
            return
        if container is not None:
            resp = cvp.api.deploy_device(device_info, container, configlets_to_apply=updated_configlets)
        else:
            resp = cvp.api.apply_configlets_to_device("Applied via API", device_info, updated_configlets)
        
        if "taskIds" in resp["data"].keys():
            return resp["data"]["taskIds"]

def getServices(workbook):
    return parseServices(workbook)

def getSites(workbook):
    sites = []
    services = getServices(workbook)
    sites_info = parseSites(workbook)
    for info in sites_info:
        services_to_add_to_site = []
        for service in services:
            if service["vrf"] in info["Services"]:
                services_to_add_to_site.append(service)

        site = Site(info["Name"], services_to_add_to_site, asn=info["ASN"])
        sites.append(site)

    return sites

def getSiteRouters(workbook):
    site_routers = []
    sites = getSites(workbook)
    site_rtrs = parseSiteRouters(workbook)
    for rtr in site_rtrs:
        found_site = False
        for site in sites:
            if rtr["Site"] == site.name:
                site_routers.append(SiteRouter(rtr["Name"], site))
                found_site = True
                break
        if found_site == False:
            print("Could not find a {} in sites for {}".format(rtr["Site"], rtr["Name"]))
    return site_routers

def getCoreRouters(workbook, ipam, ipam_network):
    global username, password
    core_routers = []
    #Get all connections between WAN Core routers
    wan_core_connections = parseCoreConnections(workbook)  
    routing_details = parseRoutingDetails(workbook)

    #Parse From Spreadsheet
    # for hostname in wan_core_connections.keys():
    #     rtr = CoreRouter(hostname=hostname, username=username, password=password)
    #     rtr.getManagementInfo(routing_details["management subnet"])
    #     rtr.core_interfaces = wan_core_connections[hostname]
    #     rtr.getAddressesForCoreFabric(routing_details, ipam, ipam_network)
    #     core_routers.append(rtr)

    #Get Info From LLDP Neighbors
    hostnames = list(wan_core_connections.keys())
    for hostname in hostnames:
        rtr = CoreRouter(hostname=hostname, username=username, password=password)
        rtr.getManagementInfo(routing_details, ipam, ipam_network)        
        core_routers.append(rtr)

    #Update BGP Neighbor Info
    for rtr in core_routers:
        rtr.getCoreInterfaces(core_routers)
        rtr.getAddressesForCoreFabric(routing_details, ipam, ipam_network)
        
    for rtr in core_routers:
        rtr.getCoreBGPNeighborInfo(core_routers)

    return core_routers

def configureCoreFabric(core_rtrs, services, cvp_client=None):
    #Get Core Router Device Dictionary from CVP 
    if cvp_client is not None:
        cvp_core_rtr_info = getCoreRouterInfoFromCVP(cvp_client, core_rtrs)

    #Create configuration for WAN Core 
    for rtr in core_rtrs:
        #Create list of configlets to apply
        configlets_to_apply = []

        #Create management configuration
        mgmt_config = rtr.produceManagementConfig()
        configlets_to_apply.append({
            "name": "{} Management".format(rtr.hostname),
            "config": mgmt_config
            })
        #Create Core Fabric Config
        core_config = rtr.produceCoreFabricConfig(services)
        configlets_to_apply.append({
            "name": "{} Core".format(rtr.hostname),
            "config": core_config
            })

        # Create/Update Configlets in CVP, Apply to Device, and Move device to proper container if necessary
        if cvp_client is not None:
            device_dict = None if rtr.hostname not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.hostname]
            device_dict = {"ipAddress": rtr.ip_address}
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=False, container=None)

        #Print configlets
        for configlet in configlets_to_apply:
            printConfiglet(configlet)

    return
 
def addServices(core_rtrs, services, cvp_client=None):
    #Get Core Router Device Dictionary from CVP 
    if cvp_client is not None:
        cvp_core_rtr_info = getCoreRouterInfoFromCVP(cvp_client, core_rtrs)

    #Update Core Fabric Config
    for rtr in core_rtrs:
        #Create list of configlets to apply
        configlets_to_apply = []

        #Add Service to Core Fabric Config
        core_config = rtr.produceCoreFabricConfig(services)
        configlets_to_apply.append({
            "name": "{} Core".format(rtr.hostname),
            "config": core_config
            })

        # Create/Update Configlets in CVP, Apply to Device, and Move device to proper container if necessary
        if cvp_client is not None:
            device_dict = None if rtr.hostname not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.hostname]
            device_dict = {"ipAddress": rtr.ip_address}
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=False, container=None) 

        #Print Configlets
        # for configlet in configlets_to_apply:
        #     printConfiglet(configlet)

    return

def addSiteRouterConnections(core_rtrs, site_rtrs, ipam, ipam_network, cvp_client=None):
    #Get Core Router Device Dictionary from CVP 
    if cvp_client is not None:
        cvp_core_rtr_info = getCoreRouterInfoFromCVP(cvp_client, core_rtrs)

    #Create configuration for Site  neighbors
    for rtr in core_rtrs:
        #Get site_interface info
        rtr.getSiteInterfaces(site_rtrs, ipam, ipam_network)

        #Create list of configlets to apply
        configlets_to_apply = []

        #Create Core Fabric Config
        site_config = rtr.produceCoreToSiteConfig()
        configlets_to_apply.append({
            "name": "{} Sites".format(rtr.hostname),
            "config": site_config
            })

        # Create/Update Configlets in CVP, Apply to Device, and Move device to proper container if necessary
        if cvp_client is not None:
            device_dict = None if rtr.hostname not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.hostname]
            device_dict = {"ipAddress": rtr.ip_address}
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=False, container=None) 

        #Print Configlets
        # for configlet in configlets_to_apply:
        #     printConfiglet(configlet)
    return

def addServicesToSite(core_rtrs, site_rtrs, ipam, ipam_network, cvp_client=None):
    return addSiteRouterConnections(core_rtrs, site_rtrs, ipam, ipam_network, cvp_client=cvp_client)

def main():
    #Parse CVP details
    yaml_parsed = yaml.load(open("settings/cvp_info.yml"), Loader=yaml.FullLoader)
    cvp_nodes = [node for node in [ yaml_parsed['primary'], yaml_parsed['secondary'], yaml_parsed['tertiary'] ] if node is not None ]

    #Parse IPAM details
    yaml_parsed = yaml.load(open("settings/ipam_info.yml"), Loader=yaml.FullLoader)
    ipam_address = yaml_parsed["ip_address"]
    ipam_type = yaml_parsed["type"]
    ipam_network = yaml_parsed["network"]

    #Get source of information
    workbook = "./MSK WAN Core.xlsx"
    #Get Services and Site Routers that the Core Routers are connected to
    services = getServices(workbook)
    site_rtrs = getSiteRouters(workbook)

    #Get credentials for CVP
    global username, password
    username, password = "cvpadmin", "nynjlab"

    #Create CVP client
    cvp = CvpClient()
    cvp.connect(cvp_nodes, username, password)
    
    #Create IPAM client and define IPAM network
    ipam_username, ipam_password = username, password
    cvp_ipam = ipam(ipam_type)
    cvp_ipam.login(ipam_address, ipam_username, ipam_password)

    #Get Core Router details
    core_rtrs = getCoreRouters(workbook, cvp_ipam, ipam_network)

    print("GENERATING CORE CONFIGURATIONS...")
    configureCoreFabric(core_rtrs, services, cvp_client=cvp)

    print("GENERATING SITE CONFIGURATIONS...")
    addSiteRouterConnections(core_rtrs, site_rtrs, cvp_ipam, ipam_network, cvp_client=cvp)

    return

# if __name__ == "__main__":
#     main()