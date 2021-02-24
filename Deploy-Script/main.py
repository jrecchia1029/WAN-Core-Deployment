#!/usr/bin/python
import json, yaml, os, glob
from cvprac.cvp_client import CvpClient
from cvprac.cvp_client_errors import CvpClientError
from parsers.Core import parseCoreRouterDetails, parseRoutingDetails
from parsers.Services import parseServices
from parsers.Sites import parseSites, parseSiteRouters
from ipam_client.ipam import ipam
from ipam_client.infoblox import Infoblox
from ipam_client.cvp_ipam import CvpIpam
from switch import CoreRouter
from sites import Site, SiteRouter
from datetime import datetime
import cherrypy
import xlrd, xlwt
import logging

path = os.path.abspath(os.path.dirname(__file__))

# create logger with 'spam_application'
logger = logging.getLogger('main')
logger.setLevel(logging.DEBUG)
# create file handler which logs even debug messages
# fh = logging.FileHandler('{}/logs/Deployment-{}.log'.format(path, int(datetime.now().timestamp())), 'w+')
fh = logging.FileHandler('{}/logs/Deployment.log'.format(path), 'a+')
fh.setLevel(logging.DEBUG)
# create console handler with a higher log level
ch = logging.StreamHandler()
ch.setLevel(logging.ERROR)
# create formatter and add it to the handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
fh.setFormatter(formatter)
ch.setFormatter(formatter)
# add the handlers to the logger
logger.addHandler(fh)
logger.addHandler(ch)

config = {
    'global' : {
        'server.socket_host' : '0.0.0.0',
        'server.socket_port' : 8081,
        'server.thread_pool' : 4,
        'server.ssl_module' : 'builtin'
    },
    '/': {
        'tools.sessions.on': True,
        'tools.staticdir.root': os.path.abspath(os.getcwd())
    },
    '/static': {
        'tools.staticdir.on': True,
        'tools.staticdir.dir': './static'
    }
}

username, password = None, None

class Handler(object):
    @cherrypy.expose
    def index(self):
        f = open("{}/index.html".format(path), "r")
        return f.read()
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def run(self):
        result = {"operation": "request", "result": "success"}
        input_json = cherrypy.request.json
        # print("INPUT JSON")
        # print(json.dumps(input_json, indent=2))
        run_script(**input_json)
        return result
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def log(self):
        log_file = "{}/logs/Deployment.log".format(path)

        f = open(log_file)
        text = f.read()
        f.close()

        return json.dumps(text)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def clearLog(self):
        result = {"operation": "request", "result": "success"}
        log_file = "{}/logs/Deployment.log".format(path)
        with open(log_file, 'w') as filename:
            filename.write("")
        return result

    @cherrypy.expose
    def readfile(self):
        list_of_files = glob.glob('{}/workbooks/workbook*.xls*'.format(path)) # * means all if need specific format then *.csv
        latest_file = max(list_of_files, key=os.path.getctime)

        with xlrd.open_workbook(latest_file) as f:    
            toReturn = {}
            def format(v):
                if type(v) == float:
                    return {'type':'text','title':int(v), 'width':200 }
                else:
                    return {'type':'text','title':v, 'width':200 }

            for n in range(0, f.nsheets):
                _sheet=f.sheet_by_index(n)
                _sheet.cell_value(0,0)
                toReturn[_sheet.name] = {'data':[],'columns':[format(val) for val in _sheet.row_values(0)]}
                for row in range(1, _sheet.nrows):
                    row = _sheet.row_values(row)
                    toReturn[_sheet.name]['data'].append(row)
                
        return json.dumps(toReturn)
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def writefile(self):        
        result = {"operation": "request", "result": "success"}
        wb = xlwt.Workbook()
        input_json = cherrypy.request.json
        for sheet in input_json:
            tab = sheet[0]
            data = sheet[1:]
            
            ws = wb.add_sheet(tab)
            for r, row in enumerate(data):
                for c, v in enumerate(row):
                    ws.write(r,c,v)

        excel_file_name = "{}/workbooks/workbook.{}.xls".format(path, int(datetime.now().timestamp()))
        wb.save(excel_file_name)

        list_of_files = glob.glob('{}/workbooks/workbook.*.xls*'.format(path))
        if len(list_of_files) > 5:
            oldest_file = min(list_of_files, key=os.path.getctime)
            os.remove(oldest_file)

        # Responses are serialized to JSON (because of the json_out decorator)
        return result
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def upload(self, myFile):
        result = {"operation": "request", "result": "success"}

        size = 0
        excel_file_name = "{}/workbooks/workbook.{}.xls".format(path, int(datetime.now().timestamp()))
        f = open(excel_file_name, "wb")
        
        while True:
            data = myFile.file.read(8192)
            f.write(data)
            if not data:
                f.close()
                break

        # Responses are serialized to JSON (because of the json_out decorator)
        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def saveServerInfo(self):        
        result = {"operation": "request", "result": "success"}
        input_json = cherrypy.request.json
        with open("{}/settings/appl_info.yml".format(path), 'w') as filename:
            yaml.dump(input_json, filename)
        return result

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def readServerInfo(self):
        return json.dumps(yaml.load(open("{}/settings/appl_info.yml".format(path)), Loader=yaml.FullLoader))

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def getConfigSettings(self):
        config_settings = {}
        config_settings["bgp"] = yaml.load(open("{}/settings/config_defaults/bgp.yml".format(path)), Loader=yaml.FullLoader)
        config_settings["management"] = yaml.load(open("{}/settings/config_defaults/management.yml".format(path)), Loader=yaml.FullLoader)
        config_settings["mcast"] = yaml.load(open("{}/settings/config_defaults/mcast.yml".format(path)), Loader=yaml.FullLoader)
        config_settings["cvp"] = yaml.load(open("{}/settings/cvp.yml".format(path)), Loader=yaml.FullLoader)
        return json.dumps(config_settings)

    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def saveConfigSettings(self):
        result = {"operation": "request", "result": "success"}
        input_json = cherrypy.request.json
        bgp_config = input_json["bgp"]
        management_config = input_json["management"]
        mcast_config = input_json["mcast"]
        cvp_settings = input_json["cvp"]

        with open("{}/settings/config_defaults/bgp.yml".format(path), 'w') as filename:
            yaml.dump(bgp_config, filename)
        with open("{}/settings/config_defaults/management.yml".format(path), 'w') as filename:
            yaml.dump(management_config, filename)
        with open("{}/settings/config_defaults/mcast.yml".format(path), 'w') as filename:
            yaml.dump(mcast_config, filename)
        with open("{}/settings/cvp.yml".format(path), 'w') as filename:
            yaml.dump(cvp_settings, filename)


        return result
        
        
def printConfiglet(configlet_dictionary):
    print("_"*50)
    print(configlet_dictionary["name"])
    print("-"*50)
    print(configlet_dictionary["config"])
    print("-"*50, "\n")

def create_main_networks_in_infoblox(ib_ipam_client, ib_ipam_view, routing_details):
    ib_types = {
    "oob management subnet":"network",
    "ib management subnet": "network",
    "core to core subnet": "network_container",
    "loopback0 subnet": "network",
    "loopback1 subnet": "network",
    "core asn range": None,
    }
    logger.info("Creating networks if they do not already exist in IPAM")
    for network_name, subnet in routing_details.items():
        if ib_types[network_name] is not None and ib_types[network_name] == "network":
            logger.debug("Creating {} network in Infoblox IPAM".format(network_name))
            ib_ipam_client.create_network(ib_ipam_view, subnet)
        elif ib_types[network_name] is not None and ib_types[network_name] == "network_container":
            logger.debug("Creating {} network container in Infoblox IPAM".format(network_name))
            ib_ipam_client.create_network_container(ib_ipam_view, subnet)

def create_service_subnets_in_infoblox(ib_ipam_client, ib_ipam_view, services):
    logger.info("Creating service network containers if they do not already exist in IPAM")
    for service in services:
        logger.debug("Creating {} subnetwork network container in Infoblox IPAM".format(service["vrf"]))
        ib_ipam_client.create_network_container(ib_ipam_view, service["subinterface subnet"])

def getCoreRouterInfoFromCVP(cvp, core_rtrs):
    cvp_core_rtr_info = {}
    devices = cvp.api.get_inventory()
    for device in devices:
        for core_rtr in core_rtrs:
            if device["serialNumber"] == core_rtr.serial_number:
                cvp_core_rtr_info[device["serialNumber"]] = device
    return cvp_core_rtr_info

def updateConfigletInCVP(cvp, configlet_name, config, core_rtr=None, merge=True):
    """[summary]

    Args:
        cvp (CvpClient): CVP API client
        configlet_name (str): configlet name
        config (str): configuration for configlet
        core_rtr (CoreRouter): Core Router object which will be used to merge configs if an existing configlet exists
    
    Returns: The configlet object from CVP
    """
    logger.info("Updating {} in CVP".format(configlet_name))
    try:
        configlet = cvp.api.get_configlet_by_name(configlet_name)
    except CvpClientError as e:
        configlet = None
    if configlet is not None:
        #Merge configlets
        existing_config = configlet["config"]
        if core_rtr is not None and merge == True:
            try:
                logger.debug("Merging new config with existing configlet")
                config = core_rtr.mergeConfigs([existing_config, config])
                logger.debug("Successfully merged new config with existing configlet for {}".format(configlet_name))
            except:
                logger.debug("Error merging configuration for {}".format(configlet_name))
                return            
        try:
            update_status = cvp.api.update_configlet(config, configlet["key"], configlet_name)
        except CvpClientError as e:
            logger.error(e)
            return
    else:
        try:
            configlet_key = cvp.api.add_configlet(configlet_name, config)
        except CvpClientError as e:
            logger.error(e)
            return
    logger.debug("Successfully updated {} in CVP".format(configlet_name))
    return cvp.api.get_configlet_by_name(configlet_name)

def configureDeviceWithCVP(cvp, device_info, configlets_to_apply, apply=False, container=None, overwrite_configlets=False):
    """[summary]

    Args:
        cvp (CvpClient): [description]
        device_info ({}): response from CVP for get_inventory()/get_device_by_hostname(<hostname>)
        configlets_to_apply ([ {"name": str, "config":str } ]): list of configlet info dictionaries to apply to switch
        container (str, optional): name of container in CVP to move container to. Defaults to None.

    Returns: list of task Ids if there are any else None
    """
    logger.info("Updating config for {} in CVP".format(device_info["hostname"]))
    global username, password
    core_rtr = CoreRouter(ip_address=device_info["ipAddress"], username=username, password=password) if device_info is not None else None
    updated_configlets = []
    for configlet in configlets_to_apply:
        updated_configlet = updateConfigletInCVP(cvp, configlet["name"], configlet["config"], core_rtr=core_rtr, merge=not(overwrite_configlets))
        if updated_configlet is not None:
            updated_configlets.append(updated_configlet)
        else:
            logger.error("Error updating {} in CVP".format(configlet["name"]))
    if apply == True:
        logger.debug("Applying configs")
        if device_info is None:
            logger.error("Unable to find {} in CVP inventory".format(device_info.hostname))
            return
        if container is not None:
            logger.debug("Deploying {}".format(device_info["hostname"]))
            resp = cvp.api.deploy_device(device_info, container, configlets=updated_configlets)
        else:
            logger.debug("Modifying configlets for {}".format(device_info["hostname"]))
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
                site_routers.append(SiteRouter(rtr["Hostname"], site))
                found_site = True
                break
        if found_site == False:
            logger.warning("Could not find a {} in sites for {}".format(rtr["Site"], rtr["Hostname"]))
    return site_routers

def getCoreRouters(workbook, cvp_ipam, cvp_ipam_network, ib_ipam=None, ib_ipam_network=None):
    logger.info("Gettting Core Router details")
    global username, password
    core_routers = []
    #Get all connections between WAN Core routers
    core_rtr_details = parseCoreRouterDetails(workbook)
    routing_details = parseRoutingDetails(workbook)

    #Create Core Router object and Update Management Info
    for hostname, info in core_rtr_details.items():
        rtr = CoreRouter(hostname=hostname, username=username, password=password, serial_number=info["serial number"])
        rtr.getManagementInfo(routing_details, ib_ipam, ib_ipam_network) if ib_ipam and ib_ipam_network is not None else rtr.getManagementInfo(routing_details, cvp_ipam, cvp_ipam_network)
        core_routers.append(rtr)

    #Update BGP Neighbor Info
    logger.info("Retrieving core router fabric details")
    for rtr in core_routers:
        rtr.getCoreInterfaces(core_routers)
        rtr.getAddressesForCoreFabric(routing_details, ib_ipam, ib_ipam_network) if ib_ipam and ib_ipam_network is not None else rtr.getAddressesForCoreFabric(routing_details, cvp_ipam, cvp_ipam_network)    
        rtr.getBGPASN(routing_details, cvp_ipam, cvp_ipam_network)
    for rtr in core_routers:
        rtr.getCoreBGPNeighborInfo(core_routers)
        
    return core_routers

def getCoreRoutersManagement(workbook, cvp_ipam, cvp_ipam_network, ib_ipam=None, ib_ipam_network=None):
    logger.info("Gettting Core Router details")
    global username, password
    core_routers = []
    #Get all connections between WAN Core routers
    core_rtr_details = parseCoreRouterDetails(workbook)
    routing_details = parseRoutingDetails(workbook)

    #Create Core Router object and Update Management Info
    for hostname, info in core_rtr_details.items():
        rtr = CoreRouter(hostname=hostname, username=username, password=password, serial_number=info["serial number"])
        rtr.getManagementInfo(routing_details, ib_ipam, ib_ipam_network) if ib_ipam and ib_ipam_network is not None else rtr.getManagementInfo(routing_details, cvp_ipam, cvp_ipam_network)
        core_routers.append(rtr)
        
    return core_routers

def configureManagementConfig(core_rtrs, cvp_client=None, container=None):
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

        # Create/Update Configlets in CVP, Apply to Device, and Move device to proper container if necessary
        if cvp_client is not None:
            device_dict = None if rtr.serial_number not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.serial_number]
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=True, container=container, overwrite_configlets=True)

def configureCoreFabric(core_rtrs, services, routing_details, cvp_client=None, container=None):
    #Get Core Router Device Dictionary from CVP 
    if cvp_client is not None:
        cvp_core_rtr_info = getCoreRouterInfoFromCVP(cvp_client, core_rtrs)

    #Create configuration for WAN Core 
    for rtr in core_rtrs:
        #Create list of configlets to apply
        configlets_to_apply = []

        #Create Core Fabric Config
        core_config = rtr.produceCoreFabricConfig(services, routing_details)
        configlets_to_apply.append({
            "name": "{} Core".format(rtr.hostname),
            "config": core_config
            })

        # Create/Update Configlets in CVP, Apply to Device, and Move device to proper container if necessary
        if cvp_client is not None:
            device_dict = None if rtr.serial_number not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.serial_number]
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=True, container=container, overwrite_configlets=True)

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
            device_dict = None if rtr.serial_number not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.serial_number]
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=True, container=None, overwrite_configlets=True) 

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
            device_dict = None if rtr.serial_number not in cvp_core_rtr_info.keys() else cvp_core_rtr_info[rtr.serial_number]
            configureDeviceWithCVP(cvp_client, device_dict, configlets_to_apply, apply=True, container=None, overwrite_configlets=True) 

    return

def addServicesToSite(core_rtrs, site_rtrs, ipam, ipam_network, cvp_client=None):
    return addSiteRouterConnections(core_rtrs, site_rtrs, ipam, ipam_network, cvp_client=cvp_client)

def printRouterDetails(core_rtrs, site_rtrs, ipam, ipam_network):
    for rtr in core_rtrs:
        #Get site_interface info
        logger.info("{}".format(str(rtr)))
        logger.info("Core interfaces for {}\n{}\n".format(rtr.hostname, rtr.core_interfaces))
        rtr.getSiteInterfaces(site_rtrs, ipam, ipam_network)
        logger.info("Site interfaces for {}\n{}\n\n".format(rtr.hostname, rtr.site_interfaces))

    return

def run_script(operation=None, cvp_user=None, cvp_pass=None,
                cvp_ipam_user=None, cvp_ipam_pass=None,
                ib_user=None, ib_pass=None):
    #Define Logger
    global path

    #Get most recently edited workbook
    list_of_files = glob.glob('{}/workbooks/workbook*.xls*'.format(path))
    workbook = max(list_of_files, key=os.path.getctime)

    #Get Services and Site Routers that the Core Routers are connected to
    routing_details = parseRoutingDetails(workbook)
    services = getServices(workbook)
    site_rtrs = getSiteRouters(workbook)

    #Get credentials for CVP
    global username, password
    username, password = cvp_user, cvp_pass

    cvp_username, cvp_password = cvp_user, cvp_pass
    cvp_ipam_username, cvp_ipam_password = cvp_ipam_user, cvp_ipam_pass
    ib_username, ib_password = ib_user, ib_pass

    # cvp_username, cvp_password = "cvpadmin", "nynjlab"
    # cvp_ipam_username, cvp_ipam_password = "cvpadmin", "nynjlab"
    # ib_username, ib_password = "admin", "Arista123"

    #Parse CVP, CVP IPAM, and Infoblox Details
    logger.debug("Parsing CVP and IPAM info")
    server_info = yaml.load(open("{}/settings/appl_info.yml".format(path)), Loader=yaml.FullLoader)

    #Create CVP client
    try:
        cvp_nodes = [node for node in [ server_info["cvp"]['primary'] ] if node is not None ]
        cvp = CvpClient()
        cvp.connect(cvp_nodes, username, password)
        logger.info("Created CVP client")
    except CvpClientError as e:
        logger.error("Unable to create CVP client\n{}".format(e))
        return

    #Create IPAM clients
    try:
        cvp_ipam_view = server_info["cvp_ipam"]["network"] if server_info["cvp_ipam"]["network"].strip() != "" else None
        cvp_ipam_address = server_info["cvp_ipam"]["ip_address"] if server_info["cvp_ipam"]["ip_address"].strip() != "" else None
        cvp_ipam_client = ipam("cvp")
        cvp_ipam_client.login(cvp_ipam_address, cvp_username, cvp_password)
        logger.info("Created CVP IPAM client")
    except Exception as e:
        logger.error("Unable to create CVP IPAM client\n{}".format(e))
        return
    try:
        ib_ipam_view = server_info["infoblox"]["network"] if server_info["infoblox"]["network"].strip() != "" else None
        ib_ipam_address = server_info["infoblox"]["ip_address"] if server_info["infoblox"]["ip_address"].strip() != "" else None
        ib_ipam_client = ipam("infoblox")
        if ib_ipam_view is not None and ib_ipam_address is not None:
            ib_ipam_client.login(ib_ipam_address, ib_username, ib_password)
            logger.info("Created Infoblox IPAM client")
        else:
            logger.info("Not enough information given to create Infoblox IPAM client")
            ib_ipam_client = None
            logger.info("Skippping creating Infoblox IPAM client")
    except Exception as e:
        logger.error("Unable to create Infoblox IPAM client\n{}".format(e))
        ib_ipam_view = None
        ib_ipam_client = None
    
    if ib_ipam_client is not None:
        #Create networks/network_containers in routing details if they don't exist
        create_main_networks_in_infoblox(ib_ipam_client, ib_ipam_view, routing_details) 
        create_service_subnets_in_infoblox(ib_ipam_client, ib_ipam_view, services)

    #Get Core Router details
    if int(operation) == 1:
        core_rtrs = getCoreRoutersManagement(workbook, cvp_ipam_client, cvp_ipam_view, ib_ipam=ib_ipam_client, ib_ipam_network=ib_ipam_view)
    else:
        core_rtrs = getCoreRouters(workbook, cvp_ipam_client, cvp_ipam_view, ib_ipam=ib_ipam_client, ib_ipam_network=ib_ipam_view)

    if int(operation) == 1:
        container = yaml.load(open("{}/settings/cvp.yml".format(path)), Loader=yaml.FullLoader)["container"]
        logger.info("Creating Management Configs...")
        configureManagementConfig(core_rtrs, cvp_client=cvp, container=container)
        logger.info("Successfully Generated and Applied Management Configs.")

    if int(operation) == 2:
        logger.info("Creating Core Configs...")
        configureCoreFabric(core_rtrs, services, routing_details, cvp_client=cvp, container=None)
        logger.info("Successfully Generated and Applied Core Configs.")

    elif int(operation) == 3:
        logger.info("Creating Site Configs...")
        if ib_ipam_client is not None and ib_ipam_view is not None:
            addSiteRouterConnections(core_rtrs, site_rtrs, ib_ipam_client, ib_ipam_view, cvp_client=cvp)
        else:
            addSiteRouterConnections(core_rtrs, site_rtrs, cvp_ipam_client, cvp_ipam_view, cvp_client=cvp)
        logger.info("Successfully Generated and Applied Site Configs.")

    elif int(operation) == 0:
        logger.info("Getting Router Details")
        if ib_ipam_client is not None and ib_ipam_view is not None:
            printRouterDetails(core_rtrs, site_rtrs, ib_ipam_client, ib_ipam_view)
        else:
            printRouterDetails(core_rtrs, site_rtrs, cvp_ipam_client, cvp_ipam_view)
        logger.info("Successfully Retrieved Router Details")


if __name__ == "__main__":
    cherrypy.quickstart(Handler(),'/',config = config)