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
import cherrypy
import xlrd, xlwt

import logging
logging.basicConfig(level=logging.INFO)
formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
handler = logging.FileHandler('Deployment.log', mode='w+')
handler.setLevel(logging.INFO)
handler.setFormatter(formatter)
logger = logging.getLogger(__name__)
logger.addHandler(handler)

config = {
  'global' : {
    'server.socket_host' : '127.0.0.1',
    'server.socket_port' : 8080,
    'server.thread_pool' : 8,
    'server.ssl_module' : 'builtin'
  }
}

username, password = None, None

class Handler(object):
    @cherrypy.expose
    def index(self):
        f = open("index.html", "r")
        return f.read()
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    @cherrypy.tools.json_in()
    def run(self):

        result = {"operation": "request", "result": "success"}
        input_json = cherrypy.request.json
        print("INPUT JSON")
        print(json.dumps(input_json, indent=2))
        run_script(**input_json)
        return result
    
    @cherrypy.expose
    @cherrypy.tools.json_out()
    def log(self):
        f = open("Deployment.log")
        text = f.read()
        f.close()
        return json.dumps(text)

    @cherrypy.expose
    def readfile(self):
        list_of_files = glob.glob('./workbooks/workbook*.xls*') # * means all if need specific format then *.csv
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

        excel_file_name = "./workbooks/workbook.{}.xls".format(int(datetime.now().timestamp()))
        wb.save(excel_file_name)

        list_of_files = glob.glob('./workbooks/workbook.*.xls*')
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
        excel_file_name = "./workbooks/workbook.{}.xls".format(int(datetime.now().timestamp()))
        f = open(excel_file_name, "wb")
        
        while True:
            data = myFile.file.read(8192)
            f.write(data)
            if not data:
                f.close()
                break

        # Responses are serialized to JSON (because of the json_out decorator)
        return result

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

def configureCoreFabric(core_rtrs, services, cvp_client=None, include_mgmt=False):
    #Get Core Router Device Dictionary from CVP 
    if cvp_client is not None:
        cvp_core_rtr_info = getCoreRouterInfoFromCVP(cvp_client, core_rtrs)

    #Create configuration for WAN Core 
    for rtr in core_rtrs:
        #Create list of configlets to apply
        configlets_to_apply = []

        if include_mgmt == True:
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

def run_script(operation=None, user=None, passwd=None):
    list_of_files = glob.glob('./workbooks/workbook*.xls*')
    workbook = max(list_of_files, key=os.path.getctime)

    #Get Services and Site Routers that the Core Routers are connected to
    services = getServices(workbook)
    site_rtrs = getSiteRouters(workbook)

    #Get credentials for CVP
    global username, password
    username, password = user, passwd

    #Parse CVP details
    yaml_parsed = yaml.load(open("settings/cvp_info.yml"), Loader=yaml.FullLoader)
    cvp_nodes = [node for node in [ yaml_parsed['primary'], yaml_parsed['secondary'], yaml_parsed['tertiary'] ] if node is not None ]

    #Create CVP client
    cvp = CvpClient()
    cvp.connect(cvp_nodes, username, password)

    #Parse IPAM details
    yaml_parsed = yaml.load(open("settings/ipam_info.yml"), Loader=yaml.FullLoader)
    ipam_address = yaml_parsed["ip_address"]
    ipam_type = yaml_parsed["type"]
    ipam_network = yaml_parsed["network"]

    #Create IPAM client and define IPAM network
    ipam_username, ipam_password = username, password
    cvp_ipam = ipam(ipam_type)
    cvp_ipam.login(ipam_address, ipam_username, ipam_password)

    #Get Core Router details
    core_rtrs = getCoreRouters(workbook, cvp_ipam, ipam_network)

    for rtr in core_rtrs:
        print(rtr)

    return

    if int(operation) == 1:
        print("Creating Core Configs...")
        configureCoreFabric(core_rtrs, services, cvp_client=cvp, include_mgmt=True)

    elif int(operation) == 2:
        print("Creating Site Configs...")
        addSiteRouterConnections(core_rtrs, site_rtrs, cvp_ipam, ipam_network, cvp_client=cvp)

    elif int(operation) == 3:
        print("Adding New Sites to Core Configs")
        configureCoreFabric(core_rtrs, services, cvp_client=cvp, include_mgmt=False)

    elif int(operation) == 4:
        print("Adding Services to Site")
        addServicesToSite(core_rtrs, site_rtrs, cvp_ipam, ipam_network, cvp_client=cvp)


if __name__ == "__main__":
    cherrypy.quickstart(Handler(),'/',config = config)