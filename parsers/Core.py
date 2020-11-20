import xlrd
import json

def parseCoreConnections(workbook):
    wan_links = {}
    try:
        workbook = xlrd.open_workbook(workbook)
    except:
        logger.error("Error finding workbook {}".format(workbook))
        return None
    try:
        worksheet = workbook.sheet_by_name("WAN Core Routers")
    except:
        logger.error("Error finding 'Wan Core Routers' sheet in spreadsheet")
        return None
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        core_rtr_links = {}
        for col in range(worksheet.ncols):
            core_rtr_links[first_row[col]]=worksheet.cell_value(row,col)
        try:
            name = core_rtr_links["Name"].strip()
            wan_links[name] = {}
            # if core_rtr_links["Interface to Halsey"].strip() != "":
            #     wan_links[name][core_rtr_links["Interface to Halsey"].strip()] = {
            #         "neighbor hostname": "Halsey"
            #     }
            # if core_rtr_links["Interface to Secaucus"].strip() != "":
            #     wan_links[name][core_rtr_links["Interface to Secaucus"].strip()] = {
            #         "neighbor hostname": "Secaucus"
            #     }
            # if core_rtr_links["Interface to Eighth"].strip() != "":
            #     wan_links[name][core_rtr_links["Interface to Eighth"].strip()] = {
            #         "neighbor hostname": "Eighth"
            #     }
            # if core_rtr_links["Interface to Hudson"].strip() != "":
            #     wan_links[name][core_rtr_links["Interface to Hudson"].strip()] = {
            #         "neighbor hostname": "Hudson"
            #     }
        except KeyError as e:
            logger.error("Unable to find column: {} in 'WAN Core Routers' sheet.".format(str(e)))
            return None
        except Exception as e:
            logger.error("Issue parsing 'WAN Core Routers' sheet")
            return None
            
    #Add remote interface details to link
    for rtr, link_info in wan_links.items():
        for link, info in link_info.items():
            for r_link, rinfo in wan_links[info["neighbor hostname"]].items():
                if rinfo["neighbor hostname"] == rtr:
                    wan_links[info["neighbor hostname"]][r_link] = {
                        "neighbor hostname": rtr,
                        "neighbor interface": link
                    }

    return wan_links

def parseRoutingDetails(workbook):
    #Get Loopback0, Loopback1, and ASN ranges defined in spreadsheet
    try:
        workbook = xlrd.open_workbook(workbook)
    except:
        logger.error("Error finding workbook {}".format(workbook))
        return None
    try:
        worksheet = workbook.sheet_by_name("WAN Core Details")
    except:
        logger.error("Error finding 'Wan Core Details' sheet in spreadsheet")
        return None

    for row in range(1, worksheet.nrows):
        if worksheet.cell(row, 0).value == "Core-to-Core Transit Address Range":
            core_to_core_transit_block = worksheet.cell(row, 1).value
        elif worksheet.cell(row, 0).value == "Core Loopback0 Address Range":
            lo0_range = worksheet.cell(row, 1).value
        elif worksheet.cell(row, 0).value == "Core Loopback1 Address Range":
            lo1_range = worksheet.cell(row, 1).value
        elif worksheet.cell(row, 0).value == "Core ASN Range":
            asn_range = worksheet.cell(row, 1).value
        elif worksheet.cell(row, 0).value == "Management Address Range":
            mgmt_range = worksheet.cell(row, 1).value

    routing_details = {
        "management subnet": mgmt_range,
        "core to core subnet": core_to_core_transit_block,
        "loopback0 subnet": lo0_range,
        "loopback1 subnet": lo1_range,
        "asn range": asn_range
    }
    return routing_details

