import xlrd
import json

def parseServices(workbook):
    services = []
    try:
        workbook = xlrd.open_workbook(workbook)
    except:
        logger.error("Error finding workbook {}".format(workbook))
        return None
    try:
        worksheet = workbook.sheet_by_name("Services")
    except:
        logger.error("Error finding 'Services' sheet in spreadsheet")
        return None
    first_row = [] # The row where we stock the name of the column
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        service = {}
        for col in range(worksheet.ncols):
            service[first_row[col]]=worksheet.cell_value(row,col)
        try:
            vrf = service["VRF"].strip()
            vni = int(service["VNI"])
            sub_iface_subnet = service["Subinterface Subnet"].strip()
            sub_iface_vlan = int(service["Subinterface VLAN"])
            description = service["Description"].strip() if service["Description"].strip() != "" else None
            services.append({
                "vrf": vrf,
                "vni": vni,
                "subinterface subnet": sub_iface_subnet,
                "subinterface vlan": sub_iface_vlan,
                "description": description
            })
        except KeyError as e:
            logger.error("Unable to find column: {} in 'Services' sheet.".format(str(e)))
            return None
        except Exception as e:
            logger.error("Issue parsing 'Services' sheet")
            return None
    return services