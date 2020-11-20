import xlrd
import json

def parseSites(workbook):
    sites = []
    site_fields = ["Name", "ASN", "Services"]
    try:
        workbook = xlrd.open_workbook(workbook)
    except:
        logger.error("Error finding workbook {}".format(workbook))
        return None
    try:
        worksheet = workbook.sheet_by_name("Site Details")
    except:
        logger.error("Error finding 'Site Details' sheet in spreadsheet")
        return None
    first_row = []
    services = []
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
        if worksheet.cell_value(0,col) not in site_fields:
            services.append(worksheet.cell_value(0,col))
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        site = {}
        for col in range(worksheet.ncols):
            site[first_row[col]]=worksheet.cell_value(row,col)
            site["Services"] = []
            for k, v in site.items():
                if k in services:
                    if v.strip() != "":
                        site["Services"].append(k)
        for name in services:
            del site[name]
        sites.append(site)

    return sites

def parseSiteRouters(workbook):
    site_rtrs = []
    try:
        workbook = xlrd.open_workbook(workbook)
    except:
        logger.error("Error finding workbook {}".format(workbook))
        return None
    try:
        worksheet = workbook.sheet_by_name("Site Routers")
    except:
        logger.error("Error finding 'Site Routers' sheet in spreadsheet")
        return None
    first_row = []
    for col in range(worksheet.ncols):
        first_row.append( worksheet.cell_value(0,col) )
    # transform the workbook to a list of dictionaries
    for row in range(1, worksheet.nrows):
        rtr = {}
        for col in range(worksheet.ncols):
            rtr[first_row[col]]=worksheet.cell_value(row,col)
            
        site_rtrs.append(rtr)
    return site_rtrs