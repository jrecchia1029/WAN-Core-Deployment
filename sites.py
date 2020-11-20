import json

class Site():
    def __init__(self, name, services, asn=None):
        self.name = name
        self.services = services
        self.asn = int(asn)

    def __str__(self):
        output = "{}\n".format(self.name)
        output += "   ASN: {}\n".format(self.asn)
        output += "   Services: {}".format([service["vrf"] for service in self.services ])
        return output

class SiteRouter():
    def __init__(self, hostname, site):
        self.hostname = hostname
        self.site = site
        self.core_interfaces = None

    def __str__(self):
        output = "{}\n".format(self.hostname)
        output += "   Site: {}".format(self.site.name)
        return output