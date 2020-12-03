import datetime
import logging
import json

logger = logging.getLogger('hpfeeds-output')

class ArcsightFormatter(logging.Formatter):
    def format(self, record):

        tmpmsg = json.loads(record.msg)
        mappingDict = {
            "src_ip": "src",
            "src_port": "spt",
            "dest_ip": "dst",
            "dest_port": "dpt",
            "transport": "proto",
            "direction": "deviceDirection",
            "vendor_product": "cs1",
            "ids_type": "cs2",
            "app": "cs3",
            "request_url": "request",
        }

        severity_map = {
            "high": "10",
            "medium": "5",
            "low": "3",
            "informational": "1"
        }
        severity = severity_map.get(tmpmsg.get('severity'), "1")
        timestamp = datetime.datetime.isoformat(datetime.datetime.utcnow())

        # Set dynamic variables
        outmsg = u"{} CEF:0|DukeSTINGAR|CHN|1.9.2|{}|{}|{}|".format(timestamp, tmpmsg['type'], tmpmsg['signature'],
                                                              severity)

        # Replace transport field with protocol value if blank
        tmpmsg['transport'] = tmpmsg.get('transport', tmpmsg['protocol'])

        # Iterate through remaining properties and append to outmsg
        for name, value in tmpmsg.items():
            if value and name in mappingDict:
                if name == 'direction':
                    value = 0 if value == 'inbound' else 1
                outmsg += "{}={} ".format(mappingDict[name], value)
                if mappingDict[name][:2] == "cs":
                    outmsg += "{}Label={} ".format(mappingDict[name], name)

        return outmsg.strip() # remove the trailing whitespace
