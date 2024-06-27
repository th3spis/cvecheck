#!/usr/bin/env python3

from pymisp import PyMISP
from pymisp import MISPEvent
from pymisp import MISPAttribute
import argparse
import datetime

warnings.filterwarnings("ignore")
logging.basicConfig(level=logging.WARN)
logger = logging.getLogger()
warnings.filterwarnings("ignore") 


def upload_Vacunas_mClaudia_to_MISP(misp_key, event_name, event_distribution, event_threat_level, attributes_list, block, tags, diff):
    misp_url = "https://misp.mydomain.es/" # MISP URL
    mispInst = PyMISP(misp_url, misp_key, False)
    eventJson = MISPEvent()
    eventJson.distribution = event_distribution
    eventJson.threat_level_id = event_threat_level
    eventJson.info = event_name
    eventJson = mispInst.add_event(eventJson)
    for attr in attributes_list:
        fretext = mispInst.freetext(eventJson, attr)
    
    print(eventJson["Event"]["uuid"])
    print(str(fretext))
    print(str(mispInst))
    event_uuid = eventJson["Event"]["uuid"]
    
    if block:
        mispInst.tag(event_uuid, "Blacklist")
    if len(tags) != 0:
        for tag in tags:
            mispInst.tag(event_uuid, tag)
    
    #EVENT TAGS
    mispInst.tag(event_uuid, "TAG1")
    mispInst.tag(event_uuid, "TAG2")
    mispInst.tag(event_uuid, "tlp:amber") # tag3
    #Añadir las que falten

    #Publicar evento
    mispInst.publish(eventJson["Event"]["id"], False)
    

if __name__== "__main__":
    #lista de atributos para el evento
    attributes_list = []
    #evento - titulo 1 - modificar/adaptar al contenido del evento/entrada
    titulo_evento1 = "IOCs de nosedonde"
    event_date = datetime.datetime.now()
    parser = argparse.ArgumentParser(prog='upload_iocs_to_misp.py: MISP AGENT - UPLOAD IOCS TO MISP.')
    parser.add_argument('-key', type=str, nargs='?', required=True, help='(str) MISP USER API KEY')
    parser.add_argument('-iocsToBlacklist', type=str, nargs='?', required=True, help='(str)  IOCs should be added to blacklist??(Y/N/some).')
    parser.add_argument('-event_name', type=str, nargs='?', default="", help='(str) Event name on MISP')
    parser.add_argument('-distribution', type=str, nargs='?', default='1', help='(int) Sharing level(0->Your organization only, 1->This community only, 2->Connected communities, 3->All communities, 4->Sharing group')
    parser.add_argument('-threat_level', type=str, nargs='?', default='2', help='(int) Threat level (1->high, 2->medium, 3->low, 4->undefined)')
    parser.add_argument('-file', type=str, nargs='?', required=False, default="", help='(str) Path to the IOCs file (ABSOLUTE PATH).')
    parser.add_argument('-tags', type=str, nargs='?', default="none", required=False, help='(str) Event tags separated by commas (Example: APT,MALWARE,Type:OSINT,...). Tags tlp:amber, InternalSource and Source:InternalPythonScript are included by default')
    args = parser.parse_args()
    upload_Vacunas_mClaudia_to_MISP(args.key, args.event_name, args.distribution, args.threat_level, attributes_list, block, taglist, True)
    