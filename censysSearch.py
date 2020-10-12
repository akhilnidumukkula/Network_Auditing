import censys.ipv4
import json
from constants import CENSYS_API_SECRET, CENSYS_API_ID, IP_RANGE

c = censys.ipv4.CensysIPv4(RADHIKA_API_ID, RADHIKA_API_SECRET)


def extract_info(attack, query):
    aggregate_info = []
    with open("vulnerable_hosts.txt", 'a+') as hosts:
        hosts.write("%s vulnerable hosts \n" % attack)
        for subnet in IP_RANGE:
            for info in c.search(query % subnet):
                if '152.' in info['ip']:
                    hosts.write("{0} \n".format(info['ip']))
                    aggregate_info.append(info)
        with open(attack + ".json", "w") as f:
            json.dump(aggregate_info, f, indent=4)
        hosts.write("\n")


extract_info("Poodle_Attack", "%s AND 443.https.ssl_3.support: True")
extract_info("Logjam_Attack", "%s AND 443.https.dhe_export.support: True")
extract_info("Freak_Attack", "%s AND 443.https.rsa_export.support: 1’")
extract_info("Carpe_Diem", "443.https.get.metadata.version: /(2.4.1[0-9]{1})|(2.4.2[0-9]{1})|(2.4.3[0-7]{1})/ AND "
                           "443.https.get.metadata.manufacturer: Apache* AND %s")
