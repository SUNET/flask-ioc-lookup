# -*- coding: utf-8 -*-

from pymisp import PyMISP

__author__ = 'lundberg'


class MISPApi(object):

    def __init__(self, config: dict):
        self.pymisp = PyMISP(config['MISP_URL'], config['MISP_KEY'], config['MISP_VERIFYCERT'], 'json')

    def search(self, controller='attributes', **kwargs):
        return self.pymisp.search(controller, **kwargs)

    def org_name_id_mapping(self):
        pass

    def domain_name_lookup(self, domain_name: str):
        result = self.search(type='domain', value=domain_name)
        return result['response'].get('Attribute', [])




# {
#     "response": {
#         "Attribute": [
#             {
#                 "id": "984076",
#                 "event_id": "9259",
#                 "object_id": "0",
#                 "object_relation": null,
#                 "category": "Network activity",
#                 "type": "domain",
#                 "to_ids": true,
#                 "uuid": "5cb4806f-6220-4ad4-9989-370d6440000b",
#                 "timestamp": "1555333409",
#                 "distribution": "5",
#                 "sharing_group_id": "0",
#                 "comment": "A cert with this CN was logged by Certificate Transparency",
#                 "deleted": false,
#                 "disable_correlation": false,
#                 "value": "idp.it.su.se.llit.cf",
#                 "Event": {
#                     "org_id": "10",
#                     "distribution": "3",
#                     "id": "9259",
#                     "info": "Potential phishing site for IdP at: idp.it.su.se",
#                     "orgc_id": "10",
#                     "uuid": "5cb47f92-87a8-4ad4-81e0-311c6440000b"
#                 }
#             }
#         ]
#     }
# }