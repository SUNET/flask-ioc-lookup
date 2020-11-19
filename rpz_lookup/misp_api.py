# -*- coding: utf-8 -*-

import datetime
import logging
from typing import Any, List, Optional

from pymisp import ExpandedPyMISP
from pymisp.mispevent import MISPAttribute, MISPEvent

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class MISPApi:
    def __init__(self, api_url: str, api_key: str, verify_cert: bool = True):
        self.pymisp = ExpandedPyMISP(api_url, api_key, verify_cert)

    def search(self, controller='attributes', **kwargs):
        return self.pymisp.search(controller, **kwargs)

    def org_name_id_mapping(self):
        pass

    def domain_name_lookup(self, domain_name: str) -> List[Any]:
        result = self.search(type='domain', value=domain_name)
        return result.get('Attribute', [])

    def add_event(
        self,
        domain_names: list,
        info: str,
        tags: List,
        comment: str,
        to_ids: bool,
        reference: Optional[str],
        ts: Optional[int] = None,
        published: Optional[bool] = False,
    ):
        attrs = []
        for name in domain_names:
            domain_attr = MISPAttribute()
            domain_attr.from_dict(
                type='domain', category='Network activity', to_ids=to_ids, value=name, comment=comment, timestamp=ts
            )
            attrs.append(domain_attr)

        if reference:
            reference_attr = MISPAttribute()
            reference_attr.from_dict(
                type='text',
                category='Internal reference',
                value=reference,
                disable_correlation=True,
                comment=comment,
                timestamp=ts,
            )
            attrs.append(reference_attr)

        event = MISPEvent()
        event.from_dict(
            info=info, Attribute=attrs, Tag=tags, date=datetime.date.today(), published=published, threat_level_id=2
        )
        logger.debug(event)
        return self.pymisp.add_event(event)
