# -*- coding: utf-8 -*-

import logging
from dataclasses import dataclass
from datetime import date, datetime
from enum import Enum
from typing import Any, List, Optional

from pymisp import ExpandedPyMISP
from pymisp.mispevent import MISPAttribute, MISPEvent, MISPSighting

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class AttrType(Enum):
    DOMAIN = 'domain'
    URL = 'url'


@dataclass
class Attr:
    name: str
    type: AttrType


class MISPApi:
    def __init__(self, api_url: str, api_key: str, verify_cert: bool = True):
        self.pymisp = ExpandedPyMISP(api_url, api_key, verify_cert)

    def search(self, controller: str = 'attributes', **kwargs):
        return self.pymisp.search(controller, **kwargs)

    def search_sightings(self, context_id: str, context: str = 'attribute', source: Optional[str] = None):
        return self.pymisp.search_sightings(context=context, context_id=context_id, source=source)

    def org_name_id_mapping(self):
        pass

    def attr_lookup(self, attr: Attr) -> List[Any]:
        if attr.type is AttrType.DOMAIN:
            return self.domain_name_lookup(domain_name=attr.name)
        elif attr.type is AttrType.URL:
            return self.url_lookup(url=attr.name)
        else:
            raise NotImplementedError(f'Lookup for typ {attr.type} not implemented.')

    def domain_name_lookup(self, domain_name: str) -> List[Any]:
        result = self.search(type='domain', value=domain_name)
        return result.get('Attribute', [])

    def url_lookup(self, url: str) -> List[Any]:
        result = self.search(type='url', value=url)
        return result.get('Attribute', [])

    def domain_sighting_lookup(self, attribute_id: str, source: Optional[str] = None) -> List[Any]:
        result = self.search_sightings(context_id=attribute_id, source=source)
        return [item['Sighting'] for item in result]

    def add_event(
        self,
        attr_items: List[Attr],
        info: str,
        tags: List,
        comment: str,
        to_ids: bool,
        reference: Optional[str],
        ts: Optional[int] = None,
        published: Optional[bool] = False,
    ):
        attrs = []
        for item in attr_items:
            report_attr = MISPAttribute()
            report_attr.from_dict(
                type=item.type.value,
                category='Network activity',
                to_ids=to_ids,
                value=item.name,
                comment=comment,
                timestamp=ts,
            )
            attrs.append(report_attr)

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
        event.from_dict(info=info, Attribute=attrs, Tag=tags, date=date.today(), published=published, threat_level_id=2)
        logger.debug(event)
        return self.pymisp.add_event(event)

    def add_sighting(self, attr: Attr, sighting_type: str, source: str) -> MISPSighting:
        sighting = MISPSighting()
        sighting['value'] = attr.name
        sighting['type'] = sighting_type
        sighting['source'] = source
        return self.pymisp.add_sighting(sighting)

    def remove_sighting(
        self,
        attr: Attr,
        sighting_type: str,
        source: str,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ):
        sightings = []
        for item in self.attr_lookup(attr):
            sightings.extend(
                self.pymisp.search_sightings(
                    context='attribute',
                    context_id=item['id'],
                    type_sighting=sighting_type,
                    source=source,
                    date_from=date_from,
                    date_to=date_to,
                    pythonify=True,
                )
            )
        for sighting in sightings:
            self.pymisp.delete_sighting(sighting)
