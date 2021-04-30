# -*- coding: utf-8 -*-

import logging
from datetime import date, datetime
from enum import Enum
from typing import Any, List, Optional

from pymisp import ExpandedPyMISP
from pymisp.mispevent import MISPAttribute, MISPEvent, MISPSighting

from ioc_lookup.misp_attributes import Attr, AttrType

logger = logging.getLogger(__name__)

__author__ = 'lundberg'


class EventCategory(Enum):
    NETWORK_ACTIVITY = 'Network activity'
    PAYLOAD_DELIVERY = 'Payload delivery'
    INTERNAL_REFERENCE = 'Internal reference'


class MISPApi:
    def __init__(self, api_url: str, api_key: str, verify_cert: bool = True):
        self.pymisp = ExpandedPyMISP(api_url, api_key, verify_cert)

    def search(self, controller: str = 'attributes', **kwargs):
        return self.pymisp.search(controller, **kwargs)

    def searchall(self, value: str, controller: str = 'attributes') -> List[Any]:
        result = self.pymisp.search(controller, value=value, searchall=True)
        assert isinstance(result, dict)  # Please mypy
        return result.get('Attribute', [])

    def search_sightings(self, context_id: str, context: str = 'attribute', source: Optional[str] = None):
        return self.pymisp.search_sightings(context=context, context_id=context_id, source=source)

    def org_name_id_mapping(self):
        pass

    def attr_search(self, attr: Attr) -> List[Any]:
        result = []
        for typ in attr.search_types:
            result += self.search(type=typ.value, value=attr.value).get('Attribute', [])
        return result

    def domain_name_search(self, domain_name: str, searchall: bool = False) -> List[Any]:
        result = self.search(type='domain', value=domain_name, searchall=searchall)
        return result.get('Attribute', [])

    def url_search(self, url: str, searchall: bool = False) -> List[Any]:
        result = self.search(type='url', value=url, searchall=searchall)
        return result.get('Attribute', [])

    def sighting_lookup(self, attribute_id: str, source: Optional[str] = None) -> List[Any]:
        result = self.search_sightings(context_id=attribute_id, source=source)
        return [item['Sighting'] for item in result]

    def _get_report_category(self, attr: Attr) -> EventCategory:
        if any(True for t in attr.report_types if t in [AttrType.DOMAIN, AttrType.URL, AttrType.IP_SRC]):
            return EventCategory.NETWORK_ACTIVITY
        elif any(True for t in attr.report_types if t in [AttrType.MD5, AttrType.SHA1]):
            return EventCategory.PAYLOAD_DELIVERY
        else:
            raise NotImplementedError(f'EventCategory for {attr.report_types} not implemented')

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
            category = self._get_report_category(item)
            for report_type in item.report_types:
                report_attr = MISPAttribute()
                report_attr.from_dict(
                    type=report_type.value,
                    category=category.value,
                    to_ids=to_ids,
                    value=item.value,
                    comment=comment,
                    timestamp=ts,
                )
                attrs.append(report_attr)

        if reference:
            reference_attr = MISPAttribute()
            reference_attr.from_dict(
                type='text',
                category=EventCategory.INTERNAL_REFERENCE.value,
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
        sighting['value'] = attr.value
        sighting['type'] = sighting_type
        sighting['source'] = source
        res = self.pymisp.add_sighting(sighting, pythonify=True)
        assert isinstance(res, MISPSighting)  # please mypy
        return res

    def remove_sighting(
        self,
        attr: Attr,
        sighting_type: str,
        source: str,
        date_from: Optional[datetime] = None,
        date_to: Optional[datetime] = None,
    ):
        sightings: List[MISPSighting] = []
        for item in self.attr_search(attr):
            res = self.pymisp.search_sightings(
                context='attribute',
                context_id=item['id'],
                type_sighting=sighting_type,
                source=source,
                date_from=date_from,
                date_to=date_to,
                pythonify=True,
            )
            # Can't get mypy to understand that sighting contains a MISPSighting
            sightings.extend([d['sighting'] for d in res if d.get('sighting') is not None])  # type: ignore
            # Please mypy
        for sighting in sightings:
            self.pymisp.delete_sighting(sighting)
