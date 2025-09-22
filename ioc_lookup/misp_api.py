import logging
from datetime import date, datetime
from enum import StrEnum
from typing import Any

from pymisp import ExpandedPyMISP
from pymisp.mispevent import MISPAttribute, MISPEvent, MISPObject, MISPSighting

from ioc_lookup.misp_attributes import Attr, AttrType

logger = logging.getLogger(__name__)

__author__ = "lundberg"


class RequestException(Exception):
    pass


class EventCategory(StrEnum):
    NETWORK_ACTIVITY = "Network activity"
    PAYLOAD_DELIVERY = "Payload delivery"
    INTERNAL_REFERENCE = "Internal reference"


class TLP(StrEnum):
    GREEN = "tlp:green"  # first choice
    CLEAR = "tlp:clear"
    AMBER = "tlp:amber"
    AMBER_STRICT = "tlp:amber+strict"

    @classmethod
    def to_dict(cls) -> dict[str, str]:
        return {item.name: item.value for item in cls}


class MISPApi:
    def __init__(self, name: str, api_url: str, api_key: str, verify_cert: bool = True) -> None:
        self.name = name
        self.pymisp = ExpandedPyMISP(api_url, api_key, verify_cert)

    def __repr__(self) -> str:
        return f"MISPApi({self.name}, {self.pymisp})"

    @staticmethod
    def _handle_request_error(
        data: dict[str, Any] | str | list[MISPEvent | MISPAttribute | MISPObject] | list[dict[str, Any]],
    ) -> None:
        """
        Example error:
        {'errors': (405, {
                            'name': 'You do not have permission to use this functionality.',
                            'message': 'You do not have permission to use this functionality.',
                            'url': '/sightings/restSearch/attribute',
                         },
                    )
        }
        """
        if isinstance(data, dict) and "errors" in data:
            error_code, error = data["errors"]
            message = error.get("message") or "An unexpected error occurred"
            raise RequestException(message)

    @staticmethod
    def tlp_to_distribution(tlp: TLP) -> int:
        match tlp:
            case TLP.AMBER_STRICT:
                return 0
            case TLP.AMBER:
                return 1
            case TLP.GREEN:
                return 2
            case TLP.CLEAR:
                return 3
            case _:
                raise ValueError(f"Unknown TLP: {tlp}")

    def search(
        self,
        controller: str = "attributes",
        **kwargs,  # noqa: ANN003
    ) -> dict[str, Any] | str | list[MISPEvent | MISPAttribute | MISPObject] | list[dict[str, Any]]:
        logger.debug(f"searching for: controller={controller}, kwargs={kwargs}")
        ret = self.pymisp.search(controller, **kwargs)
        self._handle_request_error(ret)
        logger.debug(f"search returned:\n{ret}")
        return ret

    def searchall(self, value: str, controller: str = "attributes") -> list[Any]:
        logger.debug(f"searching for: controller={controller}, value={value}, searchall=True")
        ret = self.pymisp.search(controller, value=value, searchall=True)
        self._handle_request_error(ret)
        logger.debug(f"search returned:\n{ret}")
        assert isinstance(ret, dict)  # Please mypy
        return ret.get("Attribute", [])

    def search_sightings(
        self, context_id: str, context: str = "attribute", source: str | None = None
    ) -> dict[str, Any] | list[dict[str, MISPEvent | MISPAttribute | MISPSighting]]:
        logger.debug(f"searching sightings for: context={context}, context_id={context_id}, source={source}")
        ret = self.pymisp.search_sightings(context=context, context_id=context_id, source=source)
        self._handle_request_error(ret)
        logger.debug(f"search sightings returned:\n{ret}")
        return ret

    def org_name_id_mapping(self) -> None:
        pass

    def attr_search(self, attr: Attr) -> list[Any]:
        types = [typ.value for typ in attr.search_types]
        result = self.search(type_attribute=types, value=attr.value)
        assert isinstance(result, dict)
        return result.get("Attribute", [])

    def domain_name_search(
        self,
        domain_name: str,
        searchall: bool = False,
        publish_timestamp: datetime | None = None,
        limit: int | None = None,
    ) -> list[Any]:
        result = self.search(
            type_attribute="domain",
            value=domain_name,
            searchall=searchall,
            publish_timestamp=publish_timestamp,
            limit=limit,
        )
        assert isinstance(result, dict)
        return result.get("Attribute", [])

    def url_search(self, url: str, searchall: bool = False) -> list[Any]:
        result = self.search(type_attribute="url", value=url, searchall=searchall)
        assert isinstance(result, dict)
        return result.get("Attribute", [])

    def sighting_lookup(self, attribute_id: str, source: str | None = None) -> list[Any]:
        result = self.search_sightings(context_id=attribute_id, source=source)
        assert isinstance(result, list)
        return [item["Sighting"] for item in result]

    def _get_report_category(self, attr: Attr) -> EventCategory:
        network_activity_types = [
            AttrType.DOMAIN,
            AttrType.URL,
            AttrType.EMAIL,
            AttrType.IP_SRC,
            AttrType.IP_DST,
            AttrType.IP_SRC_PORT,
            AttrType.IP_DST_PORT,
        ]
        payload_delivery_types = [AttrType.MD5, AttrType.SHA1, AttrType.SHA256, AttrType.SHA512]

        if any(True for t in attr.report_types if t in network_activity_types):
            return EventCategory.NETWORK_ACTIVITY
        elif any(True for t in attr.report_types if t in payload_delivery_types):
            return EventCategory.PAYLOAD_DELIVERY
        else:
            raise NotImplementedError(f"EventCategory for {attr.report_types} not implemented")

    def add_event(
        self,
        attr_items: list[Attr],
        info: str,
        tags: list,
        comment: str,
        to_ids: bool,
        distribution: int,
        reference: str | None,
        ts: int | None = None,
        published: bool | None = False,
    ) -> dict[str, Any] | MISPEvent:
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
                type="text",
                category=EventCategory.INTERNAL_REFERENCE.value,
                value=reference,
                disable_correlation=True,
                comment=comment,
                timestamp=ts,
            )
            attrs.append(reference_attr)

        event = MISPEvent()
        event.from_dict(
            info=info,
            Attribute=attrs,
            Tag=tags,
            date=date.today(),
            published=published,
            threat_level_id=2,
            distribution=distribution,
        )
        logger.debug(event)
        return self.pymisp.add_event(event)

    def add_sighting(self, attr: Attr, sighting_type: str, source: str) -> MISPSighting:
        sighting = MISPSighting()
        sighting["value"] = attr.value
        sighting["type"] = sighting_type
        sighting["source"] = source
        res = self.pymisp.add_sighting(sighting, pythonify=True)
        assert isinstance(res, MISPSighting)  # please mypy
        return res

    def remove_sighting(
        self,
        attr: Attr,
        sighting_type: str,
        source: str,
        date_from: datetime | None = None,
        date_to: datetime | None = None,
    ) -> None:
        sightings: list[MISPSighting] = []
        for item in self.attr_search(attr):
            res = self.pymisp.search_sightings(
                context="attribute",
                context_id=item["id"],
                type_sighting=sighting_type,
                source=source,
                date_from=date_from,
                date_to=date_to,
                pythonify=True,
            )
            # Can't get mypy to understand that sighting contains a MISPSighting
            sightings.extend([d["sighting"] for d in res if d.get("sighting") is not None])  # type: ignore  # noqa: PGH003
            # Please mypy
        for sighting in sightings:
            self.pymisp.delete_sighting(sighting)
