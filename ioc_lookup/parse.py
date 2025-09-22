import urllib.parse
from dataclasses import dataclass
from typing import Any

from validators import domain, email, ipv4, ipv6, md5, sha1, sha256, sha512, url, validator

from ioc_lookup.ioc_lookup_app import current_ioc_lookup_app
from ioc_lookup.misp_api import Attr, AttrType

__author__ = "lundberg"


@dataclass
class InputError:
    line: int
    message: str


class ParseException(Exception):
    def __init__(self, message: str, errors: list[InputError], *args: Any) -> None:
        super().__init__(message, *args)
        self.message = message
        self.errors = errors


@validator
def defanged_url(value: str) -> bool:
    """
    hxxps[://]defanged.url/path -> True
    """
    defanged_protocol = ["hxxp://", "hxxp[://]", "hxxps://", "hxxps[://]", "http[://]", "https[://]"]
    for protocol in defanged_protocol:
        if value.startswith(protocol):
            # It looks like a defanged url, let's check if it's a valid url
            value = undefang_url(value)
            return url(value)
    return False


def undefang_url(value: str) -> str:
    value = value.replace("hxx", "htt", 1)  # Replace only the first occurrence of hxx with htt
    value = value.replace("[", "").replace("]", "")  # this will break eventual IPv6 address urls
    try:
        # try to handle IPv6 address urls
        url_components = urllib.parse.urlsplit(value)
        netloc = url_components.netloc
        if ipv6(netloc):
            netloc = f"[{netloc}]"
        value = urllib.parse.urlunsplit(
            [url_components.scheme, netloc, url_components.path, url_components.query, url_components.fragment],
        )
    except ValueError:
        pass
    return value


def get_canonical_url(uri: str) -> str:
    url_components = urllib.parse.urlsplit(uri)
    return urllib.parse.urlunsplit([url_components.scheme, url_components.netloc, url_components.path, None, None])


def undefang_domain(value: str) -> str:
    value = value.replace("[.]", ".")
    return value


def pre_parse_item(item: str) -> str:
    item = "".join(item.split())  # Normalize whitespace
    item = urllib.parse.unquote_plus(item)
    if "[.]" in item:  # refang domains, urls, ips and emails
        current_ioc_lookup_app.logger.debug(f"Replacing [.] with . in: {item}")
        item = item.replace("[.]", ".")
    if "[:]" in item:  # refang ipv6 ips and url ports
        current_ioc_lookup_app.logger.debug(f"Replacing [:] with : in: {item}")
        item = item.replace("[:]", ":")
    if "md5:" in item:
        current_ioc_lookup_app.logger.debug(f"Removing md5: from: {item}")
        item = item.replace("md5:", "")
    if "sha1:" in item:
        current_ioc_lookup_app.logger.debug(f"Removing sha1: from: {item}")
        item = item.replace("sha1:", "")
    if "sha256:" in item:
        current_ioc_lookup_app.logger.debug(f"Removing sha256: from: {item}")
        item = item.replace("sha256:", "")
    if "sha512:" in item:
        current_ioc_lookup_app.logger.debug(f"Removing sha512: from: {item}")
        item = item.replace("sha512:", "")
    if "#" in item:  # remove comments
        current_ioc_lookup_app.logger.debug(f"Removing # everything after # from: {item}")
        item = "".join(item.split("#")[:-1])
    return item


def parse_items(items: str | None) -> list[Attr]:
    parsed_items: list[Attr] = []
    line = 0
    errors = []
    if not items:
        return parsed_items
    for item in items.split("\n"):
        line += 1
        if item:
            current_ioc_lookup_app.logger.debug(f"Parsing line: {item}")
            pre_parsed_item = pre_parse_item(item)
            if not pre_parsed_item:
                current_ioc_lookup_app.logger.debug("Skipping empty line")
                continue

            current_ioc_lookup_app.logger.debug(f"Parsing item {pre_parsed_item}")
            for part in pre_parsed_item.split(" "):
                typ, search_types, report_types = None, None, None
                if not part:  # skip empty parts
                    continue
                if part.startswith("#"):  # ignore comments
                    current_ioc_lookup_app.logger.debug(f"Part is a comment: {part}")
                    continue

                # Determine the type of the item
                current_ioc_lookup_app.logger.debug(f"Part {part}")
                if domain(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like a domain")
                    typ = AttrType.DOMAIN
                    search_types = [AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP]
                    report_types = [AttrType.DOMAIN]
                if url(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like an url")
                    typ = AttrType.URL
                    search_types = [AttrType.URL]
                    report_types = [AttrType.URL]
                    # Remove arguments from URLs
                    part = get_canonical_url(part)
                if defanged_url(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like a defanged url")
                    typ = AttrType.URL
                    search_types = [AttrType.URL]
                    report_types = [AttrType.URL]
                    # MISP wants a correct URL, so replace hxx with htt
                    part = get_canonical_url(undefang_url(part))
                if ipv4(part) or ipv6(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like an ip address")
                    typ = AttrType.IP_SRC
                    search_types = [
                        AttrType.DOMAIN_IP,
                        AttrType.IP_SRC,
                        AttrType.IP_SRC_PORT,
                        AttrType.IP_DST,
                        AttrType.IP_DST_PORT,
                    ]
                    report_types = [AttrType.IP_SRC]
                if md5(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like a md5 hash")
                    typ = AttrType.MD5
                    search_types = [AttrType.MD5, AttrType.FILENAME_MD5, AttrType.MALWARE_SAMPLE]
                    report_types = [AttrType.MD5]
                if sha1(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like a sha1 hash")
                    typ = AttrType.SHA1
                    search_types = [AttrType.SHA1, AttrType.FILENAME_SHA1, AttrType.MALWARE_SAMPLE]
                    report_types = [AttrType.SHA1]
                if sha256(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like a sha256 hash")
                    typ = AttrType.SHA256
                    search_types = [AttrType.SHA256, AttrType.FILENAME_SHA256, AttrType.MALWARE_SAMPLE]
                    report_types = [AttrType.SHA256]
                if sha512(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like a sha512 hash")
                    typ = AttrType.SHA512
                    search_types = [AttrType.SHA512, AttrType.FILENAME_SHA512, AttrType.MALWARE_SAMPLE]
                    report_types = [AttrType.SHA512]
                if email(part):
                    current_ioc_lookup_app.logger.debug(f"{part} looks like an email address")
                    typ = AttrType.EMAIL
                    search_types = [
                        AttrType.EMAIL,
                        AttrType.EMAIL_SRC,
                        AttrType.EMAIL_DST,
                        AttrType.TARGET_EMAIL,
                        AttrType.EPPN,
                    ]
                    report_types = [AttrType.EMAIL]
                if typ is None or search_types is None or report_types is None:
                    current_ioc_lookup_app.logger.debug(
                        f"Part {part} from item {pre_parsed_item} does not look like an IOC"
                    )
                    errors.append(InputError(line=line, message=f"Invalid input: {item}"))
                    continue
                current_ioc_lookup_app.logger.debug(f"Found IOC: {part} ({typ})")
                parsed_items.append(Attr(value=part, type=typ, search_types=search_types, report_types=report_types))
    if errors:
        raise ParseException("Could not parse input", errors=errors)
    return parsed_items


def parse_item(item: str | None) -> Attr | None:
    try:
        items = parse_items(item)
    except ParseException:
        return None
    if not items:
        return None
    return items[0]
