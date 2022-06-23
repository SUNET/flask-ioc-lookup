# -*- coding: utf-8 -*-

from __future__ import annotations

import urllib.parse
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from tld import get_fld

__author__ = 'lundberg'

# Friendly names for supported AttrTypes
SUPPORTED_TYPES = ['domain name', 'URL', 'IP address', 'hash', 'email']


@dataclass
class Attr:
    value: str
    type: AttrType
    search_types: List[AttrType] = field(default_factory=list)
    report_types: List[AttrType] = field(default_factory=list)

    def get_domain(self) -> Optional[str]:
        if self.type in [AttrType.URL, AttrType.DOMAIN]:
            url_components = urllib.parse.urlsplit(self.value)
            return url_components.netloc
        return None

    def get_first_level_domain(self) -> Optional[str]:
        if self.type in [AttrType.URL, AttrType.DOMAIN]:
            return get_fld(self.value, fix_protocol=True, fail_silently=True, search_private=False)
        return None


class AttrType(Enum):
    AS = 'AS'
    ABA_RTN = 'aba-rtn'
    ANONYMISED = 'anonymised'
    ATTACHMENT = 'attachment'
    AUTHENTIHASH = 'authentihash'
    BANK_ACCOUNT_NR = 'bank-account-nr'
    BIC = 'bic'
    BIN = 'bin'
    BOOLEAN = 'boolean'
    BRO = 'bro'
    BTC = 'btc'
    CAMPAIGN_ID = 'campaign-id'
    CAMPAIGN_NAME = 'campaign-name'
    CC_NUMBER = 'cc-number'
    CDHASH = 'cdhash'
    CHROME_EXTENSION_ID = 'chrome-extension-id'
    COMMENT = 'comment'
    COMMUNITY_ID = 'community-id'
    COOKIE = 'cookie'
    CORTEX = 'cortex'
    COUNTER = 'counter'
    COUNTRY_OF_RESIDENCE = 'country-of-residence'
    CPE = 'cpe'
    DASH = 'dash'
    DATE_OF_BIRTH = 'date-of-birth'
    DATETIME = 'datetime'
    DNS_SOA_EMAIL = 'dns-soa-email'
    DOMAIN = 'domain'
    DOMAIN_IP = 'domain|ip'
    EMAIL = 'email'
    EMAIL_ATTACHMENT = 'email-attachment'
    EMAIL_BODY = 'email-body'
    EMAIL_DST = 'email-dst'
    EMAIL_DST_DISPLAY_NAME = 'email-dst-display-name'
    EMAIL_HEADER = 'email-header'
    EMAIL_MESSAGE_ID = 'email-message-id'
    EMAIL_MIME_BOUNDARY = 'email-mime-boundary'
    EMAIL_REPLY_TO = 'email-reply-to'
    EMAIL_SRC = 'email-src'
    EMAIL_SRC_DISPLAY_NAME = 'email-src-display-name'
    EMAIL_SUBJECT = 'email-subject'
    EMAIL_THREAD_INDEX = 'email-thread-index'
    EMAIL_X_MAILER = 'email-x-mailer'
    EPPN = 'eppn'
    FILENAME = 'filename'
    FILENAME_AUTHENTIHASH = 'filename|authentihash'
    FILENAME_IMPFUZZY = 'filename|impfuzzy'
    FILENAME_IMPHASH = 'filename|imphash'
    FILENAME_MD5 = 'filename|md5'
    FILENAME_PEHASH = 'filename|pehash'
    FILENAME_SHA1 = 'filename|sha1'
    FILENAME_SHA224 = 'filename|sha224'
    FILENAME_SHA256 = 'filename|sha256'
    FILENAME_SHA3_224 = 'filename|sha3-224'
    FILENAME_SHA3_256 = 'filename|sha3-256'
    FILENAME_SHA3_384 = 'filename|sha3-384'
    FILENAME_SHA3_512 = 'filename|sha3-512'
    FILENAME_SHA384 = 'filename|sha384'
    FILENAME_SHA512 = 'filename|sha512'
    FILENAME_SHA512_224 = 'filename|sha512/224'
    FILENAME_SHA512_256 = 'filename|sha512/256'
    FILENAME_SSDEEP = 'filename|ssdeep'
    FILENAME_TLSH = 'filename|tlsh'
    FILENAME_VHASH = 'filename|vhash'
    FIRST_NAME = 'first-name'
    FLOAT = 'float'
    FREQUENT_FLYER_NUMBER = 'frequent-flyer-number'
    GENDER = 'gender'
    GENE = 'gene'
    GIT_COMMIT_ID = 'git-commit-id'
    GITHUB_ORGANISATION = 'github-organisation'
    GITHUB_REPOSITORY = 'github-repository'
    GITHUB_USERNAME = 'github-username'
    HASSH_MD5 = 'hassh-md5'
    HASSHSERVER_MD5 = 'hasshserver-md5'
    HEX = 'hex'
    HOSTNAME = 'hostname'
    HOSTNAME_PORT = 'hostname|port'
    HTTP_METHOD = 'http-method'
    IBAN = 'iban'
    IDENTITY_CARD_NUMBER = 'identity-card-number'
    IMPFUZZY = 'impfuzzy'
    IMPHASH = 'imphash'
    IP_DST = 'ip-dst'
    IP_DST_PORT = 'ip-dst|port'
    IP_SRC = 'ip-src'
    IP_SRC_PORT = 'ip-src|port'
    ISSUE_DATE_OF_THE_VISA = 'issue-date-of-the-visa'
    JA3_FINGERPRINT_MD5 = 'ja3-fingerprint-md5'
    JABBER_ID = 'jabber-id'
    KUSTO_QUERY = 'kusto-query'
    LAST_NAME = 'last-name'
    LINK = 'link'
    MAC_ADDRESS = 'mac-address'
    MAC_EUI_64 = 'mac-eui-64'
    MALWARE_SAMPLE = 'malware-sample'
    MALWARE_TYPE = 'malware-type'
    MD5 = 'md5'
    MIDDLE_NAME = 'middle-name'
    MIME_TYPE = 'mime-type'
    MOBILE_APPLICATION_ID = 'mobile-application-id'
    MUTEX = 'mutex'
    NAMED = 'named'
    PIPE = 'pipe'
    NATIONALITY = 'nationality'
    OTHER = 'other'
    PASSENGER_NAME_RECORD_LOCATOR_NUMBER = 'passenger-name-record-locator-number'
    PASSPORT_COUNTRY = 'passport-country'
    PASSPORT_EXPIRATION = 'passport-expiration'
    PASSPORT_NUMBER = 'passport-number'
    PATTERN_FILENAME = 'pattern-filename'
    PATTERN_IN_FILE = 'pattern-in-file'
    PATTERN_IN_MEMORY = 'pattern-in-memory'
    PATTERN_IN_TRAFFIC = 'pattern-in-traffic'
    PAYMENT_DETAILS = 'payment-details'
    PDB = 'pdb'
    PEHASH = 'pehash'
    PGP_PRIVATE_KEY = 'pgp-private-key'
    PGP_PUBLIC_KEY = 'pgp-public-key'
    PHONE_NUMBER = 'phone-number'
    PLACE_OF_BIRTH = 'place-of-birth'
    PLACE_PORT_OF_CLEARANCE = 'place-port-of-clearance'
    PLACE_PORT_OF_ONWARD_FOREIGN_DESTINATION = 'place-port-of-onward-foreign-destination'
    PLACE_PORT_OF_ORIGINAL_EMBARKATION = 'place-port-of-original-embarkation'
    PORT = 'port'
    PRIMARY_RESIDENCE = 'primary-residence'
    PRTN = 'prtn'
    REDRESS_NUMBER = 'redress-number'
    REGKEY = 'regkey'
    REGKEY_VALUE = 'regkey|value'
    SHA1 = 'sha1'
    SHA224 = 'sha224'
    SHA256 = 'sha256'
    SHA3_224 = 'sha3-224'
    SHA3_256 = 'sha3-256'
    SHA3_384 = 'sha3-384'
    SHA3_512 = 'sha3-512'
    SHA384 = 'sha384'
    SHA512 = 'sha512'
    SHA512_224 = 'sha512/224'
    SHA512_256 = 'sha512/256'
    SIGMA = 'sigma'
    SIZE_IN_BYTES = 'size-in-bytes'
    SNORT = 'snort'
    SPECIAL_SERVICE_REQUEST = 'special-service-request'
    SSDEEP = 'ssdeep'
    STIX2_PATTERN = 'stix2-pattern'
    TARGET_EMAIL = 'target-email'
    TARGET_EXTERNAL = 'target-external'
    TARGET_LOCATION = 'target-location'
    TARGET_MACHINE = 'target-machine'
    TARGET_ORG = 'target-org'
    TARGET_USER = 'target-user'
    TELFHASH = 'telfhash'
    TEXT = 'text'
    THREAT_ACTOR = 'threat-actor'
    TLSH = 'tlsh'
    TRAVEL_DETAILS = 'travel-details'
    TWITTER_ID = 'twitter-id'
    URI = 'uri'
    URL = 'url'
    USER_AGENT = 'user-agent'
    VHASH = 'vhash'
    VISA_NUMBER = 'visa-number'
    VULNERABILITY = 'vulnerability'
    WEAKNESS = 'weakness'
    WHOIS_CREATION_DATE = 'whois-creation-date'
    WHOIS_REGISTRANT_EMAIL = 'whois-registrant-email'
    WHOIS_REGISTRANT_NAME = 'whois-registrant-name'
    WHOIS_REGISTRANT_ORG = 'whois-registrant-org'
    WHOIS_REGISTRANT_PHONE = 'whois-registrant-phone'
    WHOIS_REGISTRAR = 'whois-registrar'
    WINDOWS_SCHEDULED_TASK = 'windows-scheduled-task'
    WINDOWS_SERVICE_DISPLAYNAME = 'windows-service-displayname'
    WINDOWS_SERVICE_NAME = 'windows-service-name'
    X509_FINGERPRINT_MD5 = 'x509-fingerprint-md5'
    X509_FINGERPRINT_SHA1 = 'x509-fingerprint-sha1'
    X509_FINGERPRINT_SHA256 = 'x509-fingerprint-sha256'
    XMR = 'xmr'
    YARA = 'yara'
    ZEEK = 'zeek'
