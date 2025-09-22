from collections.abc import Generator
from os import environ
from pathlib import Path

import pytest
from flask import jsonify
from flask.testing import FlaskClient

from ioc_lookup.ioc_lookup_app import IOCLookupApp
from ioc_lookup.misp_attributes import Attr, AttrType
from ioc_lookup.parse import InputError, ParseException, defanged_url, get_canonical_url, parse_items, undefang_url

__author__ = "lundberg"


@pytest.fixture()
def app() -> Generator[IOCLookupApp]:
    environ["IOC_LOOKUP_CONFIG"] = str(Path("./data/test_config.yaml"))
    app = IOCLookupApp("testing app")
    app.config.update(
        {
            "TESTING": True,
        }
    )

    # other setup can go here

    yield app

    # clean up / reset resources here


@pytest.fixture()
def client(app: IOCLookupApp) -> FlaskClient:
    return app.test_client()


def test_defang_url_handling() -> None:
    defanged_urls = [
        ("hxxp[://]example[.]org", "http://example.org"),
        ("hxxps[://]example[.]org/file/file[.]zip", "https://example.org/file/file.zip"),
        ("hxxps[://]example[.]org/file/SOMETHING/SOME-FILE", "https://example.org/file/SOMETHING/SOME-FILE"),
        (
            "hxxps[://][fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file[.]zip",
            "https://[fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip",
        ),
    ]

    for item, expected in defanged_urls:
        assert defanged_url(item) is True, f"{item} is not defanged"
        url = undefang_url(item)
        url = get_canonical_url(url)
        assert url is not None
        assert url == expected, f"{url} != {expected}"


def test_parse_items(app: IOCLookupApp) -> None:
    indata = """
            example.org
            test.example.org
            example[.]org
            hxxp://example[.]org
            hxxps://example[.]org/file/file[.]zip
            http[://]example[.]org
            https[://]example[.]org/file/file[.]zip
            https://[fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip
            192.168.100.100
            192[.]168[.]100[.]100
            fd00:2800:21f:cb07:6820:80da:af6b:8b2c
            fd00[:]2800[:]21f[:]cb07[:]6820[:]80da[:]af6b[:]8b2c
            0114f0fb3b87f8dc2dcbeda71c8dda9f
            md5:0114f0fb3b87f8dc2dcbeda71c8dda9f
            0b78a829c97b8abaad27a84b0a25f59be83d16bd
            sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd
            9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140
            sha256:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140 # some text
            7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b
            sha512:7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b
            example@example.org
            example@example[.]org
            """
    with app.app_context():
        result = parse_items(indata)
        assert result == [
            Attr(
                value="example.org",
                type=AttrType.DOMAIN,
                search_types=[AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP],
                report_types=[AttrType.DOMAIN],
            ),
            Attr(
                value="test.example.org",
                type=AttrType.DOMAIN,
                search_types=[AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP],
                report_types=[AttrType.DOMAIN],
            ),
            Attr(
                value="example.org",
                type=AttrType.DOMAIN,
                search_types=[AttrType.DOMAIN, AttrType.HOSTNAME, AttrType.DOMAIN_IP],
                report_types=[AttrType.DOMAIN],
            ),
            Attr(
                value="http://example.org", type=AttrType.URL, search_types=[AttrType.URL], report_types=[AttrType.URL]
            ),
            Attr(
                value="https://example.org/file/file.zip",
                type=AttrType.URL,
                search_types=[AttrType.URL],
                report_types=[AttrType.URL],
            ),
            Attr(
                value="http://example.org", type=AttrType.URL, search_types=[AttrType.URL], report_types=[AttrType.URL]
            ),
            Attr(
                value="https://example.org/file/file.zip",
                type=AttrType.URL,
                search_types=[AttrType.URL],
                report_types=[AttrType.URL],
            ),
            Attr(
                value="https://[fd00:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip",
                type=AttrType.URL,
                search_types=[AttrType.URL],
                report_types=[AttrType.URL],
            ),
            Attr(
                value="192.168.100.100",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="192.168.100.100",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="fd00:2800:21f:cb07:6820:80da:af6b:8b2c",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="fd00:2800:21f:cb07:6820:80da:af6b:8b2c",
                type=AttrType.IP_SRC,
                search_types=[
                    AttrType.DOMAIN_IP,
                    AttrType.IP_SRC,
                    AttrType.IP_SRC_PORT,
                    AttrType.IP_DST,
                    AttrType.IP_DST_PORT,
                ],
                report_types=[AttrType.IP_SRC],
            ),
            Attr(
                value="0114f0fb3b87f8dc2dcbeda71c8dda9f",
                type=AttrType.MD5,
                search_types=[AttrType.MD5, AttrType.FILENAME_MD5, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.MD5],
            ),
            Attr(
                value="0114f0fb3b87f8dc2dcbeda71c8dda9f",
                type=AttrType.MD5,
                search_types=[AttrType.MD5, AttrType.FILENAME_MD5, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.MD5],
            ),
            Attr(
                value="0b78a829c97b8abaad27a84b0a25f59be83d16bd",
                type=AttrType.SHA1,
                search_types=[AttrType.SHA1, AttrType.FILENAME_SHA1, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA1],
            ),
            Attr(
                value="0b78a829c97b8abaad27a84b0a25f59be83d16bd",
                type=AttrType.SHA1,
                search_types=[AttrType.SHA1, AttrType.FILENAME_SHA1, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA1],
            ),
            Attr(
                value="9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",
                type=AttrType.SHA256,
                search_types=[AttrType.SHA256, AttrType.FILENAME_SHA256, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA256],
            ),
            Attr(
                value="9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",
                type=AttrType.SHA256,
                search_types=[AttrType.SHA256, AttrType.FILENAME_SHA256, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA256],
            ),
            Attr(
                value="7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b",  # noqa: E501
                type=AttrType.SHA512,
                search_types=[AttrType.SHA512, AttrType.FILENAME_SHA512, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA512],
            ),
            Attr(
                value="7b77d9c836f414bbb53c6f28fd12550435049a9c22ce21910f23ae51a684be27e9e2d3ab9774da59f8e35bf7267aa3b6b2a48394ea7acce7627b37cec9ea363b",  # noqa: E501
                type=AttrType.SHA512,
                search_types=[AttrType.SHA512, AttrType.FILENAME_SHA512, AttrType.MALWARE_SAMPLE],
                report_types=[AttrType.SHA512],
            ),
            Attr(
                value="example@example.org",
                type=AttrType.EMAIL,
                search_types=[
                    AttrType.EMAIL,
                    AttrType.EMAIL_SRC,
                    AttrType.EMAIL_DST,
                    AttrType.TARGET_EMAIL,
                    AttrType.EPPN,
                ],
                report_types=[AttrType.EMAIL],
            ),
            Attr(
                value="example@example.org",
                type=AttrType.EMAIL,
                search_types=[
                    AttrType.EMAIL,
                    AttrType.EMAIL_SRC,
                    AttrType.EMAIL_DST,
                    AttrType.TARGET_EMAIL,
                    AttrType.EPPN,
                ],
                report_types=[AttrType.EMAIL],
            ),
        ]


def test_parse_items_errors(app: IOCLookupApp) -> None:
    indata = """
            example.org
            test.example.org
            example[.]org
            some other text sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd
            other text here:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140
            """
    with app.app_context():
        with pytest.raises(ParseException) as e:
            parse_items(indata)
        assert e.value.errors == [
            InputError(
                line=5,
                message="Invalid input:             some other text sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd",
            ),
            InputError(
                line=6,
                message="Invalid input:             other text here:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",  # noqa: E501
            ),
        ]
        assert jsonify({"errors": e.value.errors}).json == {
            "errors": [
                {
                    "line": 5,
                    "message": "Invalid input:             some other text sha1:0b78a829c97b8abaad27a84b0a25f59be83d16bd",  # noqa: E501
                },
                {
                    "line": 6,
                    "message": "Invalid input:             other text here:9dc1b05b8fc53c84839164e82200c5d484b65eeba25b246777fa324869487140",  # noqa: E501
                },
            ]
        }
