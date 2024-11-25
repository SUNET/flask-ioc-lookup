# -*- coding: utf-8 -*-

from unittest import TestCase

__author__ = "lundberg"

from ioc_lookup.utils import defanged_url, get_canonical_url, undefang_url


class TestApp(TestCase):

    def test_defang_url_handling(self):
        defanged_urls = [
            ("hxxp[://]example[.]org", "http://example.org"),
            ("hxxps[://]example[.]org/file/file[.]zip", "https://example.org/file/file.zip"),
            ("hxxps[://]example[.]org/file/SOMETHING/SOME-FILE", "https://example.org/file/SOMETHING/SOME-FILE"),
            (
                "hxxps[://][2606:2800:21f:cb07:6820:80da:af6b:8b2c]/file[.]zip",
                "https://[2606:2800:21f:cb07:6820:80da:af6b:8b2c]/file.zip",
            ),
        ]

        for item, expected in defanged_urls:
            assert defanged_url(item) is True, f"{item} is not defanged"
            url = undefang_url(item)
            url = get_canonical_url(url)
            assert url is not None
            assert url == expected, f"{url} != {expected}"
