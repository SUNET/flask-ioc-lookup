# -*- coding: utf-8 -*-

import csv
import sys

import yaml

from rpz_lookup.misp_api import MISPApi

__author__ = 'lundberg'


def main(path, api, delimiter=';', quotechar='"'):
    with open(path) as f:
        reader = csv.reader(f, delimiter=delimiter, quotechar=quotechar)
        domain_names = []
        for row in reader:
            domain_name = row[0]
            # TODO: More columns
            domain_names.append(domain_name)
        r = api.add_event(
            domain_names=domain_names,
            info='From misp_event_importer',
            tags=['OSINT', 'TLP:WHITE'],
            comment='From CSV',
            to_ids=True,
            published=True,
        )
        print(r)


if __name__ == '__main__':
    if len(sys.argv) == 2:
        with open('config.yaml') as cf:
            config = yaml.safe_load(cf)
        misp_api = MISPApi(config)
        main(path=sys.argv[1], api=misp_api)
    else:
        print('Usage: misp_event_importer.py path_to_csv')
        sys.exit(1)
    sys.exit(0)
