import csv
import sys

import yaml

from ioc_lookup.misp_api import MISPApi

__author__ = "lundberg"

from ioc_lookup.parse import parse_item


def main(path: str, api: MISPApi, delimiter: str = ";", quotechar: str = '"') -> None:
    with open(path) as f:
        reader = csv.reader(f, delimiter=delimiter, quotechar=quotechar)
        data_in = []
        for row in reader:
            # TODO: More columns
            if item := parse_item(row[0]):
                data_in.append(item)
        if data_in:
            r = api.add_event(
                attr_items=data_in,
                info="From misp_event_importer",
                tags=["OSINT", "TLP:WHITE"],
                comment="From CSV",
                to_ids=True,
                published=True,
                distribution=int(row[1]),
                reference=row[2],
            )
            print(r)


if __name__ == "__main__":
    if len(sys.argv) == 2:
        with open("config.yaml") as cf:
            config = yaml.safe_load(cf)
        misp_api = MISPApi(
            name="default",
            api_url=config["MISP_URL"],
            api_key=config["MISP_KEY"],
            verify_cert=config["MISP_VERIFYCERT"],
        )
        main(path=sys.argv[1], api=misp_api)
    else:
        print("Usage: misp_event_importer.py path_to_csv")
        sys.exit(1)
    sys.exit(0)
