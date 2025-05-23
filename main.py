import json
import time
from collections import defaultdict
from pathlib import Path
from typing import Dict, List
import win32evtlog
import xmltodict
from detection_engine import DetectionEngine
from rule_engine import RuleEngine
from subscription_manager import SubscriptionManager


def main():
    #### PATHS ####

    _CONFIG_PATH = r"config.json"
    _RULES_FOLDER = r"rules"

    #### PATHS ####

    def read_json(_json_path: str | Path) -> Dict:
        try:
            with open(_json_path) as _json_file:
                json_data = json.load(_json_file)
        except Exception:
            raise ValueError
        finally:
            if json_data:
                return json_data
            else:
                raise FileNotFoundError | ValueError

    def load_rules(_rules_folder: str = _RULES_FOLDER) -> List:
        _rules_folder = Path(_rules_folder)
        rules_array = []
        for rule in _rules_folder.iterdir():
            if rule.suffix == ".json":
                try:
                    rule = read_json(rule)
                    rules_array.append(rule)
                except Exception:
                    print(f'Error occurred while reading rule {rule}')
                    pass
        return rules_array

    rules_jsons, _config_json = load_rules(), read_json(_CONFIG_PATH)

    RE = RuleEngine()
    RE.rules = defaultdict(str)
    RE.rules_folder = _RULES_FOLDER
    for rule in rules_jsons:
        RE.rules[rule['id']] = rule

    monitored_channels = set(_config_json["channel_monitor"])

    DE = DetectionEngine()
    validate_channels = DE.validate_channels(monitored_channels)

    if validate_channels["all_valid"]:
        pass
    else:
        print(f"One or more channel is invalid - {validate_channels["invalid_set"]}")
        print('It will likely cause errors in initiating the xml rules')

    SM = SubscriptionManager()
    for item, value in RE.rules.items():
        xml_data = RE.load_xml(value['id'])
        sub_channel = xmltodict.parse(xml_data)['QueryList']['Query']['@Path']
        subscription = SM.start_sub(sub_channel, xml_data, value)
        SM.register_sub(
            {
                subscription: {
                    "rule_id": value["id"],
                    "sub_channel": sub_channel,
                    "offense_source": "wip",
                    "name": value["name"],
                    "description": value["description"]

                }
            }
        )
    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()
