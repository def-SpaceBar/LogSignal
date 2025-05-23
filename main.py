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
from main_engine import Engine as Eg


def main():
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

    def load_rules(_rules_folder: str) -> List:
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

    # PATHS ####
    _CONFIG_PATH = r"config.json"
    _RULES_FOLDER = r"rules"
    # PATHS ####

    # LOAD DATA ####
    rules_jsons = load_rules(_RULES_FOLDER)
    _config_json = read_json(_CONFIG_PATH)
    monitored_channels = set(_config_json["channel_monitor"])
    #### LOAD DATA ####

    # OBJECTS ####
    Engine = Eg()
    Engine.rule_engine.rules_folder = _RULES_FOLDER
    Engine.rule_engine.rules = {rule['id']: rule for rule in rules_jsons}
    # OBJECTS ####

    # VALIDATIONS ####
    validate_channels = Engine.detection_engine.validate_channels(monitored_channels)
    # VALIDATIONS ####

    if validate_channels["all_valid"]:
        pass
    else:
        print(f"One or more channel is invalid - {validate_channels["invalid_set"]}")
        print('It will likely cause errors in initiating the xml rules')

    # INITIATE SUBSCRIBERS ####
    for item, value in Engine.rule_engine.rules.items():
        xml_data = Engine.rule_engine.load_xml(value['id'])
        sub_channel = xmltodict.parse(xml_data)['QueryList']['Query']['@Path']
        subscription = Engine.sub_manager.start_sub(sub_channel, xml_data, value)
        Engine.sub_manager.register_sub(
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
    # INITIATE SUBSCRIBERS ####
    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()
