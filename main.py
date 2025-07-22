import json
import time
from pathlib import Path
from typing import Dict, List
import xmltodict
from main_engine import Engine as Eg
from variables.rule_keys import alert_source_key, rule_id_key, rule_name_key, rule_description_key, rule_xml_key, subscription_channel_key

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
    # TODO: refactor to load from database
    _CONFIG_PATH = r"config.json"
    _RULES_FOLDER = r"rules"
    # PATHS ####

    # LOAD DATA ####
    # TODO: refactor to load from database
    rules_jsons = load_rules(_RULES_FOLDER)
    _config_json = read_json(_CONFIG_PATH)
    monitored_channels = set(_config_json["channel_monitor"])
    #### LOAD DATA ####

    # OBJECTS ####
    Engine = Eg()
    Engine.rule_engine.rules_folder = _RULES_FOLDER
    Engine.rule_engine.rules = {rule[rule_id_key]: rule for rule in rules_jsons}
    # OBJECTS ####

    # VALIDATIONS ####
    # validates target channels, requires manual setup of known target channels based on the existing xml rules
    # TODO: will be modified soon & checked via channel aggregation from the loaded xml queries

    validate_channels = Engine.detection_engine.validate_channels(monitored_channels)

    if validate_channels["all_valid"]:
        pass
    else:
        print(f"One or more channel is invalid - {validate_channels["invalid_set"]}")
        print('It will likely cause errors in initiating the xml rules')
    # VALIDATIONS ####

    # INITIATE SUBSCRIBERS ####
    for rule, rule_value in Engine.rule_engine.rules.items():
        # Add the detection engine object to each subscribed rule
        rule_value.update({"detection_engine": Engine.detection_engine})
        # Load XML using the rule id
        xml_data = Engine.rule_engine.load_xml(rule_value[rule_id_key])
        # parse the target channel from the xml query and select by key
        channel_name = xmltodict.parse(xml_data)['QueryList']['Query']['@Path']
        # run the win-event xml query subscription
        subscription = Engine.sub_manager.start_sub(channel=channel_name, query=xml_data, context=rule_value)
        # register the subscription into the subscription manager
        Engine.sub_manager.register_sub(
            {
                subscription: {
                    rule_id_key: rule_value[rule_id_key],
                    subscription_channel_key: channel_name,
                    alert_source_key: rule_value[alert_source_key],
                    rule_name_key: rule_value[rule_name_key],
                    rule_description_key: rule_value[rule_description_key],
                    rule_xml_key: xml_data
                }
            }
        )

    # block exit
    while True:
        Engine.detection_engine.process_detection_map(rule_engine_object=Engine.rule_engine)
        time.sleep(3)
        # Engine.detection_engine.print_parsed_event_keys()


if __name__ == "__main__":
    main()
