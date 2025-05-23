# from winevt import EventLog
# import datetime
# import iso8601
import json
import time
from pathlib import Path
from typing import Dict, List

import win32evtlog
import xmltodict

from detection_engine import DetectionEngine, SubscriptionManager
from rule_engine import RuleEngine



def main():

    #### PATHS ####;;

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
    rules_object = RuleEngine(rules_jsons, _RULES_FOLDER)

    monitored_channels = set(_config_json["channel_monitor"])

    validate_channels = DetectionEngine.validate_channels(monitored_channels)
    if validate_channels["all_valid"]:
        pass
    else:
        print(f"One or more channel is invalid - {validate_channels["invalid_set"]}")
        print('Continue with available channels')

    subs_object = SubscriptionManager()
    for item, value in rules_object.rules.items():
        xml_data = rules_object.load_xml(value['id'])
        sub_channel = xmltodict.parse(xml_data)['QueryList']['Query']['@Path']
        subs_object.register_sub(
            {
                value["id"]: subs_object.start_sub(sub_channel,
                                                   xml_data
                                                   )
            }
        )

    subscriptions = subs_object.sub_map.values()
    valid_handles = []
    for h in subscriptions:
        try:
            if h and int(h) != 0:
                valid_handles.append(int(h))
            else:
                print(f"[!] Skipped invalid handle: {h}")
        except Exception as e:
            print(f"[!] Handle error: {e}")

    if not valid_handles:
        raise RuntimeError("No valid handles to wait on!")

    xml = '''<QueryList>
      <Query Id="0" Path="Security">
        <Select Path="Security">*[System[EventID=4625]]</Select>
      </Query>
    </QueryList>'''


    while True:
        time.sleep(5)


if __name__ == "__main__":
    main()



# saving it here for a future boilerplate of log stream analysis
# h = evt.EvtQuery(
#         Path="",
#         Flags=evt.EvtQueryChannelPath,  # flags
#         Query=QUERY_XML
#     )
#
#
#
# BATCH = 128
#
# while True:
#     handles = evt.EvtNext(h, BATCH)
#     if not handles:
#         break
#     print(handles)
#     for eh in handles:
#         xml = evt.EvtRender(eh, evt.EvtRenderEventXml)
#         print(xml)
#         break
