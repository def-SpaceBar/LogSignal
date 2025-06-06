from pathlib import Path
from datetime import datetime
import win32evtlog as evt
import win32file
from typing import Dict, List
import json
from collections import defaultdict
import threading
import xmltodict

event_parser_dict = "{'Event': {'@xmlns': 'http://schemas.microsoft.com/win/2004/08/events/event', 'System': {'Provider': {'@Name': 'Microsoft-Windows-Security-Auditing', '@Guid': '{54849625-5478-4994-a5ba-3e3b0328c30d}'}, 'EventID': '4625', 'Version': '0', 'Level': '0', 'Task': '12544', 'Opcode': '0', 'Keywords': '0x8010000000000000', 'TimeCreated': {'@SystemTime': '2025-05-24T15:10:15.7370534Z'}, 'EventRecordID': '123205', 'Correlation': {'@ActivityID': '{496d4f50-c6fe-000a-ce4f-6d49fec6db01}'}, 'Execution': {'@ProcessID': '1840', '@ThreadID': '20556'}, 'Channel': 'Security', 'Computer': 'spacebar', 'Security': None}, 'EventData': {'Data': [{'@Name': 'SubjectUserSid', '#text': 'S-1-5-21-1695492534-1908105039-4174462650-1003'}, {'@Name': 'SubjectUserName', '#text': 'space'}, {'@Name': 'SubjectDomainName', '#text': 'SPACEBAR'}, {'@Name': 'SubjectLogonId', '#text': '0x3fd44c'}, {'@Name': 'TargetUserSid', '#text': 'S-1-0-0'}, {'@Name': 'TargetUserName', '#text': 'root1'}, {'@Name': 'TargetDomainName', '#text': 'SPACEBAR'}, {'@Name': 'Status', '#text': '0xc000006d'}, {'@Name': 'FailureReason', '#text': '%%2313'}, {'@Name': 'SubStatus', '#text': '0xc0000064'}, {'@Name': 'LogonType', '#text': '2'}, {'@Name': 'LogonProcessName', '#text': 'seclogo'}, {'@Name': 'AuthenticationPackageName', '#text': 'Negotiate'}, {'@Name': 'WorkstationName', '#text': 'SPACEBAR'}, {'@Name': 'TransmittedServices', '#text': '-'}, {'@Name': 'LmPackageName', '#text': '-'}, {'@Name': 'KeyLength', '#text': '0'}, {'@Name': 'ProcessId', '#text': '0x586c'}, {'@Name': 'ProcessName', '#text': 'C:\\\\Windows\\\\System32\\\\svchost.exe'}, {'@Name': 'IpAddress', '#text': '::1'}, {'@Name': 'IpPort', '#text': '0'}]}}}"
event_parser_dict = event_parser_dict.replace('None', 'null')
event_parser_dict = event_parser_dict.replace("'", '"')
event_parser_dict = json.loads(event_parser_dict)
example_parsing_list = [""]
print(json.dumps(event_parser_dict, indent=4))

# we have 2 main keys System and EventData.Data[]
event_dict = defaultdict()


# print(search_keys('Event.System.EventID', test))


def parse_event(event: dict):
    def handle_Provider(value: dict):
        return {"provider": f"{value["@Name"]}", "provider_guid": f"{value["@Guid"]}"}

    def handle_TimeCreated(value: dict):
        date_and_time, fraction_seconds = value["@SystemTime"].split('.')
        dt_object = f"{date_and_time}.{fraction_seconds.replace('z', '')[:6]}+00:00"
        dt_object = datetime.fromisoformat(dt_object)
        timestamp = dt_object.timestamp()
        return {"time_created": timestamp}

    handlers_map = {
        "Provider": handle_Provider,
        "TimeCreated": handle_TimeCreated
    }

    parsed_event = {}

    try:
        for key, value in event["System"]:
            ...

    except:
        ...

    return 0


parse_event(event=event_parser_dict)


class DetectionEngine:

    def __init__(self):
        self.detection_map = defaultdict(dict[list: dict])
        self.parse_fields = None
        self.thread_data_lock = threading.Lock()

    @staticmethod
    def search_keys(target: str, data: dict):
        target = target.split('.')
        result = data
        for key in target:
            if isinstance(result, dict):
                result = result.get(key, None)
            elif isinstance(result, list):
                try:
                    key = int(key)
                    if key <= len(result) - 1:
                        return result[key]
                except ValueError:
                    return result
            else:
                return f'{target}_parsing_error'
        return result

    @staticmethod
    def event_parser(parse_fields_list: list, event: dict):
        ...

    def analyzer(self, event: dict):
        hi = self.detection_map
        print(f'print from analyzer of {event}')

    @staticmethod
    def validate_channels(channel_set: set) -> dict:
        channel_set = channel_set
        invalid_channel_set = set()

        for channel in channel_set:

            try:
                cfg = evt.EvtOpenChannelConfig(ChannelPath=f"{channel}", Flags=0, Session=None)
                api_call_success, decimal_flags = evt.EvtGetChannelConfigProperty(
                    cfg,
                    evt.EvtChannelConfigEnabled,  # property ID == 0
                    0)  # flags = 0
            except Exception:
                invalid_channel_set.add(channel)
                continue

            if api_call_success is True and decimal_flags >= 5:
                continue
            else:
                invalid_channel_set.add(channel)

            win32file.CloseHandle(cfg)

        return {
            "all_valid": True if len(invalid_channel_set) == 0 else False,
            "valid_set": channel_set - invalid_channel_set,
            "invalid_set": invalid_channel_set if invalid_channel_set != set() else None
        }
