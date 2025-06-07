from pathlib import Path
from datetime import datetime
import win32evtlog as evt
import win32file
from typing import Dict, List
import json
from collections import defaultdict
import threading
import xmltodict
from ..variables import event_keys as ek
from ..variables import rule_keys as rk

class DetectionEngine:

    def __init__(self):
        self.detection_map = defaultdict(dict[list: dict])
        self.parse_fields = None
        self.thread_data_lock = threading.Lock()

    @staticmethod
    def parse_event(event: dict) -> dict:

        event = event[ek.main_event_key]

        def handle_Provider(value: dict) -> dict:
            return {ek.provider: f"{value[ek.at_sign_name_selector]}", ek.provider_guid: f"{value[ek.at_sign_guid_selector]}"}

        def handle_TimeCreated(value: dict) -> dict:
            date_and_time, fraction_seconds = value[ek.time_created_selector].split('.')
            dt_object = f"{date_and_time}.{fraction_seconds.replace('z', '')[:6]}+00:00"
            dt_object = datetime.fromisoformat(dt_object)
            timestamp = dt_object.timestamp()
            return {ek.time_created: int(timestamp)}

        def handle_Execution(value: dict) -> dict:
            return {ek.process_id: f"{value[ek.process_id_selector]}", ek.thread_id: f"{value[ek.thread_id_selector]}"}

        def handle_Security(value: dict) -> dict:
            return {ek.user_sid: f"{value[ek.user_sid_selector]}"}

        handlers_map = {
            "Provider": handle_Provider,
            "TimeCreated": handle_TimeCreated,
            "Execution": handle_Execution,
            "Security": handle_Security
        }

        parsed_event = {
            ek.errors_key: []
        }

        for key, value in event[ek.system_dict_key].items():
            if isinstance(value, dict):
                try:
                    custom_system_parse = handlers_map[key](value)
                    parsed_event.update(custom_system_parse)
                except KeyError:
                    parsed_event[ek.errors_key].append({key.lower(): ek.custom_parsing_error})
                    pass
            else:
                parsed_event.update({key.lower(): value})

        for obj in event[ek.event_data_dict][ek.data_key]:
            try:
                key = obj[ek.at_sign_name_selector].lower()
                value = obj[ek.hashtag_text_selector]
                if key not in parsed_event:
                    parsed_event.update({key: value})
            except KeyError:
                parsed_event[ek.errors_key].append(obj)
                pass
        return parsed_event

    def detection_handler(self, event: dict, rule: dict):
        parsed_event = self.parse_event(event)
        hi = self.detection_map
        rule_offense_source = rule[rk.offense_source_key]
        print(f'print from analyzer of {json.dumps(event, indent=4)}\n\n')
        print(f'print of parsed event' + '\n' + json.dumps(parsed_event, indent=4))
        print('\n\n')
        print('detection map')
        print(hi)
        print('\n\n')
        print('rule data')
        print(rule)

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

