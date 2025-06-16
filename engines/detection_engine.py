import time
from datetime import datetime
import win32evtlog as evt
import win32file
import json
from collections import defaultdict
import threading
from ..variables import event_keys as ek
from ..variables import rule_keys as rk
from ..engines import rule_engine
import sqlite3

debug_state = False


def sliding_time_window():
    ...


def counter_detection_module():
    ...


class DetectionEngine:

    def __init__(self):
        self.detection_map = defaultdict(lambda: defaultdict(list))
        self.parse_fields = None
        self.thread_data_lock = threading.Lock()
        self.parsed_events_keys = set()
        self.parsed_events_keys_by_rule_id = defaultdict(frozenset)

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

    def print_parsed_event_keys(self) -> set:
        return print(self.parsed_events_keys)

    @staticmethod
    def parse_event(event: dict) -> dict:

        event = event[ek.main_event_key]

        def handle_Provider(value: dict) -> dict:
            return {ek.provider: f"{value[ek.at_sign_name_selector]}",
                    ek.provider_guid: f"{value[ek.at_sign_guid_selector]}"}

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

    def append_event_to_map(self, rule_id, offense_source_value, event) -> None:
        self.detection_map[rule_id][offense_source_value].append(event)

    def event_error_handler(self, rule_id: str | None, error_message: str, event: dict, error_key='errors') -> None:
        rule_id = rule_id if rule_id is not None else 'unknown'
        event.update({'error_message': error_message})
        self.detection_map[error_key][rule_id].append(event)

    def update_detection_events(self,rule_id: str, alert_source: str, events: list):
        self.detection_map[rule_id][alert_source] = events


    def event_handler(self, event: dict, rule: dict) -> append_event_to_map or event_error_handler:
        parsed_event = self.parse_event(event)
        self.parsed_events_keys = self.parsed_events_keys | set(parsed_event.keys())
        # self.parsed_events_keys.add()

        # Get the RULE_ID value from the rule dict
        rule_id_value = rule.get(rk.rule_id_key, None)
        if debug_state:
            print(f"{rule_id_value=}")

        # Get Configured OFFENSE_SOURCE from the current monitoring rule configuration
        rule_offense_source = rule.get(rk.alert_source_key, None)
        if debug_state:
            print(f"{rule_offense_source=}")

        # Get the event's OFFENSE_SOURCE value
        event_offense_source_value = parsed_event.get(rule_offense_source, None)
        if debug_state:
            print(f"{event_offense_source_value=}")

        if not rule_id_value:
            self.event_error_handler(rule_id=rule_id_value,
                                     error_message='get_rule_offense_source_key',
                                     event=parsed_event)
            return

        if not rule_offense_source:
            self.event_error_handler(rule_id=rule_id_value,
                                     error_message='get_rule_offense_source_key',
                                     event=parsed_event)
            return

        if not event_offense_source_value:
            self.event_error_handler(rule_id=rule_id_value,
                                     error_message='get_event_offense_source_value',
                                     event=parsed_event)
            return

        self.append_event_to_map(offense_source_value=event_offense_source_value,
                                 event=parsed_event,
                                 rule_id=rule[rk.rule_id_key])

    def event_cleanup(self, event: dict, statements: dict, rule_id, valid_events = None):
        for field, allowed in statements.get("equals", {}).items():
            if event.get(field) not in allowed:
                return False

        for field, substrings in statements.get("contains", {}).items():
            value = event.get(field, "")
            if not isinstance(value, str):
                return False  # field missing or not a string → fail
            if not any(sub in value for sub in substrings):
                return False

        return True

    def analyzer(self, rule_engine_object):
        current_time = time.time()
        engines_map = {
            "counter": counter_detection_module
        }

        detection_map = self.detection_map
        rules = rule_engine_object.rules

        for rule, detections in detection_map.items():

            # get the rule instructions
            rule_data = rules.get(rule, None)
            engine_instructions = rule_data.get(rk.engine_instructions_key, None)

            # check if we have all needed data
            if rule_data is None:
                print(f"Analyzer Error | Rule {rule} | Could not find rule instructions")
            elif engine_instructions is None:
                print(f"Analyzer Error | Rule {rule} | Could not find engine instructions")
            if rule_data or engine_instructions is None:
                continue

            detection_function = engines_map.get(rk.engine_name_key, None)
            event_remove_statements = engines_map.get(rk.engine_name_key, {})

            if event_remove_statements:
                for alert_source, event_list in detections.items():
                    cleanup_event_list = [event for event in event_list
                                          if self.event_cleanup(event=event,
                                                                statements=event_remove_statements,
                                                                rule_id=rule)
                                          and (current_time - event[ek.time_created]) <= ek.one_hour_in_second
                                          ]

            else:
                for alert_source, event_list in detections.items():
                    cleanup_event_list = [event for event in event_list
                                          if (current_time - event[ek.time_created]) <= ek.one_hour_in_second
                                          ]
                    self.update_detection_events(rule_id=rule,
                                                 alert_source=alert_source,
                                                 events=cleanup_event_list)






