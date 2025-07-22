import time
from datetime import datetime
import win32evtlog as evt
import win32file
import json
from collections import defaultdict
import threading
from LogSignal.variables import rule_keys as rk
from LogSignal.variables import event_keys as ek
from LogSignal.db_engine import db_session, alert_object

debug_state = False


def _write_alerts_to_db_(rule_name,
                         rule_id,
                         alert_source,
                         rule_description,
                         raw_events,
                         time_created=time.strftime("%Y-%m-%d %H:%M:%S"),
                         files=None,
                         endpoint='localhost',
                         severity='Unknown'):
    if files is None:
        files = []

    event_ids = [raw_event[ek.event_id] for raw_event in raw_events]
    event_ids = list(set(event_ids))
    db_session.add(
        alert_object(
            status="New",
            endpoint_name=endpoint,
            severity=severity,
            time_created=time_created,
            rule_name=rule_name,
            rule_id=rule_id,
            alert_source=alert_source,
            rule_description=rule_description,
            files=files,
            event_id=event_ids,
            raw_events=raw_events
        )
    )
    db_session.commit()


def sliding_time_window(events: list, engine_instructions: dict):
    count = engine_instructions.get(rk.event_count_key, 3)
    time_window = engine_instructions.get(rk.time_window, 0)
    detections = []
    left_over_events = events
    return detections, left_over_events


def counter_detection_engine(events: list, engine_instructions: dict):
    # print('i was here')
    count = engine_instructions.get(rk.event_count_key, 3)

    if len(events) >= count:  # ← correct comparison
        return events, []  # signal that the bucket is now empty
    else:
        return [], events  # keep waiting, leave events untouched


def event_cleanup_check(event: dict, cleanup_rules_dict: dict, rule_id, valid_events=None):
    for field, allowed in cleanup_rules_dict.get("equals", {}).items():
        if event.get(field) not in allowed:
            return False

    for field, substrings in cleanup_rules_dict.get("contains", {}).items():
        value = event.get(field, "")
        if not isinstance(value, str):
            return False  # field missing or not a string → fail
        if not any(sub in value for sub in substrings):
            return False

    return True


class DetectionEngine:

    def __init__(self):
        self.detection_map = defaultdict(lambda: defaultdict(list))
        self.parse_fields = None
        self._lock = threading.RLock()
        self.parsed_events_keys = set()
        self.parsed_events_keys_by_rule_id = defaultdict(frozenset)
        self.alerts = []

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

    def print_parsed_event_keys(self):
        return print(self.parsed_events_keys)

    @staticmethod
    def sort_events_by_time(events: list):
        return events.sort(key=lambda x: x[ek.time_created])

    @staticmethod
    def parse_event(event: dict) -> dict:

        event = event[ek.main_event_key]

        def handle_Provider(val: dict) -> dict:
            return {ek.provider: f"{val[ek.at_sign_name_selector]}",
                    ek.provider_guid: f"{val[ek.at_sign_guid_selector]}"}

        def handle_TimeCreated(val: dict) -> dict:
            date_and_time, fraction_seconds = val[ek.time_created_selector].split('.')
            dt_object = f"{date_and_time}.{fraction_seconds.replace('z', '')[:6]}+00:00"
            dt_object = datetime.fromisoformat(dt_object)
            timestamp = dt_object.timestamp()
            return {ek.time_created: int(timestamp)}

        def handle_Execution(val: dict) -> dict:
            return {ek.process_id: f"{val[ek.process_id_selector]}", ek.thread_id: f"{val[ek.thread_id_selector]}"}

        def handle_Security(val: dict) -> dict:
            return {ek.user_sid: f"{val[ek.user_sid_selector]}"}

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
        with self._lock:
            self.detection_map[rule_id][offense_source_value].append(event)

    def extend_event_to_map(self, rule_id, offense_source_value, event) -> None:
        with self._lock:
            self.detection_map[rule_id][offense_source_value].extend(event)

    def event_error_handler(self, rule_id: str | None, error_message: str, event: dict, error_key='errors') -> None:
        rule_id = rule_id if rule_id is not None else 'unknown'
        event.update({'error_message': error_message})
        with self._lock:
            self.detection_map[error_key][rule_id].append(event)

    def update_detection_events(self, rule_id: str, alert_source: str, events: list):
        with self._lock:
            self.detection_map[rule_id][alert_source] = events

    def event_handler(self, event: dict, rule: dict) -> append_event_to_map or event_error_handler:
        parsed_event = self.parse_event(event)
        print(parsed_event)
        self.parsed_events_keys = self.parsed_events_keys | set(parsed_event.keys())

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

    def run_engine(self, engine_instructions: dict, events: list, rule_id: str):
        engines_map = {
            "counter": counter_detection_engine
        }
        engine_func = engine_instructions.get(rk.engine_name_key, '')
        engine_func = engines_map.get(engine_func, None)
        if engine_func:
            return engine_func(events=events, engine_instructions=engine_instructions)
        else:
            self.event_error_handler(rule_id=rule_id,
                                     error_message='failed to find engine function',
                                     event={"operation": "run_engine"})
            return None, None

    def process_detection_map(self, rule_engine_object):
        with self._lock:
            current_time = time.time()
            detection_map = self.detection_map
            rules = rule_engine_object.rules
            # print(detection_map.items())
            for rule, detections in list(detection_map.items()):
                if rule == 'errors':
                    continue
                # get the rule instructions
                rule_data = rules.get(rule, None)
                engine_instructions = rule_data.get(rk.engine_instructions_key, None)
                # check if we have all needed data
                if rule_data is None:
                    print(f"process_detection_map Error | Rule {rule} | Could not find rule instructions")
                elif engine_instructions is None:
                    print(f"process_detection_map Error | Rule {rule} | Could not find engine instructions")
                if rule_data and engine_instructions:
                    pass
                else:
                    continue

                event_cleanup_rules = engine_instructions.get(rk.cleanup_rules_key, None)

                for alert_source, event_list in detections.items():
                    if event_list:
                        if event_cleanup_rules:
                            clean_events = [event for event in event_list
                                                              if event_cleanup_check(event=event,
                                                                                     cleanup_rules_dict=event_cleanup_rules,
                                                                                     rule_id=rule)
                                                              and (current_time - event[
                                    ek.time_created]) <= ek.one_hour_in_second]

                        else:
                            clean_events = [event for event in event_list
                                                   if (current_time - event[ek.time_created]) <= ek.one_hour_in_second
                                                   ]

                        generated_detections, left_over_events = self.run_engine(
                            engine_instructions=engine_instructions,
                            events=clean_events,
                            rule_id=rule)

                        if generated_detections:
                            try:
                                _write_alerts_to_db_(rule_name=rule_data.get(rk.rule_name_key, f'Unknown Rule - id {rule}'),
                                                     rule_id=rule,
                                                     alert_source=alert_source,
                                                     rule_description=rule_data.get(rk.rule_description_key, 'Could not get description'),
                                                     raw_events=generated_detections,
                                                     severity=rule_data.get(rk.rule_severity_key, None))
                                self.update_detection_events(rule_id=rule, alert_source=alert_source, events=left_over_events)
                            except TypeError:
                                print(f"process_detection_map Error | Rule_ID: {rule}")
        print(detection_map)
