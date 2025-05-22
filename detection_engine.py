import win32evtlog as evt
import win32file
from typing import Dict, List
import json
from collections import defaultdict


class SubscriptionManager:
    def __init__(self):
        self.sub_map = defaultdict(dict)

    def register_sub(self, subscription: Dict) -> None:
        self.sub_map.update(subscription)
    @staticmethod
    def start_sub(channel, state, query):
        subscription = evt.EvtSubscribe(channel, state, None, query, None)
        return subscription


class DetectionEngine:

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
            except Exception as e:
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
