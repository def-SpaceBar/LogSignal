import inspect
from detection_engine import DetectionEngine
import win32evtlog as evt
from typing import Dict, List
import json
from collections import defaultdict
import threading
import xmltodict


class SubscriptionManager:
    def __init__(self):
        self.sub_map = defaultdict(dict)

    def register_sub(self, subscription: Dict) -> None:
        self.sub_map.update(subscription)

    # def get_sub_data(self, subscription):
    #     with self.lock_thread_access:
    #         return self.sub_map

    @staticmethod
    def on_event(action, context, event_handle):
        detection_object = context["detection_engine"]
        parser_list: list = context["parser"]
        if action == evt.EvtSubscribeActionDeliver:
            event = evt.EvtRender(event_handle, 1)
            event = xmltodict.parse(event)
            # event = DetectionEngine.event_parser(parser_list, event)
            detection_object.analyzer(event)

        return 0

    @staticmethod
    def start_sub(channel: str, query: str, context: object):
        subscription = evt.EvtSubscribe(
            channel,  # Channel path
            evt.EvtSubscribeToFutureEvents,  # Flags
            Query=query,  # XML query
            Callback=SubscriptionManager.on_event,  # Callback function (async)
            Context=context  # Context to pass to callback
        )
        return subscription
