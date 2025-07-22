from .detection_engine import DetectionEngine
import win32evtlog as evt
from typing import Dict
from collections import defaultdict
import xmltodict


class SubscriptionManager:
    def __init__(self):
        self.sub_map = defaultdict(dict)

    def register_sub(self, subscription: Dict) -> None:
        self.sub_map.update(subscription)

    @staticmethod
    def on_event(action, context, event_handle):
        if action == evt.EvtSubscribeActionDeliver:
            event = evt.EvtRender(event_handle, 1)
            event = xmltodict.parse(event)
            detection_engine_obj = context['detection_engine']
            # Process Detected Event
            detection_engine_obj.event_handler(event=event, rule=context)
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
