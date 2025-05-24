import inspect

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

    def get_sub_data(self, subscription):
        return self.sub_map

    @staticmethod
    def on_event(action, context, event_handle):
        print(context)
        if action == evt.EvtSubscribeActionDeliver:
            event = evt.EvtRender(event_handle, 1)
            event = str(xmltodict.parse(event)).replace('null', "")
            print(json.dumps(event, indent=4))
        return 0

    @staticmethod
    def start_sub(channel: str, query: str, sub_map_as_context: object):
        subscription = evt.EvtSubscribe(
            channel,  # Channel path
            evt.EvtSubscribeToFutureEvents,  # Flags
            Query=query,  # XML query
            Callback=SubscriptionManager.on_event,  # Callback function (async)
            Context=sub_map_as_context  # Context to pass to callback
        )
        return subscription
