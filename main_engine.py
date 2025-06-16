from LogSignal.engines.subscription_manager import SubscriptionManager
from LogSignal.engines.detection_engine import DetectionEngine
from LogSignal.engines.rule_engine import RuleEngine

class Engine:
    def __init__(self):
        self.sub_manager = SubscriptionManager()
        self.detection_engine = DetectionEngine()
        self.rule_engine = RuleEngine()
        self.database = None
        self.db_cursor = None
