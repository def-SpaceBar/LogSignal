from subscription_manager import SubscriptionManager
from detection_engine import DetectionEngine
from rule_engine import RuleEngine


class Engine:
    def __init__(self):
        self.sub_manager = SubscriptionManager()
        self.detection_engine = DetectionEngine()
        self.rule_engine = RuleEngine()
