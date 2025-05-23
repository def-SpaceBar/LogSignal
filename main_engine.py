from subscription_manager import SubscriptionManager
from detection_engine import  DetectionEngine
from rule_engine import RuleEngine

class Engine:
    def __init__(self):
        self.SM = SubscriptionManager()
        self.DE = DetectionEngine()
        self.RE = RuleEngine()