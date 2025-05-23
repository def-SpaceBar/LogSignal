import xml
from collections import defaultdict

class RuleEngine:

    def __init__(self):

        self.rules = None
        self.rules_folder = None

    def load_xml(self, rule_id: str) -> xml:
        try:
            with open(self.rules_folder + "\\" + f"{rule_id}" + ".xml") as rule_xml:
                return rule_xml.read()
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Could not find the rule XML file. {rule_id}")
