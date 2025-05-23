import xml
from collections import defaultdict

class RuleEngine:
    def __init__(self, imported_rules, _rules_folder):
        __rules__ = defaultdict(str)
        for rule in imported_rules:
            __rules__[rule["id"]] = rule
        self.rules = __rules__
        self._rules_folder = _rules_folder

    def load_xml(self, rule_id: str) -> xml:
        try:
            with open(self._rules_folder + "\\" + f"{rule_id}" + ".xml") as rule_xml:
                return rule_xml.read()
        except FileNotFoundError as e:
            raise FileNotFoundError(f"Could not find the rule XML file. {rule_id}")
