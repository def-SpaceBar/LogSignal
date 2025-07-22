# USED WHEN EVER NEEDED TO ACCESS JSON KEYS OF RULES
# Those variables represents the JSON key names thats being used and should exist
# within each monitoring rule JSON file.
alert_source_key: str = 'alert_source'
rule_id_key: str = 'rule_id'
rule_name_key: str = 'rule_name'
rule_severity_key: str = 'severity'
rule_description_key: str = 'rule_description'
rule_xml_key: str = 'rule_xml'
subscription_channel_key: str = 'subscription_channel'
engine_instructions_key: str = 'engine_instructions'
engine_name_key: str = 'engine_name'
cleanup_rules_key: str = 'whitelist'
cleanup_time: str = 'cleanup_time'



#### detection_engines ####
event_count_key: str = 'count'
time_window: str = 'time_window'
