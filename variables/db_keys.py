# class alert_object(Base):
#     __tablename__ = "alerts"
#     id = Column(Integer, primary_key=True)
#     status = Column(String, default="New")
#     endpoint_name = Column(String, default='localhost')
#     severity = Column(String, default='Medium')
#     time_created = Column(String)
#     rule_name = Column(String)
#     rule_id = Column(String)
#     alert_source = Column(String)
#     rule_description = Column(Text)
#     files = Column(JSON)

# USED TO MAP & ACCESS ALERT OBJECT NAMES

alert_id = 'id'
alert_status = 'status'
origin_endpoint = 'endpoint_name'
alert_severity = 'severity'
time_created = 'time_created'
alert_rule_name = 'rule_name'
alert_rule_id = 'rule_id'
alert_source_field = 'alert_source'
alert_rule_desc = 'rule_description'
alert_files = 'files'
alert_event_id = 'event_id'
