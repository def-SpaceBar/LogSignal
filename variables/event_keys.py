##### WINDOWS EVENT JSON KEYS
main_event_key: str = 'Event'
system_dict_key: str = 'System'
event_data_dict: str = 'EventData'
data_key: str = 'Data'
process_id: str = 'processid'
process_id_selector: str = '@ProcessID'
thread_id: str = 'threadid'
thread_id_selector: str = '@ThreadID'
user_sid: str = 'usersid'
user_sid_selector: str = '@UserID'
time_created: str = 'timecreated'
time_created_selector: str = '@SystemTime'
provider: str = 'provider'
provider_guid: str = 'providerguid'
at_sign_name_selector: str = '@Name'
at_sign_guid_selector: str = '@Guid'
hashtag_text_selector: str = '#text'
event_id: str = 'eventid'

###################################


##### PARSING EVENT JSON KEYS
errors_key: str = 'errors'
custom_parsing_error: str = 'custom_parser_not_found'

#### cleanup time (if older than configured will be deleted)
one_hour_in_second: int = 3600
