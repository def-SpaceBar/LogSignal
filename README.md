# LogSignal 🚨

**A lightweight, real-time security monitoring system for Windows environments**

LogSignal is a Python-based SIEM tool that monitors Windows Event Logs in real-time, detects security threats using custom rules, and provides a clean dashboard for incident response.


## ✨ Key Features

- **Real-time Monitoring**: Live Windows Event Log monitoring with XML queries
- **Custom Detection Rules**: JSON-based rule engine customized detection functions
- **Whitelist Monitoring**: Allows to keep only events that match the whitelist (based on predefined fields & list of values).
- **Dashboard**: Streamlit dashboard for alert view.
- **SQLite Database**: Lightweight storage for alerts.
- **Multi-Channel Support**: Monitor Security, Sysmon, PowerShell, and custom channels


## 📋 How It Works

LogSignal injects XML queries to the Windows Event Viewer and analyze the retrived logs when a callback occur.

1. **Rule Loading** → Load JSON rules and XML queries from the `rules/` folder
2. **Event Subscription** → Subscribe to Windows Event Log using the loaded XML queries.
3. **Event Parsing* → Parse incoming events on subscription callbacks.
4. **Detection Engine** → Analyze the event array using the assigned detection function.
5. **Alert Creation** → Generate alerts and store in database
6. **Dashboard** → View alerts through web interface
7. **Notification** → Send alerts via webhook/Slack (🚧 coming soon)


## 📁 Project Structure

```
LogSignal/
├── main.py                   # Main monitoring engine
├── config.json               # System configuration
├── ticket_visualizer.py      # Streamlit dashboard
├── db_engine.py              # Database models
├── rules/                    # Detection rules
│   ├── 1000.json             # Rule definition
│   └── 1000.xml              # Event query
├── engines/                  # Core engines          
│   ├── detection_engine.py
│   ├── rule_engine.py
│   └── subscription_manager.py
└── variables/               # Configuration keys
```

## 🚀 Quick Start

### Prerequisites
- Windows OS
- Python 3.8+
- Administrative privileges (for Event Log access)

### Edit Configuration

**`config.json`**
```json
{
  "instance_name": "my-host",
  "channel_monitor": ["Security", "System", "Microsoft-Windows-Sysmon/Operational"], // Validates channel access.
  "case_creation": {
    "webhook": { // DOES NOT SUPPORTED YET, A PLACEHOLDER FOR NEXT UPDATE.
      "url": "https://your-webhook-url.com/alerts",
      "enabled": true
    },
    "slack": { // DOES NOT SUPPORTED YET, A PLACEHOLDER FOR NEXT UPDATE.
      "enabled": true,
      "channels": ["security-alerts", "soc-team"],
      "dm": ["security-lead"]
    }
  }
}
```

### Basic Usage
```bash
# Start the monitoring engine
python main.py

# Launch the dashboard (in another terminal)
streamlit run ticket_visualizer.py
```

## 🔧 Creating Detection Rules
Rules consist of two files: a JSON configuration and an XML query.

### Rule Components

| Field | Description | Example |
|-------|-------------|---------|
| `rule_id` | Unique identifier | `"1000"` |
| `rule_name` | Human-readable name | `"Brute Force Detection"` |
| `alert_source` | Event field to group by | `"subjectusername"` |
| `severity` | Alert priority | `"High"`, `"Medium"`, `"Low"` |
| `engine_instructions` | Detection logic | Counter, time window (🚧 In Development). |

### Detection Engines
**Counter Engine**: Triggers when event count reaches threshold
```json
{
  "engine_name": "counter",
  "count": 5
}
```
**Time Window Engine**: Triggers within specific timeframe -> (🚧 In Development)
```json
{
  "engine_name": "sliding_time_window", 
  "count": 3,
  "time_window": 300
}
```

### Example: Brute Force Detection
**`rules/1000.json`**
```json
{
  "rule_id": "1000",
  "rule_name": "Potential User Bruteforce Activity",
  "rule_description": "Multiple failed login attempts detected",
  "alert_source": "subjectusername",
  "severity": "Medium",
  "engine_instructions": {
    "engine_name": "counter",
    "count": 3,
    "whitelist": { ------> OPTIONAL, ALLOW TO KEEP ONLY CERTAIN EVENTS BASED ON FIELDS DATA FOR TARGETED MONITORING.
      "equals": {"eventid": ["4625"]},
      "contains": {"subjectusername": ["admin", "user"]}
    }
  }
}
```

**`rules/1000.xml`**
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4625)]]
    </Select>
  </Query>
</QueryList>
```
