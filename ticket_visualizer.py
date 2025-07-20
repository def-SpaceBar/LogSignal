import time

import streamlit as st
import pandas as pd
from sqlalchemy import select
from st_aggrid import AgGrid, GridOptionsBuilder, GridUpdateMode
from db_engine import db_engine, alert_object



st.set_page_config(page_title="Lite SOAR Dashboard", layout="wide")

# fixed-width sidebar CSS (keep if you like)
st.markdown("""
<style>
[data-testid="stSidebar"]{width:350px!important;}
[data-testid="stSidebar"]>div:first-child{width:350px!important;}
</style>
""", unsafe_allow_html=True)



alert_dialog_fn = st.experimental_dialog("Event-ID Enrichment")


def render_alert_dialog():
    alert = st.session_state.get("dlg_alert")
    if not alert:
        st.write("No alert selected.")
        return

    st.subheader(f"Rule ID : {alert['rule_id']}")
    st.markdown(f"**Rule Name:** {alert['rule_name']}")
    st.markdown(f"**Severity :** {alert['severity']}")
    st.markdown("**Event IDs:**")
    st.code(", ".join(map(str, alert["event_id"])) or "None")

    if st.button("Close"):
        alert_dialog_fn.close()



def open_event_dialog(row_dict):
    st.session_state["dlg_alert"] = row_dict
    alert_dialog_fn(render_alert_dialog)


def load_alerts():
    return pd.read_sql(select(alert_object), db_engine)

st.title("🚨 Lite SOAR Dashboard")


alerts_df = load_alerts()
if alerts_df.empty:
    st.warning("No alerts found in the database.")
    st.stop()

gb = GridOptionsBuilder.from_dataframe(alerts_df)
gb.configure_selection("single", use_checkbox=False)
gb.configure_default_column(resizable=True, sortable=True, filter=True)

grid_response = AgGrid(
    alerts_df,
    gridOptions=gb.build(),
    height=450,
    theme="streamlit",
    update_mode=GridUpdateMode.SELECTION_CHANGED,
    fit_columns_on_grid_load=True,
)

sel_raw = grid_response.get("selected_rows")
row = None
if isinstance(sel_raw, list) and sel_raw and isinstance(sel_raw[0], dict):
    row = sel_raw[0]
elif hasattr(sel_raw, "to_dict") and not sel_raw.empty:
    row = sel_raw.iloc[0].to_dict()


if row:
    with st.sidebar:

        st.header("🔍 Alert Details")
        st.markdown(f"**ID:** {row['id']}")
        st.markdown(f"**Status:** {row['status']}")
        st.markdown(f"**Endpoint:** {row['endpoint_name']}")
        st.markdown(f"**Severity:** {row['severity']}")
        st.markdown(f"**Time Created:** {row['time_created']}")
        st.markdown(f"**Rule Name:** {row['rule_name']}")
        st.markdown(f"**Rule ID:** {row['rule_id']}")
        if row.get("alert_source"):
            st.markdown(f"**Source:** {row['alert_source']}")
        if row.get("rule_description"):
            st.markdown(f"**Description:** {row['rule_description']}")

        if isinstance(row.get("files"), list) and row["files"]:
            st.markdown("**📂 Related Files:**")
            for file in row["files"]:
                st.code(file)

        if isinstance(row.get("event_id"), list) and row["event_id"]:
            st.markdown("**🔗 Event IDs:**")
            st.code(", ".join(map(str, row["event_id"])))
