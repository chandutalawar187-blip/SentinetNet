import streamlit as st
import pandas as pd
import json
import os
from collections import defaultdict
from datetime import datetime

_DIR = os.path.dirname(
    os.path.abspath(
        __file__
    )
)

ALERT_FILE = os.path.join(
    _DIR,
    "..",
    "shared",
    "alerts.json"
)

st.set_page_config(
    page_title="SentinelNet AI",
    layout="wide",
    page_icon="🛡️"
)

alerts = []

try:

    if os.path.exists(
        ALERT_FILE
    ):

        with open(
            ALERT_FILE,
            "r"
        ) as f:

            content = f.read()

            if content.strip():

                alerts = json.loads(
                    content
                )

except Exception as e:

    st.error(
        str(e)
    )

st.title(
    "🛡 SentinelNet AI"
)

st.subheader(
    "REAL-TIME NETWORK INTRUSION DETECTION SYSTEM"
)

if not alerts:

    st.success(
        "✅ No threats detected"
    )

    st.stop()

# LIVE ALERTS

LIVE_WINDOW = 10

now = datetime.now()

live_alerts = []

for a in alerts:

    try:

        t = datetime.fromisoformat(
            a["time"]
        )

        age = (
            now - t
        ).total_seconds()

        if (

            age < LIVE_WINDOW

            and

            a.get(
                "attack"
            ) != "BENIGN"

        ):

            live_alerts.append(
                a
            )

    except:

        pass

latest = None

if live_alerts:

    latest = live_alerts[-1]

# METRICS

total = len(
    alerts
)

active_total = len(
    live_alerts
)

high_count = sum(

    1

    for a in alerts

    if a.get(
        "severity"
    ) == "HIGH"

)

med_count = sum(

    1

    for a in alerts

    if a.get(
        "severity"
    ) == "MEDIUM"

)

low_count = sum(

    1

    for a in alerts

    if a.get(
        "severity"
    ) == "LOW"

)

unique_ips = len(

    set(

        a.get(
            "attacker",
            ""
        )

        for a

        in alerts

    )

)

c1,c2,c3,c4,c5 = st.columns(5)

c1.metric(
    "Threats",
    total
)

c2.metric(
    "High",
    high_count
)

c3.metric(
    "Medium",
    med_count
)

c4.metric(
    "Low",
    low_count
)

c5.metric(
    "Attackers",
    unique_ips
)

st.caption(
    f"Live threats: {active_total}"
)

# ACTIVE ATTACK

st.subheader(
    "🎯 Active Threat Source"
)

if latest is None:

    st.success(
        "✅ No Active Attack"
    )

else:

    latest_sev = latest.get(
        "severity",
        "LOW"
    )

    latest_risk = latest.get(
        "risk_score",
        0
    )

    st.error(
        "🚨 ACTIVE ATTACK"
    )

    cc1,cc2 = st.columns(2)

    with cc1:

        st.write(
            f"🖥 Device: {latest.get('attacker_host','Unknown')}"
        )

        st.write(
            f"🌐 IP: {latest.get('attacker')}"
        )

    with cc2:

        st.write(
            f"🔗 MAC: {latest.get('attacker_mac','Unknown')}"
        )

        st.write(
            f"⚠ Severity: {latest_sev}"
        )

    st.info(
        f"""
Attack:
{latest.get('attack')}

Ports:
{latest.get('ports')}

Risk:
{latest_risk}
"""
    )

    attacked = latest.get(
        "attacked_ports",
        []
    )

    st.warning(

        "⚠ Attacked Ports:\n\n"

        +

        ", ".join(

            map(
                str,
                attacked
            )

        )

    )

# ATTACKERS

st.subheader(
    "🌐 Attacker Activity"
)

rows = []

ip_data = defaultdict(

    lambda:{

        "count":0,

        "severity":"LOW",

        "host":"Unknown",

        "attacks":set()

    }

)

for a in alerts:

    ip = a.get(
        "attacker",
        "UNK"
    )

    ip_data[ip][
        "count"
    ] += 1

    ip_data[ip][
        "host"
    ] = a.get(
        "attacker_host",
        "Unknown"
    )

    ip_data[ip][
        "attacks"
    ].add(

        a.get(
            "attack",
            ""
        )

    )

    ip_data[ip][
        "severity"
    ] = a.get(
        "severity",
        "LOW"
    )

for ip,data in ip_data.items():

    rows.append({

        "Device":
        data["host"],

        "IP":
        ip,

        "Events":
        data["count"],

        "Severity":
        data["severity"],

        "Attack":
        ",".join(
            data["attacks"]
        )

    })

feed = pd.DataFrame(
    rows
)

st.dataframe(
    feed,
    use_container_width=True
)

# HISTORY

st.subheader(
    "📋 History"
)

history = pd.DataFrame(
    alerts
)

st.dataframe(
    history,
    use_container_width=True
)

if st.button(
    "💾 Export Report"
):

    history.to_csv(
        "report.csv",
        index=False
    )

    st.success(
        "Report saved"
    )

import time
time.sleep(2)
st.rerun()