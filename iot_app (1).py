import streamlit as st
import plotly.graph_objects as go
import pandas as pd
import numpy as np
import random

st.set_page_config(
    page_title="IIoT Security Audit Tool",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Orbitron:wght@400;700;900&family=Rajdhani:wght@400;600;700&display=swap');

.stApp { background: linear-gradient(135deg, #020812 0%, #050F1E 50%, #071224 100%); color: #E0F0FF; }
[data-testid="stSidebar"] { background: linear-gradient(180deg, #020812 0%, #050F1E 100%); border-right: 1px solid #00AAFF44; }

.main-title { font-family: 'Orbitron', monospace; font-size: 2.2rem; font-weight: 900;
    background: linear-gradient(90deg, #00AAFF, #00FFCC, #00AAFF);
    -webkit-background-clip: text; -webkit-text-fill-color: transparent;
    text-align: center; letter-spacing: 3px; padding-top: 10px; }

.sub-title { font-family: 'Rajdhani', sans-serif; font-size: 1rem; color: #4488AA;
    text-align: center; letter-spacing: 4px; margin-bottom: 20px; }

.section-header { font-family: 'Orbitron', monospace; font-size: 0.85rem; color: #00AAFF;
    letter-spacing: 3px; border-left: 3px solid #00AAFF; padding-left: 10px;
    margin: 18px 0 12px 0; text-transform: uppercase; }

.metric-card { background: linear-gradient(135deg, #050F1E, #071830);
    border: 1px solid #00AAFF33; border-radius: 10px; padding: 16px;
    text-align: center; box-shadow: 0 4px 20px rgba(0,170,255,0.08); }

.metric-value { font-family: 'Orbitron', monospace; font-size: 1.8rem; font-weight: 700; color: #00AAFF; }
.metric-label { font-family: 'Rajdhani', sans-serif; font-size: 0.8rem; color: #4488AA;
    letter-spacing: 2px; text-transform: uppercase; }

.alert-critical { background: linear-gradient(135deg, #1A0505, #2A0808);
    border: 1px solid #FF2222; border-left: 4px solid #FF2222; border-radius: 8px;
    padding: 12px 16px; margin: 6px 0; color: #FF6666; font-size: 0.9rem; }

.alert-warning { background: linear-gradient(135deg, #1A1205, #2A1E08);
    border: 1px solid #FFAA00; border-left: 4px solid #FFAA00; border-radius: 8px;
    padding: 12px 16px; margin: 6px 0; color: #FFCC44; font-size: 0.9rem; }

.alert-safe { background: linear-gradient(135deg, #051A0A, #082A10);
    border: 1px solid #00FF88; border-left: 4px solid #00FF88; border-radius: 8px;
    padding: 12px 16px; margin: 6px 0; color: #44FFAA; font-size: 0.9rem; }

.info-box { background: rgba(0,170,255,0.05); border: 1px solid #00AAFF33; border-radius: 8px;
    padding: 14px 18px; margin: 10px 0; font-family: 'Rajdhani', sans-serif;
    font-size: 0.95rem; color: #88CCEE; }

.team-card { background: linear-gradient(135deg, #050F1E, #020812);
    border: 1px solid #00AAFF22; border-radius: 8px; padding: 10px 14px; margin: 5px 0; }

.cyber-divider { border: none; height: 1px;
    background: linear-gradient(90deg, transparent, #00AAFF, transparent); margin: 20px 0; }

.stTabs [data-baseweb="tab-list"] { background: #020812; border-radius: 10px;
    padding: 4px; border: 1px solid #00AAFF22; }
.stTabs [data-baseweb="tab"] { background: transparent; color: #4488AA;
    font-family: 'Orbitron', monospace; font-size: 0.75rem; border-radius: 8px; }
.stTabs [aria-selected="true"] { background: linear-gradient(135deg, #071830, #0A2040) !important;
    color: #00AAFF !important; border: 1px solid #00AAFF !important; }

.stButton > button { background: linear-gradient(135deg, #071830, #0A2040);
    color: #00AAFF; border: 1px solid #00AAFF; border-radius: 8px;
    font-family: 'Orbitron', monospace; font-size: 0.85rem; letter-spacing: 2px;
    padding: 10px 28px; }
.stButton > button:hover { box-shadow: 0 0 20px rgba(0,170,255,0.3); }

label { font-family: 'Rajdhani', sans-serif !important; color: #4488AA !important; }
.stNumberInput input { background: #050F1E !important; border: 1px solid #00AAFF33 !important; color: #00AAFF !important; }
.stTextInput input { background: #050F1E !important; border: 1px solid #00AAFF33 !important; color: #00AAFF !important; }
.stSelectbox > div > div { background: #050F1E !important; border: 1px solid #00AAFF33 !important; color: #00AAFF !important; }

#MainMenu {visibility: hidden;} footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ── DATA ─────────────────────────────────────────────────────────────────────
TEAM = [
    ("Muhammad Sameer", "25-ME-151"),
    ("Shabaz Malik",    "25-ME-155"),
    ("Zain Abbas",      "25-ME-159"),
]

VULNERABILITIES = {
    "Default Credentials":         {"severity": "CRITICAL", "cvss": 9.8, "desc": "Device using factory default username/password"},
    "Unencrypted Communication":   {"severity": "CRITICAL", "cvss": 9.1, "desc": "Data transmitted without TLS/SSL encryption"},
    "Outdated Firmware":           {"severity": "HIGH",     "cvss": 7.5, "desc": "Firmware version has known CVEs"},
    "Open Telnet Port":            {"severity": "HIGH",     "cvss": 7.2, "desc": "Insecure Telnet service is running"},
    "No Authentication":           {"severity": "CRITICAL", "cvss": 9.5, "desc": "Device API accessible without authentication"},
    "Weak Password Policy":        {"severity": "HIGH",     "cvss": 6.8, "desc": "No password complexity requirements enforced"},
    "Unnecessary Open Ports":      {"severity": "MEDIUM",   "cvss": 5.3, "desc": "Multiple unused ports are open"},
    "No Firewall Rules":           {"severity": "HIGH",     "cvss": 7.0, "desc": "No network filtering or access control"},
    "Insecure MQTT Broker":        {"severity": "CRITICAL", "cvss": 8.9, "desc": "MQTT broker has no authentication"},
    "Missing Security Patches":    {"severity": "HIGH",     "cvss": 7.8, "desc": "Critical OS patches not applied"},
    "Hardcoded API Keys":          {"severity": "MEDIUM",   "cvss": 6.5, "desc": "API credentials embedded in source code"},
    "No Audit Logging":            {"severity": "MEDIUM",   "cvss": 5.0, "desc": "Security events not being logged"},
}

DEVICE_TYPES = ["PLC (Programmable Logic Controller)", "SCADA Gateway", "Industrial Sensor Node",
                "HMI Terminal", "Industrial Router", "Smart Meter", "RTU (Remote Terminal Unit)", "Industrial Camera"]

PROTOCOLS = ["MQTT", "Modbus TCP", "OPC-UA", "DNP3", "PROFINET", "EtherNet/IP", "BACnet", "CoAP"]

PLOT_CFG = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(5,15,30,0.8)",
    font=dict(color="#4488AA", family="Arial"),
    title_font=dict(color="#00AAFF", size=14, family="Arial"),
)

# ── SIDEBAR ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown('<div class="section-header">Audit Configuration</div>', unsafe_allow_html=True)
    facility_name = st.text_input("Facility / Plant Name", value="UET Taxila Industrial Plant")
    industry_type = st.selectbox("Industry Type", ["Manufacturing", "Power Generation", "Oil & Gas", "Water Treatment", "Chemical Plant", "Automotive"])
    st.markdown('<hr class="cyber-divider">', unsafe_allow_html=True)
    st.markdown('<div class="section-header">Group 7 — Team</div>', unsafe_allow_html=True)
    for name, reg in TEAM:
        st.markdown(f"""<div class="team-card">
            <span style="color:#AACCEE;font-weight:600;">shield {name}</span><br>
            <span style="color:#00AAFF;font-size:0.82rem;">{reg}</span>
        </div>""", unsafe_allow_html=True)
    st.markdown('<hr class="cyber-divider">', unsafe_allow_html=True)
    st.markdown('<div style="color:#224466;font-size:0.78rem;text-align:center;">ICT for Cybersecurity<br>Mechanical Engineering<br>UET Taxila 2025</div>', unsafe_allow_html=True)

# ── HEADER ───────────────────────────────────────────────────────────────────
st.markdown('<div class="main-title">IIoT SECURITY AUDIT TOOL</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-title">INDUSTRIAL INTERNET OF THINGS — CYBERSECURITY MONITORING SYSTEM</div>', unsafe_allow_html=True)
st.markdown('<hr class="cyber-divider">', unsafe_allow_html=True)

# ── TABS ─────────────────────────────────────────────────────────────────────
tab1, tab2, tab3, tab4, tab5 = st.tabs([
    "DEVICE SCANNER",
    "VULNERABILITY AUDIT",
    "NETWORK MONITOR",
    "RISK DASHBOARD",
    "ABOUT",
])

# ════════════════════════════════════════════════════════════════════════════
# TAB 1 — DEVICE SCANNER
# ════════════════════════════════════════════════════════════════════════════
with tab1:
    st.markdown('<div class="section-header">IIoT Device Scanner</div>', unsafe_allow_html=True)
    st.markdown('<div class="info-box">Register your industrial IoT devices. The system will scan each device for security vulnerabilities and misconfigurations.</div>', unsafe_allow_html=True)

    col1, col2, col3 = st.columns(3)
    with col1:
        device_name = st.text_input("Device Name / ID", value="PLC-001")
        device_type = st.selectbox("Device Type", DEVICE_TYPES)
    with col2:
        ip_address = st.text_input("IP Address", value="192.168.1.10")
        protocol   = st.selectbox("Protocol", PROTOCOLS)
    with col3:
        firmware = st.text_input("Firmware Version", value="v1.2.3")
        location = st.text_input("Physical Location", value="Workshop Floor A")

    st.markdown('<div class="section-header">Security Configuration</div>', unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        auth_enabled     = st.checkbox("Authentication Enabled", value=False)
        encryption_on    = st.checkbox("Encryption (TLS/SSL)",   value=False)
        default_creds    = st.checkbox("Default Credentials Changed", value=False)
    with c2:
        firewall_active  = st.checkbox("Firewall Active",         value=False)
        firmware_updated = st.checkbox("Firmware Up-to-Date",     value=False)
        logging_on       = st.checkbox("Audit Logging Enabled",   value=False)
    with c3:
        open_ports = st.multiselect("Open Ports",
            ["22 SSH", "23 Telnet", "80 HTTP", "443 HTTPS", "502 Modbus", "1883 MQTT", "8080 HTTP-Alt"],
            default=["23 Telnet", "1883 MQTT", "80 HTTP"])

    st.markdown('<hr class="cyber-divider">', unsafe_allow_html=True)

    if st.button("SCAN DEVICE", use_container_width=True):
        issues = []
        if not auth_enabled:    issues.append(("CRITICAL", "No Authentication",         "Device has no authentication — anyone can access it!"))
        if not encryption_on:   issues.append(("CRITICAL", "Unencrypted Communication", "Data sent without encryption — vulnerable to interception!"))
        if not default_creds:   issues.append(("CRITICAL", "Default Credentials",       "Factory passwords not changed — easy target for attackers!"))
        if not firewall_active: issues.append(("HIGH",     "No Firewall Rules",         "No network filtering — device exposed to all traffic!"))
        if not firmware_updated:issues.append(("HIGH",     "Outdated Firmware",         "Running old firmware with known security vulnerabilities!"))
        if not logging_on:      issues.append(("MEDIUM",   "No Audit Logging",          "Security events not being recorded!"))
        if "23 Telnet" in open_ports: issues.append(("HIGH", "Open Telnet Port",        "Telnet is insecure — use SSH instead!"))
        if "1883 MQTT" in open_ports and not auth_enabled:
            issues.append(("CRITICAL", "Insecure MQTT Broker", "MQTT running without authentication!"))
        if len(open_ports) > 4: issues.append(("MEDIUM",   "Too Many Open Ports",      f"{len(open_ports)} ports open — minimize attack surface!"))

        score = 100
        for sev, _, _ in issues:
            if sev == "CRITICAL": score -= 25
            elif sev == "HIGH":   score -= 15
            elif sev == "MEDIUM": score -= 8
        score = max(0, score)

        color = "#00FF88" if score >= 70 else ("#FFAA00" if score >= 40 else "#FF2222")
        label = "SECURE" if score >= 70 else ("MODERATE RISK" if score >= 40 else "HIGH RISK")

        st.markdown('<div class="section-header">Scan Results</div>', unsafe_allow_html=True)
        r1, r2, r3, r4 = st.columns(4)
        with r1: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:{color}">{score}</div><div class="metric-label">Security Score</div></div>', unsafe_allow_html=True)
        with r2:
            critical = sum(1 for s, _, _ in issues if s == "CRITICAL")
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#FF2222">{critical}</div><div class="metric-label">Critical Issues</div></div>', unsafe_allow_html=True)
        with r3:
            high = sum(1 for s, _, _ in issues if s == "HIGH")
            st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#FFAA00">{high}</div><div class="metric-label">High Issues</div></div>', unsafe_allow_html=True)
        with r4: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:{color}">{label}</div><div class="metric-label">Risk Level</div></div>', unsafe_allow_html=True)

        st.markdown('<div class="section-header">Issues Found</div>', unsafe_allow_html=True)
        if not issues:
            st.markdown('<div class="alert-safe">No issues found — Device is properly secured!</div>', unsafe_allow_html=True)
        for sev, title, desc in issues:
            cls  = "alert-critical" if sev == "CRITICAL" else ("alert-warning" if sev == "HIGH" else "alert-safe")
            icon = "CRITICAL" if sev == "CRITICAL" else ("HIGH" if sev == "HIGH" else "MEDIUM")
            st.markdown(f'<div class="{cls}">[{icon}] {title} — {desc}</div>', unsafe_allow_html=True)

        st.session_state["last_scan"] = {"device": device_name, "score": score, "issues": issues, "label": label}

# ════════════════════════════════════════════════════════════════════════════
# TAB 2 — VULNERABILITY AUDIT
# ════════════════════════════════════════════════════════════════════════════
with tab2:
    st.markdown('<div class="section-header">Vulnerability Database Checker</div>', unsafe_allow_html=True)
    st.markdown('<div class="info-box">Select vulnerabilities found in your IIoT network. The tool calculates risk score and generates a remediation plan.</div>', unsafe_allow_html=True)

    selected_vulns = []
    vuln_list = list(VULNERABILITIES.keys())
    col_v1, col_v2 = st.columns(2)
    with col_v1:
        for vuln in vuln_list[:6]:
            sev = VULNERABILITIES[vuln]["severity"]
            tag = "[CRITICAL]" if sev == "CRITICAL" else "[HIGH]" if sev == "HIGH" else "[MEDIUM]"
            if st.checkbox(f"{tag} {vuln}", key=f"v_{vuln}"):
                selected_vulns.append(vuln)
    with col_v2:
        for vuln in vuln_list[6:]:
            sev = VULNERABILITIES[vuln]["severity"]
            tag = "[CRITICAL]" if sev == "CRITICAL" else "[HIGH]" if sev == "HIGH" else "[MEDIUM]"
            if st.checkbox(f"{tag} {vuln}", key=f"v2_{vuln}"):
                selected_vulns.append(vuln)

    st.markdown('<hr class="cyber-divider">', unsafe_allow_html=True)
    if st.button("GENERATE AUDIT REPORT", use_container_width=True):
        if not selected_vulns:
            st.markdown('<div class="alert-safe">No vulnerabilities selected — Network appears secure!</div>', unsafe_allow_html=True)
        else:
            avg_cvss      = np.mean([VULNERABILITIES[v]["cvss"] for v in selected_vulns])
            critical_count = sum(1 for v in selected_vulns if VULNERABILITIES[v]["severity"] == "CRITICAL")
            high_count     = sum(1 for v in selected_vulns if VULNERABILITIES[v]["severity"] == "HIGH")

            a1, a2, a3 = st.columns(3)
            with a1: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#FF2222">{avg_cvss:.1f}</div><div class="metric-label">Avg CVSS Score</div></div>', unsafe_allow_html=True)
            with a2: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#FF2222">{critical_count}</div><div class="metric-label">Critical CVEs</div></div>', unsafe_allow_html=True)
            with a3: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#FFAA00">{high_count}</div><div class="metric-label">High Severity</div></div>', unsafe_allow_html=True)

            fig = go.Figure(go.Bar(
                x=selected_vulns,
                y=[VULNERABILITIES[v]["cvss"] for v in selected_vulns],
                marker_color=["#FF2222" if VULNERABILITIES[v]["severity"] == "CRITICAL" else "#FFAA00" if VULNERABILITIES[v]["severity"] == "HIGH" else "#00AAFF" for v in selected_vulns],
                text=[str(VULNERABILITIES[v]["cvss"]) for v in selected_vulns],
                textposition="outside",
            ))
            fig.update_layout(**PLOT_CFG, title="CVSS Scores by Vulnerability",
                xaxis=dict(tickangle=-30, gridcolor="#071830", color="#4488AA"),
                yaxis=dict(range=[0, 10.5], title="CVSS Score", gridcolor="#071830", color="#4488AA"), height=350)
            st.plotly_chart(fig, use_container_width=True)

            fixes = {
                "Default Credentials":       "Immediately change all default passwords. Use strong passwords with min 12 chars.",
                "Unencrypted Communication": "Enable TLS 1.3 on all communications. Use VPN for remote access.",
                "Outdated Firmware":         "Update firmware to latest version. Enable automatic security patch alerts.",
                "Open Telnet Port":          "Disable Telnet (port 23). Replace with SSH (port 22) for secure access.",
                "No Authentication":         "Implement multi-factor authentication (MFA) on all devices.",
                "Weak Password Policy":      "Enforce password complexity. Implement account lockout after failed attempts.",
                "Unnecessary Open Ports":    "Close all unused ports. Apply whitelist-only access control.",
                "No Firewall Rules":         "Deploy industrial firewall. Implement zero-trust network architecture.",
                "Insecure MQTT Broker":      "Enable MQTT authentication. Use MQTTS (port 8883) with TLS.",
                "Missing Security Patches":  "Apply critical patches within 72 hours of release.",
                "Hardcoded API Keys":        "Remove hardcoded credentials. Use environment variables instead.",
                "No Audit Logging":          "Enable SIEM logging. Store logs for minimum 90 days.",
            }
            st.markdown('<div class="section-header">Remediation Plan</div>', unsafe_allow_html=True)
            for vuln in selected_vulns:
                sev = VULNERABILITIES[vuln]["severity"]
                cls = "alert-critical" if sev == "CRITICAL" else "alert-warning"
                st.markdown(f'<div class="{cls}"><b>{vuln}</b> (CVSS: {VULNERABILITIES[vuln]["cvss"]})<br>{fixes.get(vuln, "Apply security best practices.")}</div>', unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# TAB 3 — NETWORK MONITOR
# ════════════════════════════════════════════════════════════════════════════
with tab3:
    st.markdown('<div class="section-header">IIoT Network Traffic Monitor</div>', unsafe_allow_html=True)
    st.markdown('<div class="info-box">Simulate IIoT network traffic patterns. Detect anomalies and suspicious activity.</div>', unsafe_allow_html=True)

    col_n1, col_n2, col_n3 = st.columns(3)
    with col_n1: num_devices  = st.slider("Number of Devices", 3, 20, 8)
    with col_n2: traffic_load = st.slider("Traffic Load (%)", 10, 100, 65)
    with col_n3: attack_prob  = st.slider("Threat Level (%)", 0, 100, 30)

    if st.button("SIMULATE NETWORK", use_container_width=True):
        np.random.seed(42)
        time_points    = np.arange(0, 60, 1)
        normal_traffic = traffic_load + np.random.normal(0, 5, len(time_points))
        attack_spikes  = np.where(
            np.random.random(len(time_points)) < attack_prob / 100,
            normal_traffic + np.random.uniform(40, 80, len(time_points)), 0)

        fig = go.Figure()
        fig.add_trace(go.Scatter(x=time_points, y=normal_traffic, mode="lines",
            line=dict(color="#00AAFF", width=2), name="Normal Traffic",
            fill="tozeroy", fillcolor="rgba(0,170,255,0.07)"))
        spike_x = [t for t, s in zip(time_points, attack_spikes) if s > 0]
        spike_y = [s for s in attack_spikes if s > 0]
        if spike_x:
            fig.add_trace(go.Scatter(x=spike_x, y=spike_y, mode="markers",
                marker=dict(size=10, color="#FF2222", symbol="x"), name="Anomaly Detected"))
        fig.update_layout(**PLOT_CFG, title="Real-Time Network Traffic Analysis",
            xaxis=dict(title="Time (seconds)", gridcolor="#071830", color="#4488AA"),
            yaxis=dict(title="Traffic (Mbps)", gridcolor="#071830", color="#4488AA"), height=350)
        st.plotly_chart(fig, use_container_width=True)

        st.markdown('<div class="section-header">Device Network Status</div>', unsafe_allow_html=True)
        device_data = []
        random.seed(10)
        for i in range(num_devices):
            risk = random.choices(["SECURE", "MODERATE", "HIGH RISK"], weights=[40, 35, 25])[0]
            device_data.append({
                "Device":         f"{random.choice(['PLC','SCADA','Sensor','HMI','Router'])}-{i+1:03d}",
                "IP":             f"192.168.{random.randint(1,5)}.{random.randint(10,200)}",
                "Protocol":       random.choice(PROTOCOLS),
                "Status":         risk,
                "Traffic (Mbps)": round(random.uniform(0.5, 50.0), 1),
            })
        df = pd.DataFrame(device_data)
        st.dataframe(df, use_container_width=True, hide_index=True)

        proto_counts = df["Protocol"].value_counts()
        fig2 = go.Figure(go.Pie(
            labels=proto_counts.index, values=proto_counts.values,
            marker=dict(colors=["#00AAFF", "#00FFCC", "#0088DD", "#006699", "#004477", "#002255"]),
            hole=0.45))
        fig2.update_layout(**PLOT_CFG, title="Protocol Distribution", height=300)
        st.plotly_chart(fig2, use_container_width=True)

# ════════════════════════════════════════════════════════════════════════════
# TAB 4 — RISK DASHBOARD
# ════════════════════════════════════════════════════════════════════════════
with tab4:
    st.markdown('<div class="section-header">Security Risk Dashboard</div>', unsafe_allow_html=True)

    col_d1, col_d2 = st.columns(2)
    with col_d1:
        total_devices    = st.number_input("Total IIoT Devices",      min_value=1,  value=15)
        critical_issues  = st.number_input("Critical Issues Found",   min_value=0,  value=4)
        high_issues      = st.number_input("High Severity Issues",    min_value=0,  value=6)
        medium_issues    = st.number_input("Medium Severity Issues",  min_value=0,  value=3)
    with col_d2:
        patched_devices   = st.number_input("Patched/Updated Devices",    min_value=0, value=8)
        encrypted_devices = st.number_input("Devices with Encryption",    min_value=0, value=5)
        auth_devices      = st.number_input("Devices with Auth Enabled",  min_value=0, value=6)

    if st.button("GENERATE DASHBOARD", use_container_width=True):
        overall_risk   = min(100, critical_issues * 25 + high_issues * 15 + medium_issues * 8)
        security_score = max(0, 100 - overall_risk)
        patch_pct = (patched_devices   / total_devices * 100) if total_devices else 0
        enc_pct   = (encrypted_devices / total_devices * 100) if total_devices else 0
        auth_pct  = (auth_devices      / total_devices * 100) if total_devices else 0

        clr = "#00FF88" if security_score >= 70 else ("#FFAA00" if security_score >= 40 else "#FF2222")
        d1, d2, d3, d4 = st.columns(4)
        with d1: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:{clr}">{security_score}</div><div class="metric-label">Overall Score</div></div>', unsafe_allow_html=True)
        with d2: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#FF2222">{critical_issues}</div><div class="metric-label">Critical Issues</div></div>', unsafe_allow_html=True)
        with d3: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#00AAFF">{patch_pct:.0f}%</div><div class="metric-label">Devices Patched</div></div>', unsafe_allow_html=True)
        with d4: st.markdown(f'<div class="metric-card"><div class="metric-value" style="color:#00AAFF">{enc_pct:.0f}%</div><div class="metric-label">Encrypted</div></div>', unsafe_allow_html=True)

        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=security_score,
            title={"text": "Overall Security Score", "font": {"color": "#00AAFF", "family": "Arial"}},
            gauge={
                "axis":      {"range": [0, 100], "tickcolor": "#4488AA"},
                "bar":       {"color": clr},
                "bgcolor":   "#050F1E",
                "bordercolor": "#00AAFF33",
                "steps": [
                    {"range": [0, 40],   "color": "#1A0505"},
                    {"range": [40, 70],  "color": "#1A1205"},
                    {"range": [70, 100], "color": "#051A0A"},
                ],
                "threshold": {"line": {"color": "#00FFCC", "width": 3}, "thickness": 0.75, "value": 70}
            }
        ))
        fig_gauge.update_layout(**PLOT_CFG, height=300)
        st.plotly_chart(fig_gauge, use_container_width=True)

        fig_bar = go.Figure(go.Bar(
            x=["Critical", "High", "Medium"],
            y=[critical_issues, high_issues, medium_issues],
            marker_color=["#FF2222", "#FFAA00", "#00AAFF"],
            text=[str(critical_issues), str(high_issues), str(medium_issues)],
            textposition="outside",
        ))
        fig_bar.update_layout(**PLOT_CFG, title="Issue Severity Breakdown",
            xaxis=dict(gridcolor="#071830", color="#4488AA"),
            yaxis=dict(gridcolor="#071830", color="#4488AA"), height=280)
        st.plotly_chart(fig_bar, use_container_width=True)

        st.markdown('<div class="section-header">Compliance Status</div>', unsafe_allow_html=True)
        checks = [
            ("IEC 62443 — Industrial Cybersecurity Standard", auth_pct >= 80),
            ("NIST Cybersecurity Framework",                  security_score >= 70),
            ("Device Patch Management",                       patch_pct >= 80),
            ("Data Encryption Standards",                     enc_pct >= 80),
            ("Zero Critical Vulnerabilities",                 critical_issues == 0),
        ]
        for check, passed in checks:
            icon = "PASS" if passed else "FAIL"
            cls  = "alert-safe" if passed else "alert-critical"
            st.markdown(f'<div class="{cls}">[{icon}] {check}</div>', unsafe_allow_html=True)

# ════════════════════════════════════════════════════════════════════════════
# TAB 5 — ABOUT
# ════════════════════════════════════════════════════════════════════════════
with tab5:
    st.markdown('<div class="section-header">About This Project</div>', unsafe_allow_html=True)
    st.markdown("""<div class="info-box">
    This IIoT Security Audit Tool is developed as part of the ICT for Cybersecurity project
    at UET Taxila (Group 7). It helps industrial facilities identify and fix cybersecurity
    vulnerabilities in their Industrial Internet of Things (IIoT) devices and networks.<br><br>
    The tool follows IEC 62443 (Industrial Cybersecurity Standard) and
    NIST Cybersecurity Framework guidelines.
    </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-header">How to Use</div>', unsafe_allow_html=True)
    steps = [
        ("Device Scanner",      "Enter device details and security configuration. Click SCAN DEVICE to get a security score."),
        ("Vulnerability Audit", "Select vulnerabilities in your network. Click GENERATE AUDIT REPORT for CVSS scores and fixes."),
        ("Network Monitor",     "Set number of devices and threat level. Click SIMULATE NETWORK to see traffic analysis."),
        ("Risk Dashboard",      "Enter overall facility security numbers. Click GENERATE DASHBOARD for compliance status."),
    ]
    for title, desc in steps:
        st.markdown(f"""<div class="alert-safe" style="border-left-color:#00AAFF;color:#88CCEE;">
            <b style="color:#00AAFF;">{title}</b><br>{desc}
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-header">Group 7 — Project Team</div>', unsafe_allow_html=True)
    for name, reg in TEAM:
        st.markdown(f"""<div class="team-card" style="padding:14px 18px;">
            <span style="color:#AACCEE;font-size:1.05rem;font-weight:600;">{name}</span>
            <span style="color:#00AAFF;font-size:0.9rem;float:right;">{reg}</span>
        </div>""", unsafe_allow_html=True)

    st.markdown('<div class="section-header">Key Cybersecurity Standards</div>', unsafe_allow_html=True)
    standards = [
        ("IEC 62443",  "International standard for industrial cybersecurity — defines IIoT/SCADA security requirements."),
        ("NIST CSF",   "NIST Cybersecurity Framework: Identify, Protect, Detect, Respond, Recover."),
        ("CVSS",       "Common Vulnerability Scoring System — rates vulnerabilities from 0 (low) to 10 (critical)."),
        ("Zero Trust", "Security model: never trust, always verify — every device must authenticate every time."),
    ]
    for std, desc in standards:
        st.markdown(f'<div class="alert-safe" style="border-left-color:#00AAFF;color:#88CCEE;"><b style="color:#00AAFF;">{std}</b> — {desc}</div>', unsafe_allow_html=True)

# ── FOOTER ───────────────────────────────────────────────────────────────────
st.markdown('<hr class="cyber-divider">', unsafe_allow_html=True)
st.markdown("""<div style="text-align:center;color:#224466;font-size:0.8rem;letter-spacing:2px;padding:10px 0;">
    ICT FOR CYBERSECURITY | IIoT SECURITY AUDIT TOOL | MECHANICAL ENGINEERING | UET TAXILA | 2025
</div>""", unsafe_allow_html=True)
