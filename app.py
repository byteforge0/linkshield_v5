import streamlit as st
import pandas as pd
from linkshield.risk import analyze_url
from linkshield.model import load_model

st.set_page_config(page_title="LinkShield", page_icon="🛡️", layout="wide")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap');

* {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background:
        radial-gradient(circle at top left, rgba(56, 189, 248, 0.18), transparent 35%),
        radial-gradient(circle at top right, rgba(139, 92, 246, 0.16), transparent 35%),
        linear-gradient(135deg, #050816 0%, #0B1020 45%, #0F172A 100%);
    color: #E5E7EB;
}

.block-container {
    padding-top: 2rem;
    padding-bottom: 4rem;
}

[data-testid="stSidebar"] {
    background: linear-gradient(180deg, rgba(15, 23, 42, 0.96), rgba(2, 6, 23, 0.98));
    border-right: 1px solid rgba(148, 163, 184, 0.18);
}

[data-testid="stSidebar"] * {
    color: #E5E7EB;
}

.hero {
    position: relative;
    overflow: hidden;
    padding: 34px;
    border-radius: 28px;
    background:
        linear-gradient(135deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.72)),
        radial-gradient(circle at 30% 20%, rgba(56, 189, 248, 0.28), transparent 28%),
        radial-gradient(circle at 80% 0%, rgba(168, 85, 247, 0.24), transparent 28%);
    border: 1px solid rgba(148, 163, 184, 0.22);
    box-shadow: 0 24px 80px rgba(0, 0, 0, 0.35);
    animation: floatIn 850ms ease-out;
}

.hero::before {
    content: "";
    position: absolute;
    inset: -80px;
    background:
        linear-gradient(90deg, transparent, rgba(125, 211, 252, 0.12), transparent);
    transform: rotate(12deg);
    animation: sweep 4.5s infinite;
}

.hero-content {
    position: relative;
    z-index: 2;
}

.hero h1 {
    margin: 0;
    font-size: 54px;
    line-height: 1;
    letter-spacing: -2px;
    font-weight: 900;
    background: linear-gradient(90deg, #FFFFFF, #A5F3FC, #C4B5FD);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
}

.hero p {
    margin-top: 12px;
    color: #CBD5E1;
    font-size: 18px;
    max-width: 860px;
}

.pill-row {
    display: flex;
    flex-wrap: wrap;
    gap: 10px;
    margin-top: 22px;
}

.pill {
    padding: 8px 12px;
    border-radius: 999px;
    background: rgba(15, 23, 42, 0.72);
    border: 1px solid rgba(148, 163, 184, 0.24);
    color: #BAE6FD;
    font-size: 13px;
    font-weight: 700;
    backdrop-filter: blur(12px);
}

.scan-card {
    margin-top: 22px;
    padding: 24px;
    border-radius: 24px;
    background: rgba(15, 23, 42, 0.72);
    border: 1px solid rgba(148, 163, 184, 0.20);
    box-shadow: 0 18px 60px rgba(0, 0, 0, 0.28);
    backdrop-filter: blur(16px);
    animation: fadeUp 700ms ease-out;
}

.metric-card {
    position: relative;
    padding: 20px;
    min-height: 130px;
    border-radius: 22px;
    background:
        linear-gradient(145deg, rgba(15, 23, 42, 0.92), rgba(30, 41, 59, 0.72));
    border: 1px solid rgba(148, 163, 184, 0.22);
    box-shadow: 0 12px 36px rgba(0, 0, 0, 0.22);
    overflow: hidden;
    animation: fadeUp 650ms ease-out;
}

.metric-card::after {
    content: "";
    position: absolute;
    right: -40px;
    top: -40px;
    width: 130px;
    height: 130px;
    border-radius: 999px;
    background: rgba(56, 189, 248, 0.13);
    filter: blur(8px);
}

.metric-label {
    color: #94A3B8;
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: .8px;
}

.metric-value {
    margin-top: 10px;
    color: #F8FAFC;
    font-size: 34px;
    font-weight: 900;
    letter-spacing: -1px;
}

.metric-sub {
    color: #CBD5E1;
    font-size: 13px;
    margin-top: 6px;
}

.badge {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 15px;
    border-radius: 999px;
    font-weight: 900;
    letter-spacing: .5px;
    box-shadow: 0 10px 30px rgba(0,0,0,.22);
}

.low {
    background: linear-gradient(135deg, #10B981, #34D399);
    color: #042F2E;
}

.medium {
    background: linear-gradient(135deg, #F59E0B, #FCD34D);
    color: #451A03;
}

.high {
    background: linear-gradient(135deg, #EF4444, #FB7185);
    color: white;
}

.critical {
    background: linear-gradient(135deg, #7F1D1D, #DC2626, #F97316);
    color: white;
    animation: pulseGlow 1.8s infinite;
}

.risk-shell {
    margin-top: 12px;
    width: 100%;
    height: 14px;
    border-radius: 999px;
    background: rgba(51, 65, 85, 0.78);
    border: 1px solid rgba(148, 163, 184, 0.18);
    overflow: hidden;
}

.risk-fill {
    height: 100%;
    border-radius: 999px;
    background: linear-gradient(90deg, #22C55E, #FACC15, #FB923C, #EF4444);
    box-shadow: 0 0 24px rgba(248, 113, 113, .55);
    animation: growBar 900ms ease-out;
}

.findings-card {
    padding: 18px;
    border-radius: 22px;
    background: rgba(15, 23, 42, 0.74);
    border: 1px solid rgba(148, 163, 184, 0.20);
    backdrop-filter: blur(16px);
}

.section-title {
    color: #F8FAFC;
    font-size: 22px;
    font-weight: 900;
    letter-spacing: -0.5px;
    margin: 8px 0 14px 0;
}

.clean-info {
    padding: 16px 18px;
    border-radius: 18px;
    background: rgba(14, 165, 233, 0.12);
    border: 1px solid rgba(125, 211, 252, 0.25);
    color: #E0F2FE;
}

.stTextInput > div > div > input {
    background: rgba(15, 23, 42, 0.88);
    color: #F8FAFC;
    border: 1px solid rgba(148, 163, 184, .35);
    border-radius: 16px;
    padding: 16px;
    font-size: 15px;
}

.stTextInput > div > div > input:focus {
    border-color: #38BDF8;
    box-shadow: 0 0 0 3px rgba(56, 189, 248, .18);
}

.stButton > button {
    border-radius: 16px;
    border: 0;
    font-weight: 900;
    letter-spacing: .2px;
    padding: 14px 18px;
    background: linear-gradient(135deg, #06B6D4, #6366F1, #A855F7);
    color: white;
    box-shadow: 0 16px 40px rgba(99, 102, 241, .35);
    transition: transform .18s ease, box-shadow .18s ease;
}

.stButton > button:hover {
    transform: translateY(-2px);
    box-shadow: 0 20px 48px rgba(99, 102, 241, .48);
}

[data-testid="stMetric"] {
    background: rgba(15, 23, 42, 0.58);
    border: 1px solid rgba(148, 163, 184, 0.18);
    border-radius: 18px;
    padding: 12px;
}

[data-testid="stDataFrame"] {
    border-radius: 18px;
    overflow: hidden;
}

.stTabs [data-baseweb="tab-list"] {
    gap: 10px;
}

.stTabs [data-baseweb="tab"] {
    background: rgba(15, 23, 42, 0.68);
    border: 1px solid rgba(148, 163, 184, 0.16);
    border-radius: 999px;
    color: #CBD5E1;
    padding: 10px 16px;
}

.stTabs [aria-selected="true"] {
    background: linear-gradient(135deg, rgba(14, 165, 233, .35), rgba(99, 102, 241, .35));
    color: white;
    border-color: rgba(125, 211, 252, 0.35);
}

div[data-testid="stJson"] {
    background: rgba(15, 23, 42, 0.88);
    border-radius: 18px;
}

@keyframes floatIn {
    from {opacity: 0; transform: translateY(18px) scale(.985);}
    to {opacity: 1; transform: translateY(0) scale(1);}
}

@keyframes fadeUp {
    from {opacity: 0; transform: translateY(16px);}
    to {opacity: 1; transform: translateY(0);}
}

@keyframes sweep {
    0% {transform: translateX(-60%) rotate(12deg);}
    55% {transform: translateX(60%) rotate(12deg);}
    100% {transform: translateX(60%) rotate(12deg);}
}

@keyframes pulseGlow {
    0%, 100% {box-shadow: 0 0 24px rgba(248, 113, 113, .35);}
    50% {box-shadow: 0 0 42px rgba(248, 113, 113, .8);}
}

@keyframes growBar {
    from {width: 0%;}
}
</style>
""", unsafe_allow_html=True)

@st.cache_resource
def model_cache():
    return load_model()

def risk_badge(risk):
    emoji = {
        "Low": "✅",
        "Medium": "⚠️",
        "High": "🚨",
        "Critical": "⛔"
    }.get(risk, "🛡️")
    st.markdown(f"<span class='badge {risk.lower()}'>{emoji} {risk.upper()} RISK</span>", unsafe_allow_html=True)

def metric_card(label, value, sub=""):
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-label">{label}</div>
            <div class="metric-value">{value}</div>
            <div class="metric-sub">{sub}</div>
        </div>
        """,
        unsafe_allow_html=True
    )

st.markdown("""
<div class="hero">
  <div class="hero-content">
    <h1>🛡️ LinkShield</h1>
    <p>Strict fraud, scam, phishing, tracking, and suspicious URL risk analysis with professional-grade explainability.</p>
    <div class="pill-row">
      <span class="pill">Risk Override Rules</span>
      <span class="pill">Trusted Domain Confidence</span>
      <span class="pill">Tracking Link Detection</span>
      <span class="pill">Affiliate Fraud Signals</span>
      <span class="pill">ML Classification</span>
    </div>
  </div>
</div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("## 🧠 Engine")
    st.markdown("**Strict Mode:** enabled")
    st.markdown("**Focus:** scam, fraud, phishing, tracking abuse")
    st.divider()
    user_reported = st.toggle("Link came from scam/suspicious message", value=False)
    st.divider()
    st.markdown("### Active Signals")
    signals = [
        "Trusted-domain confidence",
        "Risk override rules",
        "Random subdomain detection",
        "Campaign ID detection",
        "Click-fragment detection",
        "Affiliate fraud analytics",
        "Mismatched domain params",
        "Suspicious TLD detection",
        "Dangerous scheme detection",
        "ML probability scoring",
    ]
    for signal in signals:
        st.markdown(f"✅ {signal}")

model = model_cache()

st.markdown("<div class='scan-card'>", unsafe_allow_html=True)
st.markdown("<div class='section-title'>Run Security Scan</div>", unsafe_allow_html=True)

url = st.text_input("URL", placeholder="Paste a suspicious or normal URL here...")
scan = st.button("Run LinkShield Deep Scan", type="primary", use_container_width=True)
st.markdown("</div>", unsafe_allow_html=True)

if scan:
    if not url.strip():
        st.error("Please enter a URL.")
    else:
        with st.spinner("Analyzing URL across strict fraud and phishing signals..."):
            result = analyze_url(url, model=model, user_reported=user_reported)

        risk_width = max(3, int(result["risk_percent"]))
        trusted = "Trusted" if result["trusted_domain_confidence"] else "Not trusted"
        ml_value = "N/A" if not result["model_used"] else f"{result['model_probability'] * 100:.1f}%"

        st.markdown("<br>", unsafe_allow_html=True)
        c1, c2, c3, c4 = st.columns(4)

        with c1:
            metric_card("Risk Level", result["risk_level"], "Final decision")
            risk_badge(result["risk_level"])

        with c2:
            metric_card("Final Risk", f"{result['risk_percent']}%", "Combined strict score")
            st.markdown(
                f"""
                <div class="risk-shell">
                    <div class="risk-fill" style="width:{risk_width}%"></div>
                </div>
                """,
                unsafe_allow_html=True
            )

        with c3:
            metric_card("Static Risk", f"{result['static_score'] * 100:.1f}%", "Rule engine")

        with c4:
            metric_card("Domain Status", trusted, "Confidence layer")

        st.markdown("<br>", unsafe_allow_html=True)

        st.markdown(
            f"""
            <div class="clean-info">
                <b>Recommendation:</b> {result["recommendation"]}
            </div>
            """,
            unsafe_allow_html=True
        )

        st.code(result["normalized_url"], language="text")

        st.markdown("<div class='section-title'>Security Findings</div>", unsafe_allow_html=True)
        findings = pd.DataFrame(result["findings"])
        st.dataframe(findings, use_container_width=True, hide_index=True)

        tab1, tab2, tab3 = st.tabs(["Signal Overview", "Feature Matrix", "Raw Report"])

        with tab1:
            left, right = st.columns(2)

            with left:
                st.markdown("<div class='findings-card'>", unsafe_allow_html=True)
                st.markdown("### Core Risk Signals")
                keys = [
                    "is_tracking_domain",
                    "tracking_param_count",
                    "click_action_fragment",
                    "numeric_param_count",
                    "short_token_path",
                    "fragment_has_query_style",
                    "affiliate_param_count",
                    "domain_param_mismatch",
                    "ip_value_count",
                    "suspicious_tld"
                ]
                st.dataframe(
                    pd.DataFrame([{"Signal": k, "Value": result["features"].get(k)} for k in keys]),
                    use_container_width=True,
                    hide_index=True
                )
                st.markdown("</div>", unsafe_allow_html=True)

            with right:
                st.markdown("<div class='findings-card'>", unsafe_allow_html=True)
                st.markdown("### Trust Signals")
                keys = [
                    "trusted_registered_domain",
                    "direct_trusted_host",
                    "safe_path",
                    "uses_https",
                    "param_count",
                    "random_like_token_count",
                    "first_label_length",
                    "first_label_entropy"
                ]
                st.dataframe(
                    pd.DataFrame([{"Signal": k, "Value": result["features"].get(k)} for k in keys]),
                    use_container_width=True,
                    hide_index=True
                )
                st.markdown("</div>", unsafe_allow_html=True)

        with tab2:
            st.dataframe(
                pd.DataFrame([{"Indicator": k, "Value": v} for k, v in result["features"].items()]),
                use_container_width=True,
                hide_index=True
            )

        with tab3:
            st.json(result)

else:
    st.markdown("<br>", unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("Trusted Links", "Clear Low", "Known safe domains")
    with c2:
        metric_card("Scam Links", "Strict High", "Fraud correlations")
    with c3:
        metric_card("Explainability", "Full Report", "Every signal shown")
