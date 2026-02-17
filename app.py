#!/usr/bin/env python3
"""
Domain Sender Approval - Streamlit App
=======================================
User view: Enter domains, run analysis, download results
Admin view: Configure scoring weights and thresholds
"""

import streamlit as st
import pandas as pd
import json
import os
from datetime import datetime
from io import BytesIO

# Import the analysis engine
from analyzer import analyze_domain, DomainApprovalResult, calculate_score, ANALYZER_VERSION
from config import load_config, save_config, DEFAULT_CONFIG

# Page config
st.set_page_config(
    page_title="Domain Sender Approval",
    page_icon="📧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .stAlert {margin-top: 1rem;}
    .result-approve {background-color: #d4edda; padding: 10px; border-radius: 5px; margin: 5px 0;}
    .result-deny {background-color: #f8d7da; padding: 10px; border-radius: 5px; margin: 5px 0;}
    .metric-card {background-color: #f8f9fa; padding: 20px; border-radius: 10px; text-align: center;}
    .big-number {font-size: 48px; font-weight: bold;}
    .admin-section {background-color: #fff3cd; padding: 15px; border-radius: 10px; margin: 10px 0;}
    
    /* Text wrapping for dataframes */
    .stDataFrame div[data-testid="stDataFrameResizable"] {
        width: 100% !important;
    }
    .stDataFrame [data-testid="stDataFrameResizable"] div {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
    }
    div[data-testid="stDataFrame"] div[role="gridcell"] {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        overflow-wrap: break-word !important;
        line-height: 1.4 !important;
    }
    /* Make summary column wider and wrap */
    .dataframe td, .dataframe th {
        white-space: pre-wrap !important;
        word-wrap: break-word !important;
        max-width: 500px !important;
    }
</style>
""", unsafe_allow_html=True)


def init_session_state():
    """Initialize session state variables."""
    if 'config' not in st.session_state:
        st.session_state.config = load_config()
    if 'results' not in st.session_state:
        st.session_state.results = None
    if 'admin_authenticated' not in st.session_state:
        st.session_state.admin_authenticated = False


def parse_domains(text: str) -> list:
    """Parse domain input text into list of domains."""
    domains = []
    for line in text.replace(',', '\n').replace(';', '\n').splitlines():
        d = line.strip().lower()
        if not d or d.startswith('#'):
            continue
        # Clean URLs
        if '://' in d:
            from urllib.parse import urlparse
            d = urlparse(d).netloc or urlparse(d).path
        d = d.strip('/').strip('.')
        if d and '.' in d:
            domains.append(d)
    return list(dict.fromkeys(domains))  # Remove duplicates, preserve order


def run_analysis(domains: list, config: dict, progress_callback=None) -> list:
    """Run domain analysis with current config."""
    results = []
    for i, domain in enumerate(domains):
        if progress_callback:
            progress_callback(i, len(domains), domain)
        try:
            result = analyze_domain(
                domain=domain,
                timeout=config.get('timeout', 10.0),
                check_rdap=config.get('check_rdap', True),
                weights=config.get('weights', {}),
                threshold=config.get('approve_threshold', 50)
            )
            results.append(result)
        except Exception as e:
            # Create error result
            results.append({
                'domain': domain,
                'risk_score': 100,
                'recommendation': 'DENY',
                'summary': f'Analysis failed: {str(e)[:100]}',
                'risk_level': 'ERROR'
            })
    return results


def results_to_dataframe(results: list) -> pd.DataFrame:
    """Convert results to DataFrame."""
    if not results:
        return pd.DataFrame()
    
    # Primary columns first
    primary_cols = ['domain', 'risk_score', 'recommendation', 'summary']
    
    # Convert to list of dicts if needed
    if hasattr(results[0], '__dict__'):
        data = [vars(r) for r in results]
    else:
        data = results
    
    df = pd.DataFrame(data)
    
    # Reorder columns
    cols = primary_cols + [c for c in df.columns if c not in primary_cols]
    df = df[[c for c in cols if c in df.columns]]
    
    return df


def user_view():
    """Main user interface for domain analysis."""
    st.title("📧 Domain Sender Approval")
    st.markdown("Analyze email sender domains for risk assessment and approval recommendations.")
    
    # Sidebar info
    with st.sidebar:
        st.header("ℹ️ How to Use")
        st.markdown("""
        1. **Paste domains** in the text box (one per line)
        2. Click **Analyze Domains**
        3. Review results and **download CSV**
        
        ---
        
        **Scoring:**
        - Score ≤ {threshold}: ✅ APPROVE
        - Score > {threshold}: 🚫 DENY
        """.format(threshold=st.session_state.config.get('approve_threshold', 50)))
        
        st.markdown("---")
        
        # Options
        st.subheader("⚙️ Options")
        check_rdap = st.checkbox("Check domain age (RDAP)", value=True, 
                                  help="Lookup domain registration date - adds ~1s per domain")
        
        st.session_state.config['check_rdap'] = check_rdap
    
    # Main input area
    col1, col2 = st.columns([2, 1])
    
    with col1:
        domains_input = st.text_area(
            "Enter domains to analyze (one per line)",
            height=200,
            placeholder="example.com\nanotherdomain.com\nhttps://somesite.org/path",
            help="Paste domains, URLs, or a list from a spreadsheet"
        )
    
    with col2:
        st.markdown("### 📁 Or upload a file")
        uploaded_file = st.file_uploader(
            "CSV or TXT file",
            type=['csv', 'txt'],
            help="First column should contain domains"
        )
        
        if uploaded_file:
            try:
                if uploaded_file.name.endswith('.csv'):
                    df = pd.read_csv(uploaded_file)
                    file_domains = df.iloc[:, 0].astype(str).tolist()
                else:
                    file_domains = uploaded_file.read().decode('utf-8').splitlines()
                domains_input = '\n'.join(file_domains)
                st.success(f"Loaded {len(file_domains)} lines from file")
            except Exception as e:
                st.error(f"Error reading file: {e}")
    
    # Parse domains
    domains = parse_domains(domains_input) if domains_input else []
    
    if domains:
        st.info(f"**{len(domains)} domains** ready for analysis")
    
    # Analyze button
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        analyze_clicked = st.button("🔍 Analyze Domains", type="primary", disabled=len(domains) == 0)
    
    # Run analysis
    if analyze_clicked and domains:
        progress_bar = st.progress(0)
        status_text = st.empty()
        
        def update_progress(i, total, domain):
            progress_bar.progress((i + 1) / total)
            status_text.text(f"Analyzing {i+1}/{total}: {domain}")
        
        with st.spinner("Running analysis..."):
            results = run_analysis(domains, st.session_state.config, update_progress)
            st.session_state.results = results
        
        progress_bar.empty()
        status_text.empty()
        st.success(f"✅ Analysis complete! Analyzed {len(results)} domains.")
    
    # Display results
    if st.session_state.results:
        display_results(st.session_state.results)


def display_results(results: list):
    """Display analysis results."""
    st.markdown("---")
    st.header("📊 Results")
    
    df = results_to_dataframe(results)
    
    # Summary metrics
    approve_count = len(df[df['recommendation'] == 'APPROVE'])
    deny_count = len(df[df['recommendation'] == 'DENY'])
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Analyzed", len(df))
    with col2:
        st.metric("✅ Approved", approve_count)
    with col3:
        st.metric("🚫 Denied", deny_count)
    with col4:
        avg_score = df['risk_score'].mean()
        st.metric("Avg Risk Score", f"{avg_score:.1f}")
    
    # Tabs for different views
    tab1, tab2, tab3 = st.tabs(["📋 Summary View", "📊 Full Details", "⬇️ Download"])
    
    with tab1:
        # Summary table with color coding — clean view: just domain, score, result, summary
        summary_df = df[['domain', 'risk_score', 'recommendation', 'summary']].copy()
        
        def color_recommendation(val):
            if val == 'APPROVE':
                return 'background-color: #d4edda; color: #155724'
            else:
                return 'background-color: #f8d7da; color: #721c24'
        
        def color_score(val):
            if val <= 30:
                return 'background-color: #d4edda'
            elif val <= 50:
                return 'background-color: #fff3cd'
            else:
                return 'background-color: #f8d7da'
        
        styled_df = summary_df.style.applymap(
            color_recommendation, subset=['recommendation']
        ).applymap(
            color_score, subset=['risk_score']
        )
        
        # Column configuration for better display
        column_config = {
            "domain": st.column_config.TextColumn("Domain", width="medium"),
            "risk_score": st.column_config.NumberColumn("Score", width="small"),
            "recommendation": st.column_config.TextColumn("Result", width="small"),
            "summary": st.column_config.TextColumn("Summary", width="large"),
        }
        
        st.dataframe(
            styled_df, 
            use_container_width=True, 
            height=400,
            column_config=column_config
        )
        

    
    with tab2:
        # Full details table with column config
        full_column_config = {
            "domain": st.column_config.TextColumn("Domain", width="medium"),
            "risk_score": st.column_config.NumberColumn("Score", width="small"),
            "recommendation": st.column_config.TextColumn("Result", width="small"),
            "high_risk_phish_infra": st.column_config.CheckboxColumn("🚨 Phish Infra", width="small"),
            "asn_display": st.column_config.TextColumn("ASN", width="medium"),
            "rules_triggered": st.column_config.TextColumn("Rules Fired", width="medium"),
            "summary": st.column_config.TextColumn("Summary", width="large"),
            "signals_triggered": st.column_config.TextColumn("Signals", width="medium"),
        }
        st.dataframe(df, use_container_width=True, height=400, column_config=full_column_config)
        
        # Column selector
        with st.expander("🔧 Select columns to display"):
            all_cols = df.columns.tolist()
            selected_cols = st.multiselect(
                "Columns",
                all_cols,
                default=['domain', 'risk_score', 'recommendation', 'summary', 
                        'asn_display', 'rules_triggered',
                        'spf_exists', 'dkim_exists', 'dmarc_exists', 'domain_age_days']
            )
            if selected_cols:
                st.dataframe(df[selected_cols], use_container_width=True)
    
    with tab3:
        st.subheader("⬇️ Download Results")
        
        # CSV download
        csv_buffer = BytesIO()
        df.to_csv(csv_buffer, index=False)
        csv_buffer.seek(0)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        col1, col2 = st.columns(2)
        with col1:
            st.download_button(
                label="📥 Download Full CSV",
                data=csv_buffer.getvalue(),
                file_name=f"domain_approval_results_{timestamp}.csv",
                mime="text/csv"
            )
        
        with col2:
            # Summary CSV (just key columns)
            summary_csv = BytesIO()
            summary_cols = ['domain', 'risk_score', 'recommendation', 'summary']
            summary_cols = [c for c in summary_cols if c in df.columns]
            df[summary_cols].to_csv(summary_csv, index=False)
            summary_csv.seek(0)
            st.download_button(
                label="📥 Download Summary CSV",
                data=summary_csv.getvalue(),
                file_name=f"domain_approval_summary_{timestamp}.csv",
                mime="text/csv"
            )
    
    # Detailed breakdown by domain
    st.markdown("---")
    st.subheader("🔍 Individual Domain Details")
    
    selected_domain = st.selectbox(
        "Select a domain to view details",
        df['domain'].tolist()
    )
    
    if selected_domain:
        domain_data = df[df['domain'] == selected_domain].iloc[0]
        
        col1, col2 = st.columns([1, 2])
        
        with col1:
            # Score display
            score = domain_data['risk_score']
            rec = domain_data['recommendation']
            
            if rec == 'APPROVE':
                st.success(f"### ✅ {rec}")
            else:
                st.error(f"### 🚫 {rec}")
            
            st.metric("Risk Score", score)
            
            if 'risk_level' in domain_data:
                st.metric("Risk Level", domain_data.get('risk_level', 'N/A'))
            
            # High-risk phishing infrastructure indicator
            if domain_data.get('high_risk_phish_infra'):
                st.error(f"### 🚨 HIGH-RISK PHISHING INFRA")
                st.caption(domain_data.get('high_risk_phish_infra_reason', ''))
            
            # ASN display
            asn_display = domain_data.get('asn_display', '')
            if asn_display:
                is_render = 'render' in asn_display.lower()
                if is_render:
                    st.warning(f"**ASN:** 🔴 {asn_display}")
                else:
                    st.markdown(f"**ASN:** {asn_display}")
        
        with col2:
            st.markdown("**Summary:**")
            st.info(domain_data['summary'])
            
            # Key signals
            st.markdown("**Email Authentication:**")
            auth_col1, auth_col2, auth_col3 = st.columns(3)
            with auth_col1:
                spf = "✅" if domain_data.get('spf_exists') else "❌"
                st.markdown(f"SPF: {spf}")
            with auth_col2:
                dkim = "✅" if domain_data.get('dkim_exists') else "❌"
                st.markdown(f"DKIM: {dkim}")
            with auth_col3:
                dmarc = "✅" if domain_data.get('dmarc_exists') else "❌"
                st.markdown(f"DMARC: {dmarc}")
            
            if domain_data.get('domain_age_days', -1) >= 0:
                st.markdown(f"**Domain Age:** {domain_data['domain_age_days']} days")
            
            # Hosting Provider display
            if domain_data.get('hosting_provider'):
                provider = domain_data['hosting_provider']
                ptype = domain_data.get('hosting_provider_type', '')
                via = domain_data.get('hosting_detected_via', '')
                asn_org = domain_data.get('hosting_asn_org', '')
                type_icons = {
                    'budget_shared': '⚠️',
                    'free': '🚩',
                    'suspect': '🔴',
                    'premium': '✅',
                }
                icon = type_icons.get(ptype, 'ℹ️')
                st.markdown(f"**Hosting:** {icon} {provider} ({ptype}) — detected via {via}")
                if asn_org:
                    st.markdown(f"**ASN Org:** {asn_org}")
            
            # MX Provider display
            mx_ptype = domain_data.get('mx_provider_type', '')
            if mx_ptype and mx_ptype != 'unknown':
                mx_primary = domain_data.get('mx_primary', '')
                mx_icons = {
                    'enterprise': '✅',
                    'standard': 'ℹ️',
                    'disposable': '⚠️',
                    'selfhosted': '⚠️',
                }
                mx_icon = mx_icons.get(mx_ptype, 'ℹ️')
                st.markdown(f"**MX Provider:** {mx_icon} {mx_ptype} ({mx_primary})")
            
            # Rules triggered display
            rules_str = domain_data.get('rules_triggered', '')
            if rules_str:
                rules_list = rules_str.split(';')
                rules_labels_str = domain_data.get('rules_labels', '')
                labels = rules_labels_str.split(';') if rules_labels_str else []
                
                st.markdown(f"**📐 Rules Fired:** {len(rules_list)} rule(s)")
                with st.expander("View fired rules"):
                    for i, r in enumerate(rules_list):
                        label = labels[i].strip() if i < len(labels) and labels[i].strip() else ''
                        if label:
                            st.markdown(f"• **`{r}`** — {label}")
                        else:
                            st.markdown(f"• `{r}`")


def admin_view():
    """Admin interface for configuring scoring weights."""
    st.title("🔧 Admin Configuration")
    
    # Simple password protection
    if not st.session_state.admin_authenticated:
        st.warning("⚠️ Admin access required")
        password = st.text_input("Enter admin password", type="password")
        admin_password = st.session_state.config.get('admin_password', 'Doma!nHe5lThOS')
        
        if st.button("Login"):
            if password == admin_password:
                st.session_state.admin_authenticated = True
                st.rerun()
            else:
                st.error("Incorrect password")
        
        st.info("Default password: `*********` (change this in config!)")
        return
    
    # Admin is authenticated
    st.success("✅ Authenticated as Admin")
    
    if st.button("🚪 Logout"):
        st.session_state.admin_authenticated = False
        st.rerun()
    
    st.markdown("---")
    
    config = st.session_state.config
    
    # Tabs for different config sections
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["⚖️ Scoring Weights", "📖 Signal Reference", "📐 Rules Engine", "🎯 Thresholds", "📋 Lists", "💾 Import/Export"])
    
    with tab1:
        st.header("⚖️ Scoring Weights")
        st.markdown("Adjust the risk points added for each signal. Higher = more risky.")
        
        weights = config.get('weights', DEFAULT_CONFIG['weights'])
        
        # Group weights by category
        categories = {
            "Email Authentication": ['no_spf', 'spf_pass_all', 'spf_neutral_all', 'no_dkim', 'no_dmarc', 
                                     'dmarc_p_none', 'no_mx', 'null_mx', 'no_ptr', 'ptr_mismatch'],
            "Blacklists": ['domain_blacklisted', 'ip_blacklisted'],
            "Domain Age": ['domain_lt_7d', 'domain_lt_30d', 'domain_lt_90d'],
            "Domain Type": ['suspicious_tld', 'free_email_domain', 'disposable_email', 
                           'typosquat_detected', 'free_hosting'],
            "Web/TLS": ['no_https', 'tls_handshake_failed', 'tls_connection_failed',
                       'cert_expired', 'cert_self_signed', 'redirect_chain_2plus',
                       'redirect_cross_domain', 'redirect_temp_302_307'],
            "Content/Phishing": ['credential_form', 'brand_impersonation', 'phishing_paths',
                                'malware_links', 'minimal_shell', 'js_redirect'],
            "Domain Name Patterns": ['suspicious_prefix', 'suspicious_suffix', 
                                     'tech_support_tld', 'domain_brand_impersonation',
                                     'brand_spoofing_keyword',
                                     'tld_variant_spoofing'],
            "Hosting Provider": ['hosting_budget_shared', 'hosting_free', 'hosting_suspect'],
            "Bonuses (Reduce Score)": ['has_bimi', 'has_mta_sts'],
        }
        
        new_weights = {}
        
        for category, signals in categories.items():
            with st.expander(f"**{category}**", expanded=(category == "Email Authentication")):
                cols = st.columns(2)
                for i, signal in enumerate(signals):
                    with cols[i % 2]:
                        current = weights.get(signal, 0)
                        new_val = st.number_input(
                            signal.replace('_', ' ').title(),
                            min_value=-50,
                            max_value=100,
                            value=current,
                            step=1,
                            key=f"weight_{signal}",
                            help=f"Current: {current}"
                        )
                        new_weights[signal] = new_val
        
        config['weights'] = {**weights, **new_weights}
    
    with tab2:
        st.header("📖 Signal Reference")
        st.caption("Read-only reference of all signals the analyzer can detect. "
                   "Use these signal names when creating or editing rules in the Rules Engine tab.")
        
        signal_groups = {
            "Email Authentication": {
                "no_spf": "No SPF record found — cannot verify authorized senders",
                "no_dkim": "No DKIM record — missing cryptographic email signature",
                "no_dmarc": "No DMARC policy — no spoofing protection framework",
                "spf_pass_all": "SPF +all — allows anyone to send as this domain (spoofable)",
                "spf_softfail_all": "SPF ~all — soft enforcement, common but weak",
                "spf_neutral_all": "SPF ?all — provides zero protection",
                "dmarc_p_none": "DMARC policy=none — monitoring only, no enforcement",
                "dmarc_no_rua": "DMARC has no rua= tag — cannot monitor authentication failures",
                "spf_no_external_includes": "SPF has no external includes — no third-party email service configured",
            },
            "MX / Mail Server": {
                "no_mx": "No MX records — domain cannot receive email",
                "null_mx": "Null MX record — domain explicitly refuses email",
                "mx_enterprise": "Enterprise MX provider (Google, Microsoft, etc.) — trusted",
                "mx_disposable": "Disposable/temporary MX provider — commonly used for spam",
                "mx_selfhosted": "Self-hosted MX — mail server on own domain, no external oversight",
                "mx_mail_prefix": "MX is mail.{domain} — common phishing infrastructure template pattern",
            },
            "DNS": {
                "no_ptr": "No PTR (reverse DNS) record — enterprise filters may reject",
                "ptr_mismatch": "PTR doesn't match forward DNS — triggers spam filters",
            },
            "Trust & Authentication": {
                "has_bimi": "BIMI record present — brand logo authentication (high trust)",
                "has_mta_sts": "MTA-STS configured — enforces encrypted email transport",
            },
            "App Store Presence": {
                "app_store_high": "Found in major app store with high confidence — strong legitimacy signal",
                "app_store_medium": "Found in app store with medium confidence",
                "app_store_low": "Found in app store with low confidence",
                "app_store_platform_false_positive": "App store match is likely a platform false positive",
            },
            "Blacklists": {
                "domain_blacklisted": "Domain appears on email/DNS blacklists",
                "ip_blacklisted": "IP address appears on blacklists",
            },
            "Domain Age": {
                "domain_lt_7d": "Domain registered less than 7 days ago",
                "domain_lt_30d": "Domain registered less than 30 days ago",
                "domain_lt_90d": "Domain registered less than 90 days ago",
                "domain_gt_1yr": "Domain registered more than 1 year ago — established",
            },
            "Domain Type": {
                "suspicious_tld": "High-abuse TLD (.xyz, .top, .click, etc.)",
                "free_email_domain": "Free consumer email provider domain (gmail.com, etc.)",
                "disposable_email": "Disposable/temporary email domain",
                "typosquat_detected": "Domain appears to be a typosquat of a known brand",
                "free_hosting": "Domain on a free hosting provider",
            },
            "Hosting Provider": {
                "hosting_budget_shared": "Budget shared hosting — commonly used for spam/phishing",
                "hosting_free": "Free hosting — associated with throwaway sites",
                "hosting_suspect": "Suspect/bulletproof hosting — abuse-tolerant provider",
                "hosting_platform": "Developer platform hosting (Render, Vercel, etc.) — free tier abuse risk",
            },
            "Domain Name Patterns": {
                "suspicious_prefix": "Domain starts with suspicious prefix (secure-, login-, verify-, etc.)",
                "suspicious_suffix": "Domain ends with suspicious suffix (-support, -account, etc.)",
                "is_tech_support_tld": "Tech support scam TLD (.support, .tech, .help)",
                "domain_brand_impersonation": "Domain name impersonates a known brand",
                "brand_spoofing_keyword": "Brand spoofing keyword detected in domain",
                "brand_impersonation": "Brand impersonation detected via content analysis",
            },
            "TLD Variant": {
                "tld_variant_spoofing": "Established business exists at a variant TLD — potential impersonation",
            },
            "Web / TLS": {
                "no_https": "No valid HTTPS — may indicate abandoned or suspicious domain",
                "tls_handshake_failed": "TLS handshake failed — broken SSL config or evasion",
                "tls_connection_failed": "Cannot reach port 443 — no HTTPS service running",
                "cert_expired": "TLS certificate has expired",
                "cert_self_signed": "Self-signed TLS certificate",
            },
            "Redirects": {
                "redirect_chain_2plus": "Redirect chain with 2+ hops — may trigger phishing detection",
                "redirect_cross_domain": "Redirects to a different domain — suspicious pattern",
                "redirect_temp_302_307": "Uses temporary redirects (302/307) — suggests URL cloaking",
            },
            "HTTP Status Codes": {
                "status_401_unauthorized": "Returns 401 — public domain requires authentication",
                "status_403_cloaking": "Returns 403 — may be blocking scanners (cloaking)",
                "status_429_throttling": "Returns 429 — throttling automated checks",
                "status_503_disposable": "Returns 503 — disposable/intermittent infrastructure",
            },
            "Content Analysis": {
                "minimal_shell": "Minimal/shell website — common phishing indicator",
                "js_redirect": "JavaScript redirect — suspicious redirect technique",
                "meta_refresh": "Meta refresh redirect — often used for cloaking",
                "has_external_js": "External JavaScript loader — content from external source",
                "missing_trust_signals": "No corporate pages (/about, /contact, /privacy)",
                "access_restricted": "Access blocked — cannot fully analyze site content",
                "opaque_entity": "Access blocked AND no corporate pages — high B2B fraud risk",
                "parking_page": "Domain shows a parking/placeholder page — not actively used",
                "credential_form": "Login/credential form detected on landing page",
            },
            "Scam / Phishing Patterns": {
                "hijack_path_pattern": "Suspicious URL path pattern common in hijacked domains",
                "doc_sharing_lure": "Document sharing lure (fake OneDrive, Google Docs, etc.)",
                "phishing_js_behavior": "Suspicious JavaScript patterns matching phishing kits",
                "phishing_infra_redirect": "Redirects to known phishing infrastructure",
                "email_tracking_url": "Email/victim tracking URL parameters detected",
                "phishing_paths": "Known phishing URL paths detected",
            },
            "E-commerce": {
                "retail_scam_tld": ".shop/.store TLD — heavily abused for fake stores",
                "cross_domain_brand_link": "Links to same brand on different TLD — clone store pattern",
                "ecommerce_no_identity": "E-commerce site without business identity information",
            },
        }
        
        for group_name, signals in signal_groups.items():
            with st.expander(f"**{group_name}** ({len(signals)} signals)"):
                for signal_name, description in sorted(signals.items()):
                    st.markdown(f"**`{signal_name}`** — {description}")
    
    with tab3:
        st.header("📐 Rules Engine")
        st.caption("All scoring rules grouped by category. Each rule fires when its signal conditions are met, "
                   "adding (or subtracting) its score. Toggle rules on/off, adjust scores, or create new rules.")
        
        rules = config.get('rules', DEFAULT_CONFIG.get('rules', []))
        
        # Group rules by category
        rule_categories = {}
        for idx, rule in enumerate(rules):
            cat = rule.get('category', 'Uncategorized')
            rule_categories.setdefault(cat, []).append((idx, rule))
        
        # Define category display order and icons
        cat_icons = {
            'Positive Signals': '✅',
            'Phishing Templates': '🎯',
            'Email Auth Weakness': '📧',
            'MX Provider Risk': '📬',
            'Brand Impersonation': '🛡️',
            'TLD Variant Spoofing': '🔀',
            'Fraud / Blacklist': '🚫',
            'Tech Support Scam': '☎️',
            'Hosting Risk': '🖥️',
            'HTTP Status Evasion': '🔒',
            'Phishing Infrastructure': '🕸️',
            'Phishing Lures': '🪝',
            'Opaque Entity': '👻',
            'General Risk': '⚠️',
        }
        
        # Show positive signals first, then phishing templates, then rest alphabetically
        priority_order = ['Positive Signals', 'Phishing Templates']
        sorted_cats = priority_order + [c for c in sorted(rule_categories.keys()) if c not in priority_order]
        
        for cat_name in sorted_cats:
            if cat_name not in rule_categories:
                continue
            cat_rules = rule_categories[cat_name]
            icon = cat_icons.get(cat_name, '📋')
            
            # Count enabled/disabled
            enabled_count = sum(1 for _, r in cat_rules if r.get('enabled', True))
            disabled_count = len(cat_rules) - enabled_count
            
            header = f"{icon} **{cat_name}** — {enabled_count} active"
            if disabled_count > 0:
                header += f", {disabled_count} disabled"
            header += f" ({len(cat_rules)} total)"
            
            # Phishing Templates expanded by default
            is_priority = cat_name in priority_order
            
            with st.expander(header, expanded=is_priority):
                # Bulk controls
                bulk_col1, bulk_col2, bulk_col3 = st.columns([1, 1, 2])
                with bulk_col1:
                    if st.button(f"✅ Enable all", key=f"enable_all_{cat_name}"):
                        for _, r in cat_rules:
                            r['enabled'] = True
                        st.rerun()
                with bulk_col2:
                    if st.button(f"⛔ Disable all", key=f"disable_all_{cat_name}"):
                        for _, r in cat_rules:
                            r['enabled'] = False
                        st.rerun()
                
                st.markdown("---")
                
                for idx, rule in cat_rules:
                    rule_name = rule.get('name', f'rule_{idx}')
                    rule_score = rule.get('score', 0)
                    rule_enabled = rule.get('enabled', True)
                    rule_label = rule.get('label', '')
                    
                    # Main row: toggle + name + score
                    toggle_col, name_col, score_col = st.columns([0.4, 2.5, 1])
                    
                    with toggle_col:
                        new_enabled = st.toggle(
                            "on",
                            value=rule_enabled,
                            key=f"rule_toggle_{idx}",
                            label_visibility="collapsed",
                        )
                        rule['enabled'] = new_enabled
                    
                    with name_col:
                        status = "✅" if new_enabled else "⛔"
                        if new_enabled:
                            st.markdown(f"{status} **`{rule_name}`**")
                        else:
                            st.markdown(f"{status} ~~`{rule_name}`~~ *(disabled)*")
                        if rule_label:
                            st.caption(rule_label)
                    
                    with score_col:
                        new_score = st.number_input(
                            "pts",
                            min_value=-50,
                            max_value=100,
                            value=rule_score,
                            step=1,
                            key=f"rule_score_{idx}",
                            label_visibility="collapsed",
                            disabled=not new_enabled,
                        )
                        rule['score'] = new_score
                    
                    # Expandable conditions editor
                    with st.expander(f"Edit conditions: {rule_name}", expanded=False):
                        rule['label'] = st.text_input(
                            "Label", value=rule_label, key=f"rule_label_{idx}",
                        )
                        
                        new_cat = st.selectbox(
                            "Category",
                            options=sorted(cat_icons.keys()),
                            index=sorted(cat_icons.keys()).index(cat_name) if cat_name in cat_icons else 0,
                            key=f"rule_cat_{idx}",
                        )
                        rule['category'] = new_cat
                        
                        c1, c2, c3 = st.columns(3)
                        with c1:
                            if_all_str = st.text_area(
                                "if_all (ALL must match)",
                                value='\n'.join(rule.get('if_all', [])),
                                height=80, key=f"rule_if_all_{idx}",
                            )
                            rule['if_all'] = [s.strip() for s in if_all_str.splitlines() if s.strip()]
                        with c2:
                            if_any_str = st.text_area(
                                "if_any (AT LEAST ONE)",
                                value='\n'.join(rule.get('if_any', [])),
                                height=80, key=f"rule_if_any_{idx}",
                            )
                            rule['if_any'] = [s.strip() for s in if_any_str.splitlines() if s.strip()]
                        with c3:
                            if_not_str = st.text_area(
                                "if_not (NONE may match)",
                                value='\n'.join(rule.get('if_not', [])),
                                height=80, key=f"rule_if_not_{idx}",
                            )
                            rule['if_not'] = [s.strip() for s in if_not_str.splitlines() if s.strip()]
        
        # Add new rule
        st.markdown("---")
        st.subheader("➕ Add New Rule")
        
        with st.form("new_rule_form"):
            new_name = st.text_input("Rule name (unique, no spaces)", placeholder="my_new_rule")
            new_rule_label = st.text_input("Label", placeholder="What this rule detects")
            
            nr_col1, nr_col2 = st.columns(2)
            with nr_col1:
                new_rule_score = st.number_input("Score", min_value=-50, max_value=100, value=10, step=1)
            with nr_col2:
                new_rule_cat = st.selectbox("Category", options=sorted(cat_icons.keys()), index=0, key="new_rule_cat")
            
            nr_c1, nr_c2, nr_c3 = st.columns(3)
            with nr_c1:
                new_if_all = st.text_area("if_all (one per line)", height=80, key="new_rule_if_all")
            with nr_c2:
                new_if_any = st.text_area("if_any (one per line)", height=80, key="new_rule_if_any")
            with nr_c3:
                new_if_not = st.text_area("if_not (one per line)", height=80, key="new_rule_if_not")
            
            submitted = st.form_submit_button("Add Rule")
            if submitted and new_name:
                existing_names = [r.get('name', '') for r in rules]
                if new_name in existing_names:
                    st.error(f"Rule name '{new_name}' already exists.")
                else:
                    rules.append({
                        'name': new_name.strip().replace(' ', '_'),
                        'score': new_rule_score,
                        'label': new_rule_label,
                        'category': new_rule_cat,
                        'enabled': True,
                        'if_all': [s.strip() for s in new_if_all.splitlines() if s.strip()],
                        'if_any': [s.strip() for s in new_if_any.splitlines() if s.strip()],
                        'if_not': [s.strip() for s in new_if_not.splitlines() if s.strip()],
                    })
                    st.success(f"Rule '{new_name}' added! Click **Save Configuration** to persist.")
        
        config['rules'] = rules

    
    with tab4:
        st.header("🎯 Thresholds & Settings")
        
        col1, col2 = st.columns(2)
        
        with col1:
            config['approve_threshold'] = st.slider(
                "Approval Threshold",
                min_value=0,
                max_value=100,
                value=config.get('approve_threshold', 50),
                help="Scores at or below this value = APPROVE"
            )
            
            config['timeout'] = st.number_input(
                "Request Timeout (seconds)",
                min_value=1.0,
                max_value=60.0,
                value=config.get('timeout', 10.0),
                step=1.0
            )
        
        with col2:
            config['check_rdap'] = st.checkbox(
                "Enable RDAP (Domain Age) Lookup",
                value=config.get('check_rdap', True)
            )
            
            new_password = st.text_input(
                "Change Admin Password",
                type="password",
                help="Leave blank to keep current"
            )
            if new_password:
                config['admin_password'] = new_password
    
    with tab5:
        st.header("📋 Pattern Lists")
        
        st.subheader("Suspicious TLDs")
        suspicious_tlds = st.text_area(
            "One per line (include the dot)",
            value='\n'.join(config.get('suspicious_tlds', DEFAULT_CONFIG.get('suspicious_tlds', []))),
            height=150
        )
        config['suspicious_tlds'] = [t.strip() for t in suspicious_tlds.splitlines() if t.strip()]
        
        st.subheader("Protected Brands (for typosquatting)")
        protected_brands = st.text_area(
            "One per line",
            value='\n'.join(config.get('protected_brands', DEFAULT_CONFIG.get('protected_brands', []))),
            height=150
        )
        config['protected_brands'] = [b.strip().lower() for b in protected_brands.splitlines() if b.strip()]
    
    with tab6:
        st.header("💾 Import/Export Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Export")
            config_json = json.dumps(config, indent=2)
            st.download_button(
                "📥 Download Config JSON",
                data=config_json,
                file_name="domain_approval_config.json",
                mime="application/json"
            )
        
        with col2:
            st.subheader("Import")
            uploaded_config = st.file_uploader("Upload Config JSON", type=['json'])
            if uploaded_config:
                try:
                    imported = json.loads(uploaded_config.read())
                    if st.button("Apply Imported Config"):
                        st.session_state.config = imported
                        save_config(imported)
                        st.success("Config imported!")
                        st.rerun()
                except Exception as e:
                    st.error(f"Invalid config file: {e}")
        
        st.markdown("---")
        
        if st.button("🔄 Reset to Defaults"):
            st.session_state.config = DEFAULT_CONFIG.copy()
            save_config(DEFAULT_CONFIG)
            st.success("Reset to defaults!")
            st.rerun()
    
    # Save button
    st.markdown("---")
    col1, col2, col3 = st.columns([1, 1, 2])
    with col1:
        if st.button("💾 Save Configuration", type="primary"):
            save_config(config)
            st.session_state.config = config
            st.success("✅ Configuration saved!")


def main():
    """Main app entry point."""
    init_session_state()
    
    # Navigation
    st.sidebar.title("Navigation")
    page = st.sidebar.radio(
        "Select Page",
        ["🔍 Analyze Domains", "🔧 Admin Config"],
        label_visibility="collapsed"
    )
    
    if page == "🔍 Analyze Domains":
        user_view()
    else:
        admin_view()
    
    # Footer
    st.sidebar.markdown("---")
    st.sidebar.caption(f"Domain Sender Approval v3.0 | Analyzer v{ANALYZER_VERSION}")
    st.sidebar.caption(f"Threshold: {st.session_state.config.get('approve_threshold', 50)}")


if __name__ == "__main__":
    main()
