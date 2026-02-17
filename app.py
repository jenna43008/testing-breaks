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
    primary_cols = ['domain', 'risk_score', 'recommendation', 'high_risk_phish_infra', 
                    'asn_display', 'rules_triggered', 'summary']
    
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
        # Summary table with color coding
        summary_df = df[['domain', 'risk_score', 'recommendation', 'summary']].copy()
        
        # Add high-risk phishing infra indicator column
        if 'high_risk_phish_infra' in df.columns:
            summary_df.insert(2, 'phish_infra', df['high_risk_phish_infra'].apply(
                lambda x: '🚨 HIGH RISK' if x else ''
            ))
        
        # Add ASN display column
        if 'asn_display' in df.columns:
            summary_df.insert(3 if 'phish_infra' in summary_df.columns else 2, 
                            'asn', df['asn_display'].fillna(''))
        
        # Add rules triggered column
        if 'rules_triggered' in df.columns:
            summary_df['rules_fired'] = df['rules_triggered'].apply(
                lambda x: x.replace(';', ' | ') if pd.notna(x) and x else ''
            )
        
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
            "phish_infra": st.column_config.TextColumn("⚠️ Phish Infra", width="small"),
            "asn": st.column_config.TextColumn("ASN", width="medium"),
            "recommendation": st.column_config.TextColumn("Result", width="small"),
            "rules_fired": st.column_config.TextColumn("Rules Fired", width="medium"),
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
            "combos_triggered": st.column_config.TextColumn("Combos", width="medium"),
        }
        st.dataframe(df, use_container_width=True, height=400, column_config=full_column_config)
        
        # Column selector
        with st.expander("🔧 Select columns to display"):
            all_cols = df.columns.tolist()
            selected_cols = st.multiselect(
                "Columns",
                all_cols,
                default=['domain', 'risk_score', 'recommendation', 'high_risk_phish_infra',
                        'asn_display', 'rules_triggered', 'summary', 
                        'combos_triggered', 'spf_exists', 'dkim_exists', 'dmarc_exists', 'domain_age_days']
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
            summary_cols = ['domain', 'risk_score', 'recommendation', 'high_risk_phish_infra',
                           'asn_display', 'rules_triggered', 'summary']
            # Only include columns that exist in the dataframe
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
            
            # Combos triggered display
            combos_str = domain_data.get('combos_triggered', '')
            if combos_str:
                combos_list = combos_str.split(';')
                config = st.session_state.config
                combos_cfg = config.get('combos', DEFAULT_CONFIG.get('combos', {}))
                combo_details = []
                total_combo_pts = 0
                for c in combos_list:
                    pts = combos_cfg.get(c, 0)
                    total_combo_pts += pts
                    combo_details.append(f"  • `{c}` → +{pts}")
                st.markdown(f"**🔗 Combo Scoring:** +{total_combo_pts} points from {len(combos_list)} combo(s)")
                with st.expander("View triggered combos"):
                    st.markdown("\n".join(combo_details))
            
            # Rules triggered display
            rules_str = domain_data.get('rules_triggered', '')
            if rules_str:
                rules_list = rules_str.split(';')
                st.markdown(f"**📐 Rules Fired:** {len(rules_list)} rule(s)")
                for r in rules_list:
                    st.markdown(f"  • `{r}`")
                # Show labels too
                rules_labels_str = domain_data.get('rules_labels', '')
                if rules_labels_str:
                    with st.expander("View rule details"):
                        for label in rules_labels_str.split(';'):
                            if label.strip():
                                st.markdown(f"  ⚡ {label.strip()}")


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
    tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs(["⚖️ Scoring Weights", "🔗 Signal Combos", "📐 Custom Rules", "🎯 Thresholds", "📋 Lists", "💾 Import/Export"])
    
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
        st.header("🔗 Signal Combination Weights")
        st.caption("Bonus points when two signals occur together. These amplify the base weights above.")
        
        combos = config.get('combos', DEFAULT_CONFIG.get('combos', {}))
        
        # Group combos by first signal prefix
        combo_groups = {}
        for combo_key, combo_val in sorted(combos.items()):
            prefix = combo_key.split('+')[0] if '+' in combo_key else combo_key
            # Map to friendly category names
            if 'tld_variant' in prefix:
                category = "TLD Variant Spoofing"
            elif 'domain_brand' in prefix or 'brand_impersonation' in combo_key or 'brand_spoofing' in prefix:
                category = "Brand Impersonation"
            elif 'suspicious_prefix' in prefix or 'suspicious_suffix' in prefix or 'tech_support' in prefix:
                category = "Tech Support Scam Patterns"
            elif 'status_' in prefix:
                category = "HTTP Status Code"
            elif 'hijack' in combo_key or 'phishing_infra' in prefix or 'doc_sharing' in prefix or 'phishing_js' in prefix:
                category = "Hijacked Domain / Phishing"
            elif 'hosting_' in prefix:
                category = "Hosting Provider"
            elif 'mx_' in prefix:
                category = "MX Provider"
            elif 'opaque' in prefix or 'access_restricted' in prefix or 'missing_trust' in prefix:
                category = "Opaque Entity"
            elif 'no_spf' in prefix or 'no_dkim' in prefix or 'no_dmarc' in prefix or 'spf_' in prefix or 'no_mx' in prefix:
                category = "Email Auth"
            elif 'typosquat' in prefix or 'domain_blacklisted' in prefix:
                category = "Fraud / Blacklist"
            elif 'app_store' in prefix:
                category = "App Store (Legitimacy)"
            else:
                category = "Other"
            
            if category not in combo_groups:
                combo_groups[category] = {}
            combo_groups[category][combo_key] = combo_val
        
        new_combos = {}
        for category in sorted(combo_groups.keys()):
            group = combo_groups[category]
            with st.expander(f"**{category}** ({len(group)} combos)", expanded=(category == "TLD Variant Spoofing")):
                cols = st.columns(2)
                for i, (combo_key, combo_val) in enumerate(sorted(group.items())):
                    with cols[i % 2]:
                        new_val = st.number_input(
                            combo_key,
                            min_value=-50,
                            max_value=100,
                            value=combo_val,
                            step=1,
                            key=f"combo_{combo_key}",
                        )
                        new_combos[combo_key] = new_val
        
        config['combos'] = {**combos, **new_combos}
    
    with tab3:
        st.header("📐 Custom Rules")
        st.markdown("""
        Rules provide **if/then logic** beyond simple signal combos. Each rule checks conditions 
        against triggered signals and adds (or subtracts) points when all conditions are met.
        
        **How rules work:**
        - `if_all` — ALL listed signals must be present (AND logic)
        - `if_any` — AT LEAST ONE signal must be present (OR logic)  
        - `if_not` — NONE of these signals may be present (exclusion)
        - `score` — Points to add when rule fires (positive = riskier)
        """)
        
        rules = config.get('rules', DEFAULT_CONFIG.get('rules', []))
        
        # Available signals reference (collapsible)
        with st.expander("📖 Available signals reference"):
            st.markdown("""
            **Email auth:** `no_spf`, `no_dkim`, `no_dmarc`, `spf_pass_all`, `spf_softfail_all`, `spf_neutral_all`, `dmarc_p_none`, `dmarc_no_rua`, `spf_no_external_includes`
            
            **MX:** `no_mx`, `null_mx`, `mx_enterprise`, `mx_disposable`, `mx_selfhosted`, `mx_mail_prefix`
            
            **DNS:** `no_ptr`, `ptr_mismatch`
            
            **Trust/Auth:** `has_bimi`, `has_mta_sts`
            
            **App store:** `app_store_high`, `app_store_medium`, `app_store_low`, `app_store_platform_false_positive`
            
            **Blacklists:** `domain_blacklisted`, `ip_blacklisted`
            
            **Domain age:** `domain_lt_7d`, `domain_lt_30d`, `domain_lt_90d`, `domain_gt_1yr`
            
            **Domain type:** `suspicious_tld`, `free_email_domain`, `disposable_email`, `typosquat_detected`, `free_hosting`
            
            **Hosting:** `hosting_budget_shared`, `hosting_free`, `hosting_suspect`, `hosting_platform`
            
            **Domain name:** `suspicious_prefix`, `suspicious_suffix`, `is_tech_support_tld`, `domain_brand_impersonation`
            
            **TLD variant:** `tld_variant_spoofing`
            
            **Web:** `no_https`, `tls_handshake_failed`, `tls_connection_failed`, `cert_expired`, `cert_self_signed`
            
            **Redirects:** `redirect_chain_2plus`, `redirect_cross_domain`, `redirect_temp_302_307`
            
            **Status codes:** `status_401_unauthorized`, `status_403_cloaking`, `status_429_throttling`, `status_503_disposable`
            
            **Content:** `minimal_shell`, `js_redirect`, `meta_refresh`, `has_external_js`, `missing_trust_signals`, `access_restricted`, `opaque_entity`
            
            **Scam patterns:** `hijack_path_pattern`, `doc_sharing_lure`, `phishing_js_behavior`, `phishing_infra_redirect`, `email_tracking_url`
            
            **E-commerce:** `retail_scam_tld`, `cross_domain_brand_link`, `ecommerce_no_identity`
            """)
        
        updated_rules = []
        
        for idx, rule in enumerate(rules):
            rule_name = rule.get('name', f'rule_{idx}')
            rule_label = rule.get('label', '')
            rule_score = rule.get('score', 0)
            rule_enabled = rule.get('enabled', True)
            
            # Highlight the two key phishing rules
            is_key_rule = rule_name in ('phish_factory_template', 'platform_phish_setup')
            header_prefix = "🎯 " if is_key_rule else ""
            
            with st.expander(f"{header_prefix}**{rule_name}** (score: {rule_score:+d}){' — ⚡ KEY PHISH RULE' if is_key_rule else ''}", expanded=is_key_rule):
                
                col_enable, col_score = st.columns([1, 1])
                
                with col_enable:
                    new_enabled = st.checkbox(
                        "Enabled",
                        value=rule_enabled,
                        key=f"rule_enabled_{idx}",
                    )
                
                with col_score:
                    new_score = st.number_input(
                        "Score (points added when rule fires)",
                        min_value=-50,
                        max_value=100,
                        value=rule_score,
                        step=1,
                        key=f"rule_score_{idx}",
                    )
                
                new_label = st.text_input(
                    "Label (shown in results when rule fires)",
                    value=rule_label,
                    key=f"rule_label_{idx}",
                )
                
                st.markdown("**Conditions:**")
                
                col1, col2, col3 = st.columns(3)
                
                with col1:
                    if_all_str = st.text_area(
                        "if_all (ALL must match, one per line)",
                        value='\n'.join(rule.get('if_all', [])),
                        height=100,
                        key=f"rule_if_all_{idx}",
                        help="ALL of these signals must be present for the rule to fire"
                    )
                
                with col2:
                    if_any_str = st.text_area(
                        "if_any (AT LEAST ONE must match, one per line)",
                        value='\n'.join(rule.get('if_any', [])),
                        height=100,
                        key=f"rule_if_any_{idx}",
                        help="At least ONE of these signals must be present"
                    )
                
                with col3:
                    if_not_str = st.text_area(
                        "if_not (NONE may be present, one per line)",
                        value='\n'.join(rule.get('if_not', [])),
                        height=100,
                        key=f"rule_if_not_{idx}",
                        help="If ANY of these signals are present, the rule will NOT fire"
                    )
                
                updated_rule = {
                    'name': rule_name,
                    'score': new_score,
                    'label': new_label,
                    'enabled': new_enabled,
                    'if_all': [s.strip() for s in if_all_str.splitlines() if s.strip()],
                    'if_any': [s.strip() for s in if_any_str.splitlines() if s.strip()],
                    'if_not': [s.strip() for s in if_not_str.splitlines() if s.strip()],
                }
                updated_rules.append(updated_rule)
        
        # Add new rule button
        st.markdown("---")
        st.subheader("➕ Add New Rule")
        
        with st.form("new_rule_form"):
            new_name = st.text_input("Rule name (unique identifier, no spaces)", placeholder="my_new_rule")
            new_rule_label = st.text_input("Label (human-readable description)", placeholder="Description of what this rule catches")
            new_rule_score = st.number_input("Score", min_value=-50, max_value=100, value=10, step=1)
            
            nr_col1, nr_col2, nr_col3 = st.columns(3)
            with nr_col1:
                new_if_all = st.text_area("if_all (one per line)", height=80, key="new_rule_if_all")
            with nr_col2:
                new_if_any = st.text_area("if_any (one per line)", height=80, key="new_rule_if_any")
            with nr_col3:
                new_if_not = st.text_area("if_not (one per line)", height=80, key="new_rule_if_not")
            
            submitted = st.form_submit_button("Add Rule")
            if submitted and new_name:
                # Check for duplicate names
                existing_names = [r.get('name', '') for r in updated_rules]
                if new_name in existing_names:
                    st.error(f"Rule name '{new_name}' already exists. Use a unique name.")
                else:
                    new_rule = {
                        'name': new_name.strip().replace(' ', '_'),
                        'score': new_rule_score,
                        'label': new_rule_label,
                        'enabled': True,
                        'if_all': [s.strip() for s in new_if_all.splitlines() if s.strip()],
                        'if_any': [s.strip() for s in new_if_any.splitlines() if s.strip()],
                        'if_not': [s.strip() for s in new_if_not.splitlines() if s.strip()],
                    }
                    updated_rules.append(new_rule)
                    st.success(f"Rule '{new_name}' added! Click **Save Configuration** to persist.")
        
        config['rules'] = updated_rules
    
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
    st.sidebar.caption(f"Domain Sender Approval v2.2 | Analyzer v{ANALYZER_VERSION}")
    st.sidebar.caption(f"Threshold: {st.session_state.config.get('approve_threshold', 50)}")


if __name__ == "__main__":
    main()
