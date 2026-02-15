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
        # Summary table with color coding
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
            df[['domain', 'risk_score', 'recommendation', 'summary']].to_csv(summary_csv, index=False)
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
    tab1, tab2, tab3, tab4 = st.tabs(["⚖️ Scoring Weights", "🎯 Thresholds", "📋 Lists", "💾 Import/Export"])
    
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
    
    with tab3:
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
    
    with tab4:
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
    st.sidebar.caption(f"Domain Sender Approval v2.1 | Analyzer v{ANALYZER_VERSION}")
    st.sidebar.caption(f"Threshold: {st.session_state.config.get('approve_threshold', 50)}")


if __name__ == "__main__":
    main()
