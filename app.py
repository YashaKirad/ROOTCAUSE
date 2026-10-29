
import json
import hashlib
from datetime import datetime
from pathlib import Path

import pandas as pd
import streamlit as st

from log_parser import parse_logs
from analyzer import analyze_logs


# Set up the dashboard layout 

st.set_page_config(
    page_title="RootCause AI | Incident Investigation",
    page_icon=":material/troubleshoot:",
    layout="wide",
    initial_sidebar_state="expanded"
)

BASE_DIR = Path(__file__).resolve().parent
SAMPLE_DIR = BASE_DIR / "sample_logs"


#css for it

st.markdown("""
<style>
    .block-container {
        padding-top: 3.5rem;
        padding-bottom: 3rem;
        max-width: 1450px;
    }

    h1, h2, h3 {
        letter-spacing: -0.025em;
    }

    h1 {
        font-size: 2.1rem !important;
        font-weight: 700 !important;
    }

    [data-testid="stMetric"] {
        border: 1px solid rgba(128,128,128,0.20);
        border-radius: 10px;
        padding: 18px;
    }

    [data-testid="stMetricValue"] {
        font-size: 1.8rem;
        font-weight: 650;
    }

    [data-testid="stSidebar"] {
        border-right: 1px solid rgba(128,128,128,0.15);
    }

    .section-label {
        font-size: 0.8rem;
        font-weight: 600;
        letter-spacing: 0.08em;
        text-transform: uppercase;
        opacity: 0.85;
        margin-top: 10px;
        margin-bottom: 12px;
        line-height: 1.6;
    }

    .app-subtitle {
        font-size: 1rem;
        opacity: 0.75;
        margin-top: -8px;
        margin-bottom: 24px;
    }

    div.stButton > button[kind="primary"] {
        border-radius: 8px;
        font-weight: 600;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 8px;
        overflow: hidden;
    }
</style>
""", unsafe_allow_html=True)




def prepare_table(records):
    
    df = pd.DataFrame(records)

    if df.empty:
        return df

    rename_columns = {
        "timestamp": "Timestamp",
        "level": "Severity",
        "service": "Service",
        "message": "Message",
        "line_number": "Line"
    }

    return df.rename(columns=rename_columns)


def generate_report(investigation):
  
    result = investigation["result"]
    hypothesis = result["hypothesis"]

    return {
        "application": "RootCause AI",
        "report_type": "Application Failure Investigation",
        "generated_at": datetime.now().astimezone().isoformat(),
        "source_file": investigation["filename"],
        "analysis_method": "Rule-based pattern detection",
        "status": result["status"],
        "summary": result["summary"],
        "invalid_line_count": len(
            investigation["invalid_lines"]
        ),
        "hypothesis": hypothesis,
        "supporting_evidence": result["evidence"],
        "failure_timeline": result["timeline"],
        "limitations": [
            "The analysis is based on predefined rules.",
            "A hypothesis does not establish causality.",
            "Nearby events may not be causally related.",
            "Only one leading hypothesis is reported.",
            "Service dependencies are predefined."
        ]
    }
#report

def generate_markdown_report(report):
    
    summary = report["summary"]
    hypothesis = report["hypothesis"]

    # Start with the source details and a quick summary of the logs.

    lines = [
        "# RootCause AI - Investigation Report",
        "",
        f"**Source:** {report['source_file']}",
        f"**Generated:** {report['generated_at']}",
        f"**Status:** {report['status']}",
        f"**Method:** {report['analysis_method']}",
        "",
        "## Investigation Overview",
        "",
        f"- Total events: {summary.get('total_events', 0)}",
        f"- Errors: {summary.get('error_count', 0)}",
        f"- Warnings: {summary.get('warning_count', 0)}",
        f"- Invalid lines: {report['invalid_line_count']}",
        "- Affected services: "
        + ", ".join(summary.get("affected_services", [])),
        "",
        "## Root-Cause Assessment",
        ""
    ]

    
    if hypothesis:
        lines.extend([
            f"### {hypothesis['name']}",
            "",
            hypothesis["explanation"],
            "",
            f"Initiating log line: {hypothesis['initiating_line']}",
            "",
            "## Supporting Evidence",
            ""
        ])

        for event in report["supporting_evidence"]:
            lines.append(
                f"- Line {event['line_number']} | "
                f"{event['timestamp']} | "
                f"{event['service']} | "
                f"{event['level']} | "
                f"{event['message']}"
            )

        lines.extend([
            "",
            "## Recommended Next Steps",
            ""
        ])

        for step in hypothesis["recommendations"]:
            lines.append(f"- {step}")

    else:
        lines.append(
            "No recognized root-cause pattern was identified."
        )

    
    lines.extend([
        "",
        "## Full Failure Timeline",
        ""
    ])

    for event in report["failure_timeline"]:
        lines.append(
            f"- {event['timestamp']} | "
            f"{event['service']} | "
            f"{event['level']} | "
            f"{event['message']}"
        )

    # Adding the limitations so the report doesn't present a possible cause as something that has been proven.

    lines.extend([
        "",
        "## Limitations",
        ""
    ])

    for limitation in report["limitations"]:
        lines.append(f"- {limitation}")

    return "\n".join(lines)


def get_sample_files():
   
    if not SAMPLE_DIR.exists():
        return {}

    return {
        str(path.relative_to(SAMPLE_DIR)): path
        for path in sorted(SAMPLE_DIR.rglob("*.log"))
    }


# For movable sidebar

with st.sidebar:

    st.title("RootCause AI")
    st.caption("Incident Investigation Workspace")

    st.divider()

    st.markdown("### Data Source")

    source_mode = st.radio(
        "Choose an input method",
        ["Upload File", "Sample Scenario"],
        label_visibility="collapsed"
    )

    log_text = None
    filename = None

    #upload or maybe try a sample log 

    if source_mode == "Upload File":

        uploaded_file = st.file_uploader(
            "Application log",
            type=["log", "txt"],
            help="Upload a UTF-8 encoded application log."
        )

        if uploaded_file is not None:
            filename = uploaded_file.name

            try:
                log_text = uploaded_file.getvalue().decode(
                    "utf-8"
                )
            except UnicodeDecodeError:
                st.error(
                    "Unsupported encoding. "
                    "Please provide a UTF-8 file."
                )

    else:

        samples = get_sample_files()

        if samples:

            selected_sample = st.selectbox(
                "Select a scenario",
                options=list(samples.keys())
            )

            filename = selected_sample

            try:
                log_text = samples[
                    selected_sample
                ].read_text(encoding="utf-8")
            except (UnicodeDecodeError, OSError):
                st.error(
                    "The selected sample could not be read."
                )

            st.caption(
                "Sample scenarios use synthetic data."
            )

        else:
            st.warning("No sample logs found.")

    st.divider()

    
    current_source_id = (
        hashlib.sha256(
            (filename or "").encode("utf-8")
            + b"\0"
            + log_text.encode("utf-8")
        ).hexdigest()
        if log_text is not None
        else None
    )

 #restart the session so it removes the prev log if file change

    if st.session_state.get("source_id") != current_source_id:
        st.session_state["source_id"] = current_source_id
        st.session_state.pop("investigation", None)

    investigate_clicked = st.button(
        "Run Investigation",
        type="primary",
        use_container_width=True,
        disabled=log_text is None
    )

    st.divider()

    st.markdown("### Analysis Configuration")

    st.caption("Detection method")
    st.write("Rule-based pattern matching")

    st.caption("Evidence window")
    st.write("60 seconds")

    st.caption("Data processing")
    st.write("Local, in-memory")


# Run the parser and analyzer when the user starts an investigation.

if investigate_clicked:

    if not log_text or not log_text.strip():
        st.warning("The selected log file is empty.")

    else:
        with st.spinner("Processing log events..."):

            df, invalid_lines = parse_logs(log_text)
            result = analyze_logs(df)

            #if tab switching let the current session keep going

            st.session_state["investigation"] = {
                "filename": filename,
                "dataframe": df,
                "invalid_lines": invalid_lines,
                "result": result
            }


#MAIN DASHBOARDDDDDDD

st.markdown(
    '<div class="section-label">'
    'Developer Tools / Observability'
    '</div>',
    unsafe_allow_html=True
)

st.title("Application Failure Investigation")

st.markdown(
    '<div class="app-subtitle">'
    'Analyze application logs, trace failure signals, '
    'and review evidence-supported diagnoses.'
    '</div>',
    unsafe_allow_html=True
)




if "investigation" not in st.session_state:

    st.divider()

    st.subheader("Start an Investigation")

    st.write(
        "Upload an application log or select a sample "
        "scenario from the sidebar to begin."
    )

    col1, col2, col3 = st.columns(3)

    with col1:
        with st.container(border=True):
            st.markdown("**01 / Ingest**")
            st.write(
                "Parse timestamps, severity levels, "
                "services, and log messages."
            )

    with col2:
        with st.container(border=True):
            st.markdown("**02 / Investigate**")
            st.write(
                "Identify known failure patterns and "
                "examine related events."
            )

    with col3:
        with st.container(border=True):
            st.markdown("**03 / Report**")
            st.write(
                "Review hypotheses, supporting evidence, "
                "and recommended next steps."
            )

    st.info(
        "This prototype uses explainable rule-based "
        "analysis. It does not use a trained AI model."
    )

    st.stop()




investigation = st.session_state["investigation"]

df = investigation["dataframe"]
invalid_lines = investigation["invalid_lines"]
result = investigation["result"]

summary = result["summary"]
hypothesis = result["hypothesis"]

st.caption(f"Source: {investigation['filename']}")



if df.empty:
    st.error(
        "No valid log entries were found. "
        "Review the input format and rejected lines."
    )

    if invalid_lines:
        st.dataframe(
            pd.DataFrame(invalid_lines),
            hide_index=True,
            use_container_width=True
        )

    st.stop()




col1, col2, col3, col4 = st.columns(4)

col1.metric(
    "Total Events",
    summary["total_events"]
)

col2.metric(
    "Errors",
    summary["error_count"]
)

col3.metric(
    "Warnings",
    summary["warning_count"]
)

col4.metric(
    "Affected Services",
    len(summary["affected_services"])
)

st.write("")


# Split the results 
tab_overview, tab_investigation, tab_explorer, tab_export = (
    st.tabs([
        "Overview",
        "Investigation",
        "Event Explorer",
        "Export Report"
    ])
)




with tab_overview:

    st.subheader("Incident Overview")

    left, right = st.columns([1.3, 1])

    with left:

        with st.container(border=True):

            st.markdown("#### Investigation Status")

            if hypothesis:

                st.warning(
                    "Recognized failure pattern detected"
                )

                st.markdown(
                    f"**Leading hypothesis:** "
                    f"{hypothesis['name']}"
                )

                st.write(hypothesis["explanation"])

            elif (
                summary["error_count"] == 0
                and summary["warning_count"] == 0
            ):

                st.success(
                    "No errors or warnings detected "
                    "in the supplied log entries."
                )

            else:

                st.info(
                    "Errors or warnings were detected, "
                    "but no known root-cause pattern matched."
                )

            st.caption(
                "Findings are hypotheses, not confirmed "
                "causal diagnoses."
            )

    with right:

        with st.container(border=True):

            st.markdown("#### Event Severity")


            severity = (
                df["level"]
                .value_counts()
                .rename_axis("Severity")
                .reset_index(name="Events")
            )

            st.bar_chart(
                severity.set_index("Severity"),
                horizontal=True,
                height=220
            )

    st.subheader("Affected Services")

    if summary["affected_services"]:

   
        service_counts = (
            df[df["level"].isin([
                "WARN", "WARNING", "ERROR", "CRITICAL"
            ])]
            .groupby("service")
            .size()
            .sort_values(ascending=False)
        )

        st.bar_chart(
            service_counts,
            horizontal=True
        )

    else:
        st.info("No affected services identified.")

    if invalid_lines:
        st.warning(
            f"{len(invalid_lines)} lines could not be parsed. "
            "See Event Explorer for details."
        )




with tab_investigation:

    st.subheader("Root-Cause Assessment")

    if hypothesis:

        with st.container(border=True):

            st.markdown(
                '<div class="section-label">'
                'Leading Hypothesis</div>',
                unsafe_allow_html=True
            )

            st.markdown(f"### {hypothesis['name']}")

            st.write(hypothesis["explanation"])

            st.markdown(
                f"**Initiating signal:** "
                f"Log line {hypothesis['initiating_line']}"
            )

            st.markdown(
                f"**Evidence entries:** "
                f"{hypothesis['evidence_count']}"
            )

            st.caption(
                "The selected signal is not necessarily "
                "the proven initiating cause."
            )

        st.markdown("### Supporting Evidence")

        evidence_df = prepare_table(result["evidence"])

        if not evidence_df.empty:

            st.dataframe(
                evidence_df,
                use_container_width=True,
                hide_index=True
            )

        st.caption(
            "Events are selected using the investigation "
            "window and predefined service relationships. "
            "Inclusion does not prove causation."
        )

        st.markdown("### Recommended Investigation Steps")

        for index, step in enumerate(
            hypothesis["recommendations"], start=1
        ):
            st.markdown(f"{index}. {step}")

    else:

        st.info(
            "No recognized root-cause hypothesis "
            "is available for this investigation."
        )

    st.divider()

    st.subheader("Failure Timeline")


    timeline_df = prepare_table(result["timeline"])

    if not timeline_df.empty:

        st.dataframe(
            timeline_df,
            use_container_width=True,
            hide_index=True
        )

    else:
        st.info("No warning or error events to display.")




with tab_explorer:

    st.subheader("Event Explorer")

    st.caption(
        "Filter parsed events by severity, service, "
        "or message content."
    )

    filter1, filter2 = st.columns(2)

    with filter1:

        selected_levels = st.multiselect(
            "Severity",
            options=sorted(df["level"].unique()),
            default=sorted(df["level"].unique())
        )

    with filter2:

        selected_services = st.multiselect(
            "Service",
            options=sorted(df["service"].unique()),
            default=sorted(df["service"].unique())
        )

    search_query = st.text_input(
        "Search log messages",
        placeholder="e.g. timeout, connection, payment"
    )

    # Apply the selected severity and service filters first.
    filtered_df = df[
        df["level"].isin(selected_levels)
        & df["service"].isin(selected_services)
    ].copy()

    

    if search_query.strip():

        filtered_df = filtered_df[
            filtered_df["message"].str.contains(
                search_query,
                case=False,
                regex=False,
                na=False
            )
        ]

    st.caption(
        f"Showing {len(filtered_df)} of {len(df)} events"
    )

    st.dataframe(
        prepare_table(filtered_df),
        use_container_width=True,
        hide_index=True,
        height=420
    )

    

    with st.expander(
        f"Rejected Log Lines ({len(invalid_lines)})"
    ):

        if invalid_lines:

            st.dataframe(
                pd.DataFrame(invalid_lines),
                use_container_width=True,
                hide_index=True
            )

        else:
            st.success("All non-empty lines were parsed.")

#download options

with tab_export:

    st.subheader("Export Investigation Report")

    st.write(
        "Download the investigation findings, "
        "supporting evidence, event timeline, "
        "and recommended next steps."
    )

    report = generate_report(investigation)

    markdown_report = generate_markdown_report(report)

    json_report = json.dumps(
        report,
        indent=2,
        default=str
    )

    export1, export2 = st.columns(2)

    with export1:

        with st.container(border=True):

            st.markdown("#### Markdown Report")

            st.write(
                "A readable investigation document "
                "suitable for sharing or reviewing."
            )

            st.download_button(
                "Download Markdown",
                data=markdown_report,
                file_name="rootcause_report.md",
                mime="text/markdown",
                use_container_width=True
            )

    with export2:

        with st.container(border=True):

            st.markdown("#### JSON Report")

            st.write(
                "Structured investigation data "
                "for programmatic use."
            )

            st.download_button(
                "Download JSON",
                data=json_report,
                file_name="rootcause_report.json",
                mime="application/json",
                use_container_width=True
            )

    st.divider()

    # Initial few lines preview of the repot

    with st.expander("Preview Report"):

        st.markdown(markdown_report)
