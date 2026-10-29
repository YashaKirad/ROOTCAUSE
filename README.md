# RootCause AI — Intelligent Failure Investigator


RootCause AI helps developers move from a noisy application log to a focused investigation: it parses events, identifies known failure signatures, collects related evidence, and presents a leading hypothesis with a timeline and practical next checks. It is a working rule-based MVP, not an automated proof of causality or an LLM-powered diagnosis engine.

## Why I built it

Debugging a backend failure often means reading timestamped messages from multiple services and distinguishing an initiating problem from downstream symptoms. This is a recurring engineering challenge I encountered while working on software and backend projects. I wanted to test whether a small, transparent tool could reduce the initial effort of finding useful signals without inventing an explanation when the evidence is insufficient.

The prototype was developed in **3 hours and 48 minutes** for the MiraFlores AI case study. All included incidents are **synthetic**; no production or employer logs are used.

## What the prototype does

- **Upload logs or choose a sample:** Accept UTF-8 `.log` and `.txt` files or select built-in synthetic scenarios.
- **Parse and validate:** Extract timestamps, severity, service, and message; preserve original line numbers; separate malformed lines; sort valid events chronologically.
- **Detect known failures:** Recognize database connection pool exhaustion, database connection timeouts, memory exhaustion, and service unavailability.
- **Correlate supporting evidence:** Collect relevant warning/error events within a **60-second forward window**, using predefined service relationships.
- **Explain the result:** Show one leading hypothesis, supporting log evidence, a timeline, affected services, and suggested investigation steps.
- **Explore and export:** Review overview metrics and charts, filter events, and download Markdown or JSON investigation reports.
- **Handle uncertainty:** If errors do not match a known pattern, report **no known pattern** rather than inventing a cause.

## Tech stack

- **Python** — parsing, validation, and deterministic investigation logic
- **Pandas** — structured event processing and analysis
- **Streamlit** — interactive upload, dashboard, investigation, and export interface
- **Python `unittest`** — regression and edge-case tests

**No API key, paid service, trained model, or LLM call is required to run the MVP.**

Requires Python 3 and the packages `streamlit` and `pandas`.

```bash
pip install streamlit pandas
python -m streamlit run app.py
```

Open the local URL shown in the terminal. Upload a UTF-8 `.log` or `.txt` file, or select a sample scenario from the sidebar, then click **Run Investigation**.

Expected log format:

```text
2026-10-28 14:21:15 ERROR ResponseService Downstream API timeout during response generation
```

Each line should contain a timestamp (`YYYY-MM-DD HH:MM:SS`), severity, service name, and message.

## Project files

| File or folder | Purpose |
| --- | --- |
| `app.py` | Streamlit interface, charts, filters, and report downloads |
| `log_parser.py` | Parses and validates log entries |
| `analyzer.py` | Matches known failure patterns and selects supporting events |
| `test_cases.py` | Automated tests for the original scenarios |
| `sample_logs/` | Basic demonstration logs |
| `sample_logs/edge_cases/` | Empty, malformed, mixed-quality, out-of-order, unknown, and multiple-incident examples |
| `sample_logs/project_scenarios/` | Synthetic logs inspired by earlier chatbot and NLP data-processing work |

## Sample scenarios

Start with `database_failure.log` to see a recognized failure and its supporting evidence. `healthy_application.log` shows how the app handles normal activity. The files in `edge_cases/` cover invalid input, event ordering, unknown errors, and independent incidents.

The two files in `project_scenarios/` model a chatbot response timeout and an NLP annotation pipeline failure. They are **synthetic examples**, not original production or internship logs. The current analyzer can parse and display these events but does not have rules to diagnose either failure type.

## Tests

Run the original automated tests with:

```bash
python test_cases.py
```

The tests cover normal behavior and edge cases. Review the terminal output to confirm the results in your environment.

## Limitations

- Detection is limited to four predefined failure patterns.
- The analyzer returns one leading hypothesis, not separate diagnoses for every incident.
- The 60-second evidence window and service relationships are heuristics; nearby events are not necessarily causally related.
- Unknown failures remain visible in the timeline but do not receive a diagnosis.
- Logs are processed locally in memory. There is no persistent incident history or live log ingestion.

## Next steps

The next improvements would be grouping independent incidents, correlating events using request or trace IDs, and testing against a wider range of log formats. A later version could add persistent storage, live ingestion, and AI-assisted explanations grounded in specific log evidence.

## Development note

The initial prototype was built in **3 hours and 48 minutes**. AI tools were used to help draft and refine code, test scenarios, and documentation; the current investigation logic itself uses deterministic rules rather than an AI model.
