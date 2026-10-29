
import re

import pandas as pd


# These are the that will rules help me recognize common failures in application logs.
# Each rule has a pattern to look for, its priority, and possible fixes.

FAILURE_RULES = [
    {
        "id": "database_pool_exhaustion",
        "name": "Database connection pool exhaustion",
        "pattern": (
            r"connection pool (?:exhausted|usage reached)"
        ),
        "service": "Database",
        "priority": 1,
        "explanation": (
            "The database connection pool appears to have "
            "reached capacity. Subsequent database timeouts "
            "and service failures may be related."
        ),
        "recommendations": [
            "Inspect active database connections and pool limits.",
            "Check for connection leaks or long-running queries.",
            "Review recent traffic spikes and database configuration."
        ]
    },
    {
        "id": "database_timeout",
        "name": "Database connection timeout",
        "pattern": r"connection timeout",
        "service": "Database",
        "priority": 2,
        "explanation": (
            "Database connection attempts are timing out. "
            "This may indicate connection exhaustion, "
            "network problems, or database unavailability."
        ),
        "recommendations": [
            "Check database availability and connectivity.",
            "Inspect connection pool utilization.",
            "Review database response times."
        ]
    },
    {
        "id": "memory_exhaustion",
        "name": "Memory exhaustion",
        "pattern": r"out of memory|memory exhausted|\boom\b",
        "service": None,
        "priority": 1,
        "explanation": (
            "The logs indicate memory exhaustion, which "
            "may have disrupted application processing."
        ),
        "recommendations": [
            "Inspect application memory usage.",
            "Check for memory leaks.",
            "Review memory limits and recent workload changes."
        ]
    },
    {
        "id": "service_unavailable",
        "name": "Service unavailability",
        "pattern": r"service unavailable|connection refused",
        "service": None,
        "priority": 3,
        "explanation": (
            "A service appears unreachable or unavailable."
        ),
        "recommendations": [
            "Verify service health and availability.",
            "Inspect network connectivity.",
            "Check recent service deployments."
        ]
    }
]




SERVICE_DEPENDENCIES = {
    "database": {
        "database",
        "paymentservice",
        "orderservice",
        "apigateway"
    },
    "imageservice": {
        "imageservice"
    }
}


#Compliling

MEMORY_PATTERN = re.compile(
    r"out of memory|memory exhausted|\boom\b",
    re.IGNORECASE
)


def is_related_event(event, initiating_event, rule):
    """
    Check whether a log event is related to the failure we are investigating.
    We use the service name and failure type to make this decision.
    This only identifies possible connections, not confirmed causes.
    """

    service = str(event["service"]).lower()

    initiating_service = str(
        initiating_event["service"]
    ).lower()

    message = str(event["message"])

    rule_id = rule["id"]



    if (
        rule_id in {
            "database_pool_exhaustion",
            "database_timeout"
        }
        and MEMORY_PATTERN.search(message)
    ):
        return False

    # Database problems can affect other services that depend on it.
   

    if rule_id in {
        "database_pool_exhaustion",
        "database_timeout"
    }:
        return service in SERVICE_DEPENDENCIES["database"]

    # For memory issues, only look at events from the same service.

    if rule_id == "memory_exhaustion":
        return service == initiating_service

    # For unavailable services, keep the investigation within that service.

    if rule_id == "service_unavailable":
        return service == initiating_service

    return service == initiating_service


def analyze_logs(df):
    """
    Go through the parsed logs, look for known failures, and collect
    the information needed to build an investigation report.
    """

    # Return an empty report if there are no logs to investigate.

    if df.empty:
        return {
            "status": "no_data",
            "summary": {},
            "hypothesis": None,
            "evidence": [],
            "timeline": []
        }

    error_levels = ["ERROR", "CRITICAL"]
    warning_levels = ["WARN", "WARNING"]

    relevant_levels = error_levels + warning_levels

    # Count errors and warnings, and find which services were affected.

    errors = df[
        df["level"].isin(error_levels)
    ]

    warnings = df[
        df["level"].isin(warning_levels)
    ]

    affected_services = sorted(
        df[
            df["level"].isin(relevant_levels)
        ]["service"].unique().tolist()
    )

    summary = {
        "total_events": len(df),
        "error_count": len(errors),
        "warning_count": len(warnings),
        "affected_services": affected_services
    }

    # Check each error or warning against our known failure rules.
  

    matches = []

    for _, event in df.iterrows():

        if event["level"] not in relevant_levels:
            continue

        for rule in FAILURE_RULES:

            # Some rules only apply to a particular service.
          

            if (
                rule["service"] is not None
                and str(event["service"]).lower()
                != rule["service"].lower()
            ):
                continue

            # Save the rule and log event whenever the message matches.

            if re.search(
                rule["pattern"],
                str(event["message"]),
                flags=re.IGNORECASE
            ):
                matches.append({
                    "rule": rule,
                    "event": event
                })

    # Build a timeline using errors and warnings.
    

    timeline = df[
        df["level"].isin(relevant_levels)
    ].copy()

    timeline = timeline.sort_values(
        by=["timestamp", "line_number"]
    )

    timeline_records = []

    for _, event in timeline.iterrows():

        timeline_records.append({
            "timestamp": str(event["timestamp"]),
            "level": event["level"],
            "service": event["service"],
            "message": event["message"],
            "line_number": int(event["line_number"])
        })

    # We might find errors without recognizing any known failure pattern.
    

    if not matches:
        return {
            "status": "no_known_pattern",
            "summary": summary,
            "hypothesis": None,
            "evidence": [],
            "timeline": timeline_records
        }

    # Choose the leading failure based on rule priority.
    # Lower numbers come first, and ties are resolved using the earliest log.

    matches.sort(
        key=lambda match: (
            match["rule"]["priority"],
            match["event"]["timestamp"],
            match["event"]["line_number"]
        )
    )

    selected = matches[0]

    selected_rule = selected["rule"]
    initiating_event = selected["event"]

    # Look at events occurring within 60 seconds after the selected failure.
    # This is so that it will give me a smaller set of logs to investigate for related problems.

    window_end = (
        initiating_event["timestamp"]
        + pd.Timedelta(seconds=60)
    )

    candidate_events = timeline[
        (
            timeline["timestamp"]
            >= initiating_event["timestamp"]
        )
        &
        (
            timeline["timestamp"]
            <= window_end
        )
    ]

    # Events happening close together are not always connected.
    # Check their service and failure type before treating them as evidence.

    related_events = candidate_events[
        candidate_events.apply(
            lambda event: is_related_event(
                event,
                initiating_event,
                selected_rule
            ),
            axis=1
        )
    ]

    # Collect the related log entries so they can be shown as evidenc in the investigation report.

    evidence = []

    for _, event in related_events.iterrows():

        evidence.append({
            "timestamp": str(event["timestamp"]),
            "level": event["level"],
            "service": event["service"],
            "message": event["message"],
            "line_number": int(event["line_number"])
        })

    # Put together the likely failure, its explanation, suggested fixes and the number of log entries supporting the investigation.

    hypothesis = {
        "id": selected_rule["id"],
        "name": selected_rule["name"],
        "explanation": selected_rule["explanation"],
        "recommendations": selected_rule["recommendations"],
        "initiating_line": int(
            initiating_event["line_number"]
        ),
        "evidence_count": len(evidence)
    }

    # Return everything the dashboard 

    return {
        "status": "investigated",
        "summary": summary,
        "hypothesis": hypothesis,
        "evidence": evidence,
        "timeline": timeline_records
    }
