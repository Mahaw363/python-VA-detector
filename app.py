import ast
import json
import subprocess
import sys
import tempfile
from pathlib import Path

import streamlit as st


st.set_page_config(
    page_title="Python Vulnerability Detector",
    page_icon="🛡️",
    layout="wide",
)


def analyse_code(source):
    with tempfile.TemporaryDirectory() as folder:
        code_file = Path(folder) / "submitted_code.py"
        report_file = Path(folder) / "report.json"

        # Save the submitted code as text. Never execute it.
        code_file.write_text(source, encoding="utf-8")

        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
                "-o",
                str(report_file),
                "-q",
                "--ignore-nosec",
                str(code_file),
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
            cwd=folder,
        )

        if process.returncode not in (0, 1):
            details = process.stderr.strip()
            raise RuntimeError(
                f"Bandit exit code: {process.returncode}\n"
                f"{details or 'No diagnostic message returned.'}"
            )

        if not report_file.exists():
            details = process.stderr.strip()
            raise RuntimeError(
                "Bandit did not create a report.\n"
                f"{details or 'No diagnostic message returned.'}"
            )

        try:
            report = json.loads(
                report_file.read_text(encoding="utf-8")
            )
        except json.JSONDecodeError as error:
            raise RuntimeError(
                "Bandit returned an unreadable report.\n"
                f"{error}\n{process.stderr.strip()}"
            ) from error

        if not isinstance(report, dict):
            raise RuntimeError("Unexpected Bandit report format.")

        errors = report.get("errors", [])
        if errors:
            reasons = [
                str(item.get("reason", "Unknown processing error"))
                if isinstance(item, dict)
                else str(item)
                for item in errors
            ]
            raise RuntimeError(
                "Bandit could not process the code:\n"
                + "\n".join(reasons)
            )

        findings = report.get("results")
        if not isinstance(findings, list):
            raise RuntimeError(
                "The Bandit report is missing its results list."
            )

        return findings


def recommendation(check_id):
    guidance = {
        "B307": (
            "Review eval(). Avoid evaluating untrusted input. "
            "Use a parser appropriate for the expected data format."
        ),
        "B602": (
            "Review shell=True. Prefer an argument list with "
            "shell=False and validate user-controlled arguments."
        ),
        "B608": (
            "Review the SQL statement construction. "
            "Use parameterized queries for user-supplied values."
        ),
        "B105": (
            "Check whether this value is a real credential. "
            "Store real secrets outside source code."
        ),
        "B106": (
            "Review the apparent hard-coded password argument. "
            "Use an appropriate secrets management mechanism."
        ),
    }

    return guidance.get(
        check_id,
        "Review this finding in its application context and "
        "consult the corresponding Bandit documentation.",
    )


st.title("🛡️ Python Vulnerability Detector")
st.write(
    "Inspect Python code for potential security issues "
    "and review relevant recommendations."
)

st.info(
    "Current version: Bandit static analysis. "
    "The machine learning component is not connected yet."
)

with st.form("analysis_form"):
    source = st.text_area(
        "Paste your Python code",
        height=320,
        max_chars=50000,
        placeholder="Enter a Python code snippet here...",
    )
    submitted = st.form_submit_button("Analyze Code")

st.caption(
    "Code is analysed without being executed. "
    "Inline # nosec comments do not suppress checks in this prototype. "
    "Use public or non-sensitive examples."
)

if submitted:
    if not source.strip():
        st.error("Please enter Python code before requesting analysis.")
        st.stop()

    try:
        ast.parse(source)
    except SyntaxError as error:
        st.error(
            f"Python syntax error on line {error.lineno}: {error.msg}"
        )
        st.stop()
    except (ValueError, RecursionError, MemoryError):
        st.error("The input could not be parsed. Try a smaller snippet.")
        st.stop()

    try:
        with st.spinner("Analysing your code..."):
            findings = analyse_code(source)
    except subprocess.TimeoutExpired:
        st.error("Analysis timed out. Try a smaller code snippet.")
        st.stop()
    except (RuntimeError, OSError, UnicodeError) as error:
        st.error(
            "Static analysis failed. "
            "This does not mean the code has no security issues."
        )
        st.write("Diagnostic details:")
        st.code(f"{type(error).__name__}: {error}", language="text")
        st.stop()

    st.subheader("Static Analysis Results")

    columns = st.columns(4)
    columns[0].metric("Total findings", len(findings))

    for column, severity in zip(
        columns[1:], ["HIGH", "MEDIUM", "LOW"]
    ):
        count = sum(
            item.get("issue_severity") == severity
            for item in findings
        )
        column.metric(f"{severity.title()} severity", count)

    if not findings:
        st.success("Analysis completed. Bandit reported no findings.")
    else:
        st.warning(
            "Potential security issues were detected. "
            "Review each finding in context."
        )

        for number, item in enumerate(findings, start=1):
            check_id = item.get("test_id", "Unknown")
            line = item.get("line_number", "Unknown")

            with st.expander(
                f"{number}. {check_id} — Line {line}",
                expanded=True,
            ):
                st.write(item.get("issue_text", ""))
                st.write(
                    "Severity:",
                    item.get("issue_severity", "Unknown"),
                )
                st.write(
                    "Confidence:",
                    item.get("issue_confidence", "Unknown"),
                )
                st.code(item.get("code", ""), language="python")
                st.markdown("**Recommendation**")
                st.write(recommendation(check_id))

    st.caption(
        "Severity describes potential seriousness. "
        "Confidence describes Bandit's confidence in the finding; "
        "it is not an ML probability."
    )

    st.warning(
        "No detected issues does not guarantee secure code. "
        "Machine learning and combined results are unavailable "
        "in this version."
    )
