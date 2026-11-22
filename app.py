import ast
import json
import platform
import subprocess
import sys
import tempfile
import textwrap
import warnings
from pathlib import Path

import joblib
import sklearn
import streamlit as st


st.set_page_config(
    page_title="Python Vulnerability Detector",
    page_icon="🛡️",
    layout="wide",
)

APP_DIR = Path(__file__).resolve().parent


def prepare_source(value):
    return textwrap.dedent(value).strip()


# Must match the preprocessing used during training.
def model_text(code):
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        tree = ast.parse(code)

    for node in ast.walk(tree):
        if isinstance(
            node,
            (
                ast.Module,
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
            ),
        ):
            if (
                node.body
                and isinstance(node.body[0], ast.Expr)
                and isinstance(node.body[0].value, ast.Constant)
                and isinstance(node.body[0].value.value, str)
            ):
                node.body = node.body[1:]

                if not node.body and not isinstance(node, ast.Module):
                    node.body = [ast.Pass()]

    return ast.unparse(ast.fix_missing_locations(tree))


@st.cache_resource
def load_model():
    bundle = joblib.load(APP_DIR / "va_model.joblib")

    if bundle.get("sklearn_version") != sklearn.__version__:
        raise RuntimeError("The model requires its training library version.")

    trained_python = bundle.get("python_version", "").split(".")[:2]
    current_python = platform.python_version().split(".")[:2]

    if trained_python != current_python:
        raise RuntimeError("The model requires its training Python version.")

    if bundle.get("preprocessing") != "ast_unparse_strip_docstrings_v1":
        raise RuntimeError("Unsupported model preprocessing.")

    if bundle.get("hybrid_rule") not in ("Hybrid OR", "Hybrid AND"):
        raise RuntimeError("Unsupported combination rule.")

    if list(bundle["model"].classes_) != [0, 1]:
        raise RuntimeError("Unexpected model labels.")

    return bundle


def analyse_with_bandit(source):
    with tempfile.TemporaryDirectory() as folder:
        code_file = Path(folder) / "submitted_code.py"
        code_file.write_text(source, encoding="utf-8")

        process = subprocess.run(
            [
                sys.executable,
                "-m",
                "bandit",
                "-f",
                "json",
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
            raise RuntimeError("Bandit could not complete the analysis.")

        report = json.loads(process.stdout)

        if report.get("errors"):
            raise RuntimeError("Bandit could not analyse the submitted code.")

        if not isinstance(report.get("results"), list):
            raise RuntimeError("Bandit returned an invalid report.")

        if not any(
            name != "_totals"
            for name in report.get("metrics", {})
        ):
            raise RuntimeError("Bandit did not scan the submitted file.")

        return report["results"]


def recommendation(test_id):
    advice = {
        "B307": (
            "Avoid eval() on untrusted input. Use a parser appropriate "
            "for the expected data format."
        ),
        "B602": (
            "Review shell=True. Prefer an argument list with shell=False "
            "and validate external input."
        ),
        "B608": (
            "Use parameterized database queries. Avoid constructing "
            "SQL statements from external input."
        ),
        "B105": (
            "Review the possible hard-coded credential. Store real "
            "secrets outside source code."
        ),
        "B106": (
            "Review the possible hard-coded credential. Store real "
            "secrets outside source code."
        ),
    }

    return advice.get(
        test_id,
        "Review this finding in context and consult the relevant "
        "Bandit check documentation before changing the code.",
    )


st.title("🛡️ Python Vulnerability Detector")
st.write(
    "Inspect Python code using Bandit static analysis and an "
    "experimental machine learning classifier."
)

st.info(
    "Research prototype: the trained classifier has limited performance. "
    "Its prediction is a review signal, not a security verdict."
)

with st.form("analysis_form"):
    source_input = st.text_area(
        "Paste your Python code",
        height=300,
        max_chars=50000,
        placeholder="Enter a Python code snippet here...",
    )
    submitted = st.form_submit_button("Analyze Code", type="primary")

st.caption(
    "Submitted code is analysed without being executed. "
    "Inline # nosec comments do not suppress checks in this prototype. "
    "Use public or non-sensitive examples."
)

if submitted:
    source = prepare_source(source_input)

    if not source:
        st.error("Please enter Python code before requesting analysis.")
        st.stop()

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            ast.parse(source)
    except SyntaxError as exc:
        st.error(
            f"Python syntax error on line {exc.lineno}: {exc.msg}"
        )
        st.stop()
    except (ValueError, RecursionError, MemoryError):
        st.error("The submitted code could not be parsed.")
        st.stop()

    findings = None
    ml_flag = None
    bundle = None

    with st.spinner("Analysing code..."):
        try:
            findings = analyse_with_bandit(source)
        except subprocess.TimeoutExpired:
            st.error("Bandit analysis timed out. Try a smaller snippet.")
        except Exception:
            st.error(
                "Static analysis failed. This does not mean "
                "the code has no security issues."
            )

        try:
            bundle = load_model()
            processed = model_text(source)
            ml_flag = int(bundle["model"].predict([processed])[0])
        except Exception:
            st.error(
                "The machine learning component is unavailable. "
                "Its prediction and the combined result cannot be shown."
            )

    st.subheader("Analysis Summary")
    bandit_col, ml_col, combined_col = st.columns(3)

    with bandit_col:
        st.markdown("**Bandit static analysis**")

        if findings is None:
            st.write("Unavailable")
        else:
            st.metric("Findings", len(findings))

    with ml_col:
        st.markdown("**Experimental ML prediction**")

        if ml_flag is None:
            st.write("Unavailable")
        elif ml_flag == 1:
            st.warning("Classified as a vulnerable example")
        else:
            st.info("Classified as a patched example")

    with combined_col:
        st.markdown("**Combined review signal**")

        if findings is None or ml_flag is None:
            st.write("Unavailable")
        else:
            bandit_flag = bool(findings)
            rule = bundle["hybrid_rule"]

            if rule == "Hybrid OR":
                combined_flag = bandit_flag or bool(ml_flag)
            else:
                combined_flag = bandit_flag and bool(ml_flag)

            if combined_flag:
                st.warning("Potential issue signal — review required")
            else:
                st.info("Neither method flagged the snippet")

            if rule == "Hybrid OR":
                st.caption("OR rule: either method can trigger a review.")
            else:
                st.caption("AND rule: both methods must trigger a review.")

    if findings is not None:
        st.subheader("Static Analysis Details")

        if not findings:
            st.success("Analysis completed. Bandit reported no findings.")
        else:
            columns = st.columns(3)

            for column, severity in zip(
                columns, ["HIGH", "MEDIUM", "LOW"]
            ):
                count = sum(
                    item.get("issue_severity") == severity
                    for item in findings
                )
                column.metric(f"{severity.title()} severity", count)

            for number, item in enumerate(findings, start=1):
                test_id = item.get("test_id", "Unknown")
                line = item.get("line_number", "?")

                with st.expander(
                    f"{number}. {test_id} — Line {line}",
                    expanded=len(findings) == 1,
                ):
                    st.write(item.get("issue_text", "Review required."))
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
                    st.write(recommendation(test_id))

                    link = item.get("more_info", "")
                    if link.startswith("https://bandit.readthedocs.io/"):
                        st.link_button("Bandit check documentation", link)

    if ml_flag is not None:
        st.caption(
            "ML predicts a class for the whole snippet. It does not "
            "identify the vulnerability type or affected line. "
            "Recommendations above are based on Bandit findings."
        )

    st.caption(
        "Bandit confidence describes confidence in its finding; "
        "it is not a machine learning probability."
    )

    st.warning(
        "No detected issues does not guarantee secure code. "
        "A patched-class prediction does not establish that a snippet "
        "is safe. Review all outputs in context."
    )

    if bundle is not None:
        with st.expander("Research evaluation and limitations"):
            st.write(
                "On the held-out dataset of 732 examples, Hybrid OR "
                "achieved approximately 56.0% accuracy, 56.3% precision, "
                "82.3% recall, and 0.507 Macro F1."
            )
            st.write(
                "Overall performance is limited. These results apply "
                "to the evaluated dataset and do not establish "
                "performance on arbitrary Python snippets."
            )
            st.write(
                "The classifier was trained on vulnerable originals "
                "and patched versions. Source labels may be imperfect, "
                "and extracted functions may lack surrounding context."
            )
