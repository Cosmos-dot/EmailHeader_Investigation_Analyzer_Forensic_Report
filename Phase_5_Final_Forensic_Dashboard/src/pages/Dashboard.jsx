import { useState } from "react";
import axios from "axios";
import "./Dashboard.css";

const API_URL = "http://localhost:5001";

function Dashboard() {
  const [file, setFile] = useState(null);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const analyzeFile = async () => {
    if (!file) {
      setError("Please select an .eml file.");
      return;
    }

    setLoading(true);
    setError("");
    setResult(null);

    try {
      const formData = new FormData();
      formData.append("email", file);

      const response = await axios.post(
        `${API_URL}/verify`,
        formData
      );

      console.log(
        "VERIFICATION RESULT:",
        response.data
      );

      if (!response.data?.success) {
        throw new Error(
          response.data?.message ||
            "Email verification failed."
        );
      }

      setResult(response.data);
    } catch (err) {
      console.error(
        "EML VERIFICATION ERROR:",
        err
      );

      setError(
        err.response?.data?.message ||
          err.response?.data?.error ||
          err.message ||
          "Unable to verify the EML file."
      );
    } finally {
      setLoading(false);
    }
  };

  const clearAnalysis = () => {
    setFile(null);
    setResult(null);
    setError("");

    const input =
      document.getElementById("emlFile");

    if (input) {
      input.value = "";
    }
  };

  const display = (value) => {
    if (
      value === null ||
      value === undefined ||
      value === ""
    ) {
      return "Not available";
    }

    return String(value);
  };

  const getStatusClass = (value) => {
    const status =
      String(value || "").toLowerCase();

    if (status === "pass") {
      return "status-pass";
    }

    if (
      status === "fail" ||
      status === "failure"
    ) {
      return "status-fail";
    }

    if (
      status.includes("neutral") ||
      status.includes("softfail")
    ) {
      return "status-warning";
    }

    return "status-unknown";
  };

  const authentication =
    result?.authentication || {};

  const summary =
    result?.summary || {};

  const smtp =
    result?.smtpEvidence || {};

  const alignment =
    result?.explicitDMARCAlignment || {};

  const spf =
    summary.spf ||
    authentication.spf?.status?.result ||
    "unknown";

  const dkim =
    summary.dkim ||
    authentication.dkim?.results?.[0]
      ?.status?.result ||
    "unknown";

  const dmarc =
    summary.dmarc ||
    authentication.dmarc?.status?.result ||
    "unknown";

  // DMARC result reported by the main
  // authentication verification engine
  const reportedDmarc =
    alignment.mailauthDMARCResult ||
    dmarc;

  // DMARC result independently calculated
  // using explicit SPF/DKIM alignment
  const independentDmarc =
    alignment.dmarc?.calculatedResult ||
    "unknown";

  // Whether both DMARC calculations agree
  const resultsAgree =
    alignment.resultsAgree;

  const spfAlignment =
    alignment.spf?.dmarcAligned;

  const dkimAlignment =
    alignment.dkim?.aligned;

  const dmarcPassedBy =
    alignment.dmarc?.passedBy || "none";

  const dmarcExplanation =
    alignment.explanation ||
    "No DMARC explanation available.";

  return (
    <div className="forensic-dashboard">

      {/* HEADER */}

      <header className="forensic-header">
        <div className="brand-section">

          <div className="brand-symbol">
            ✉
          </div>

          <div>
            <h1>
              Email Header Investigation Analyzer
            </h1>

            <p>
              Digital Forensic Email Analysis
              Platform
            </p>
          </div>

        </div>

        <div className="final-label">
          FINAL FORENSIC ANALYSIS
        </div>
      </header>

      {/* INPUT */}

      <main className="dashboard-container">

        <section className="investigation-panel">

          <div className="section-heading">

            <div>
              <h2>
                Email Investigation
              </h2>

              <p>
                Upload an EML file for independent
                forensic authentication verification.
              </p>
            </div>

            {result && (
              <button
                className="clear-button"
                onClick={clearAnalysis}
              >
                Clear Analysis
              </button>
            )}

          </div>

          <div className="eml-section">

            <div className="upload-symbol">
              📎
            </div>

            <h3>
              Upload EML File
            </h3>

            <p>
              Upload the original .eml file for
              complete forensic analysis.
            </p>

            <label
              htmlFor="emlFile"
              className="file-label"
            >
              Choose EML File
            </label>

            <input
              id="emlFile"
              type="file"
              accept=".eml,message/rfc822"
              onChange={(event) => {
                setFile(
                  event.target.files?.[0] ||
                    null
                );

                setError("");
                setResult(null);
              }}
            />

            {file && (
              <div className="selected-file">
                <span>📄</span>
                <span>{file.name}</span>
              </div>
            )}

            <button
              className="analyze-button"
              onClick={analyzeFile}
              disabled={loading || !file}
            >
              {loading
                ? "Verifying..."
                : "Analyze EML File"}
            </button>

          </div>

          {error && (
            <div className="error-message">

              <strong>
                Analysis Error:
              </strong>

              <span>
                {error}
              </span>

            </div>
          )}

        </section>

        {/* RESULTS */}

        {result && (
          <section className="forensic-results">

            <div className="results-header">

              <div>
                <h2>
                  Forensic Analysis Results
                </h2>

                <p>
                  Independent email authentication
                  verification completed.
                </p>
              </div>

              <div className="analysis-complete">
                ✓ ANALYSIS COMPLETE
              </div>

            </div>

            {/* AUTHENTICATION */}

            <div className="dashboard-section">

              <div className="section-title">
                Authentication Verification
              </div>

              <div className="authentication-grid">

                {/* SPF */}

                <div className="authentication-card">

                  <div className="auth-name">
                    SPF
                  </div>

                  <div
                    className={`auth-status ${getStatusClass(
                      spf
                    )}`}
                  >
                    {display(spf).toUpperCase()}
                  </div>

                  <p>
                    Sender Policy Framework
                  </p>

                  <p>
                    Client IP:{" "}
                    {display(smtp.clientIp)}
                  </p>

                  <p>
                    Envelope:{" "}
                    {display(
                      smtp.envelopeSender
                    )}
                  </p>

                  {authentication.spf?.status
                    ?.comment && (
                    <p>
                      Reason:{" "}
                      {
                        authentication.spf
                          .status.comment
                      }
                    </p>
                  )}

                </div>

                {/* DKIM */}

                <div className="authentication-card">

                  <div className="auth-name">
                    DKIM
                  </div>

                  <div
                    className={`auth-status ${getStatusClass(
                      dkim
                    )}`}
                  >
                    {display(dkim).toUpperCase()}
                  </div>

                  <p>
                    DomainKeys Identified Mail
                  </p>

                  {authentication.dkim?.results?.map(
                    (signature, index) => (
                      <div
                        className="dkim-details"
                        key={index}
                      >

                        <p>
                          Signing Domain:{" "}
                          {display(
                            signature.signingDomain
                          )}
                        </p>

                        <p>
                          Selector:{" "}
                          {display(
                            signature.selector
                          )}
                        </p>

                        <p>
                          Result:{" "}
                          {display(
                            signature.status?.result
                          )}
                        </p>

                        <p>
                          Reason:{" "}
                          {display(
                            signature.status?.comment
                          )}
                        </p>

                      </div>
                    )
                  )}

                </div>

                {/* DMARC */}

                <div className="authentication-card">

                  <div className="auth-name">
                    DMARC
                  </div>

                  <div
                    className={`auth-status ${getStatusClass(
                      reportedDmarc
                    )}`}
                  >
                    {display(
                      reportedDmarc
                    ).toUpperCase()}
                  </div>

                  <p>
                    Domain-based Message
                    Authentication
                  </p>

                  <p>
                    From Domain:{" "}
                    {display(
                      smtp.headerFromDomain
                    )}
                  </p>

                  <p>
                    Policy:{" "}
                    {display(
                      authentication.dmarc?.policy
                    )}
                  </p>

                  <p>
                    Independent Result:{" "}
                    <strong>
                      {display(
                        independentDmarc
                      ).toUpperCase()}
                    </strong>
                  </p>

                  <p>
                    Results Agree:{" "}
                    <strong>
                      {resultsAgree === true
                        ? "YES"
                        : resultsAgree === false
                        ? "NO"
                        : "NOT AVAILABLE"}
                    </strong>
                  </p>

                </div>

              </div>

            </div>

            {/* SENDER */}

            <div className="dashboard-section">

              <div className="section-title">
                Sender & Routing Information
              </div>

              <div className="information-grid">

                <div className="information-item">

                  <span>
                    Envelope Sender
                  </span>

                  <strong>
                    {display(
                      smtp.envelopeSender
                    )}
                  </strong>

                </div>

                <div className="information-item">

                  <span>
                    Header From
                  </span>

                  <strong>
                    {display(
                      smtp.headerFrom
                    )}
                  </strong>

                </div>

                <div className="information-item">

                  <span>
                    Domain
                  </span>

                  <strong>
                    {display(
                      smtp.headerFromDomain
                    )}
                  </strong>

                </div>

                <div className="information-item">

                  <span>
                    IPv4 Address
                  </span>

                  <strong>
                    {display(
                      smtp.clientIp
                    )}
                  </strong>

                </div>

                <div className="information-item">

                  <span>
                    HELO
                  </span>

                  <strong>
                    {display(
                      smtp.helo
                    )}
                  </strong>

                </div>

                <div className="information-item">

                  <span>
                    Routing Hops
                  </span>

                  <strong>
                    {display(
                      smtp.routingHops
                    )}
                  </strong>

                </div>

              </div>

            </div>

            {/* DMARC ALIGNMENT */}

            <div className="dashboard-section">

              <div className="section-title">
                DMARC Alignment Verification
              </div>

              <div className="alignment-grid">

                <div className="alignment-item">

                  <span>
                    SPF Alignment
                  </span>

                  <strong>
                    {spfAlignment === true
                      ? "PASS"
                      : spfAlignment === false
                      ? "FAIL"
                      : "NOT AVAILABLE"}
                  </strong>

                </div>

                <div className="alignment-item">

                  <span>
                    DKIM Alignment
                  </span>

                  <strong>
                    {dkimAlignment === true
                      ? "PASS"
                      : dkimAlignment === false
                      ? "FAIL"
                      : "NOT AVAILABLE"}
                  </strong>

                </div>

                <div className="alignment-item">

                  <span>
                    DMARC Passed By
                  </span>

                  <strong>
                    {display(
                      dmarcPassedBy
                    ).toUpperCase()}
                  </strong>

                </div>

                <div className="alignment-item">

                  <span>
                    Independent DMARC Result
                  </span>

                  <strong>
                    {display(
                      independentDmarc
                    ).toUpperCase()}
                  </strong>

                </div>

                <div className="alignment-item">

                  <span>
                    Verification Results Agree
                  </span>

                  <strong>
                    {resultsAgree === true
                      ? "YES"
                      : resultsAgree === false
                      ? "NO"
                      : "NOT AVAILABLE"}
                  </strong>

                </div>

              </div>

              <div className="dmarc-explanation">

                <strong>
                  Independent DMARC Decision
                </strong>

                <p>
                  {dmarcExplanation}
                </p>

              </div>

            </div>

            {/* VERIFICATION METHOD */}

            <div className="dashboard-section">

              <div className="section-title">
                Verification Method
              </div>

              <div className="information-grid">

                <div className="information-item">

                  <span>SPF</span>

                  <strong>
                    Independent DNS Verification
                  </strong>

                </div>

                <div className="information-item">

                  <span>DKIM</span>

                  <strong>
                    Cryptographic Signature
                    Verification
                  </strong>

                </div>

                <div className="information-item">

                  <span>DMARC</span>

                  <strong>
                    DNS Policy + Explicit
                    Alignment
                  </strong>

                </div>

                <div className="information-item">

                  <span>ARC</span>

                  <strong>
                    Reported Separately
                  </strong>

                </div>

              </div>

            </div>

            {/* FINAL CONCLUSION */}

            <div className="dashboard-section">

              <div className="section-title">
                Forensic Conclusion
              </div>

              <div className="dmarc-explanation">

                <p>
                  The uploaded email was independently
                  evaluated using its SMTP evidence,
                  SPF policy, DKIM signature and DMARC
                  alignment.
                </p>

                <p>
                  SPF Result:{" "}
                  <strong>
                    {display(spf).toUpperCase()}
                  </strong>
                </p>

                <p>
                  DKIM Result:{" "}
                  <strong>
                    {display(dkim).toUpperCase()}
                  </strong>
                </p>

                <p>
                  Reported DMARC Result:{" "}
                  <strong>
                    {display(
                      reportedDmarc
                    ).toUpperCase()}
                  </strong>
                </p>

                <p>
                  Independent DMARC Result:{" "}
                  <strong>
                    {display(
                      independentDmarc
                    ).toUpperCase()}
                  </strong>
                </p>

                <p>
                  DMARC Verification Results Agree:{" "}
                  <strong>
                    {resultsAgree === true
                      ? "YES"
                      : resultsAgree === false
                      ? "NO"
                      : "NOT AVAILABLE"}
                  </strong>
                </p>

              </div>

            </div>

          </section>
        )}

      </main>

    </div>
  );
}

export default Dashboard;