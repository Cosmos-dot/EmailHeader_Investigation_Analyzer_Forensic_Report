function Reports() {
  return (
    <div className="dashboard">
      <nav className="navbar">
        <div>
          <h2>Email Forensic Analyzer</h2>
          <span>Investigation Reports</span>
        </div>
      </nav>

      <main className="dashboard-content">
        <section className="analysis-card">
          <h1>Forensic Reports</h1>
          <p>Saved email header investigation reports will appear here.</p>

          <div className="empty-report">
            No saved reports available.
          </div>
        </section>
      </main>
    </div>
  );
}

export default Reports;
