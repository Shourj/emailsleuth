from datetime import datetime

def generate_report(data):
    email = data["email"]
    domain = data["domain"]
    dns = data["dns"]
    whois = data["whois"]
    breach = data["breach"]
    smtp = data["smtp"]
    gravatar = data["gravatar"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Risk score calculation
    risk_score = 0
    risk_flags = []

    if not dns["spf_found"]:
        risk_score += 20
        risk_flags.append("No SPF record — domain can be spoofed")
    if not dns["dmarc_found"]:
        risk_score += 20
        risk_flags.append("No DMARC record — phishing protection missing")
    if whois["is_new"]:
        risk_score += 25
        risk_flags.append(f"Domain is only {whois['age_days']} days old")
    if breach["hash_found"]:
        risk_score += 20
        risk_flags.append(f"Email hash found in breach dumps ({breach['hash_count']} times)")
    if breach["is_disposable"]:
        risk_score += 30
        risk_flags.append("Disposable email domain detected")
    if breach["leakcheck_found"]:
        risk_score += 15
        risk_flags.append(f"Found in {breach['leakcheck_count']} public breach(es)")

    risk_score = min(risk_score, 100)

    if risk_score == 0:
        risk_level = "Low"
        risk_color = "#2ecc71"
    elif risk_score < 40:
        risk_level = "Medium"
        risk_color = "#f39c12"
    else:
        risk_level = "High"
        risk_color = "#e74c3c"

    # MX rows
    mx_rows = ""
    for mx in dns["mx_records"]:
        mx_rows += f"<tr><td>{mx['priority']}</td><td>{mx['server']}</td></tr>"

    # Breach sources
    breach_rows = ""
    for s in breach["leakcheck_sources"]:
        breach_rows += f"<tr><td>{s.get('name','Unknown')}</td><td>{s.get('date','Unknown')}</td></tr>"

    # Risk flags
    flags_html = ""
    for flag in risk_flags:
        flags_html += f'<li>⚠️ {flag}</li>'
    if not flags_html:
        flags_html = '<li style="color:#2ecc71">✅ No risk flags detected</li>'

    # Gravatar section
    gravatar_html = ""
    if gravatar["avatar_exists"]:
        gravatar_html = f'<img src="{gravatar["avatar_url"]}" style="border-radius:50%;width:80px;margin-bottom:10px;"><br>'
    for field in ["display_name", "full_name", "location", "bio", "profile_url"]:
        if gravatar[field]:
            gravatar_html += f'<p><strong>{field.replace("_"," ").title()}:</strong> {gravatar[field]}</p>'
    if not gravatar_html:
        gravatar_html = '<p style="color:#888">No Gravatar profile found</p>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>EmailSleuth Report — {email}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', sans-serif; background: #0d1117; color: #c9d1d9; }}
        .header {{ background: linear-gradient(135deg, #161b22, #1f2937); padding: 40px; border-bottom: 1px solid #30363d; }}
        .header h1 {{ font-size: 28px; color: #58a6ff; }}
        .header p {{ color: #8b949e; margin-top: 5px; }}
        .container {{ max-width: 960px; margin: 30px auto; padding: 0 20px; }}
        .risk-badge {{ display: inline-block; padding: 8px 20px; border-radius: 20px; font-weight: bold; font-size: 18px; background: {risk_color}22; color: {risk_color}; border: 1px solid {risk_color}; margin-top: 15px; }}
        .risk-bar-wrap {{ background: #21262d; border-radius: 10px; height: 12px; margin-top: 10px; }}
        .risk-bar {{ background: {risk_color}; width: {risk_score}%; height: 12px; border-radius: 10px; transition: width 1s; }}
        .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 10px; padding: 25px; margin-bottom: 20px; }}
        .card h2 {{ color: #58a6ff; font-size: 16px; margin-bottom: 15px; border-bottom: 1px solid #30363d; padding-bottom: 10px; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #21262d; color: #8b949e; padding: 10px; text-align: left; font-size: 13px; }}
        td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 14px; }}
        .badge-green {{ color: #2ecc71; font-weight: bold; }}
        .badge-red {{ color: #e74c3c; font-weight: bold; }}
        .badge-yellow {{ color: #f39c12; font-weight: bold; }}
        ul {{ padding-left: 20px; }}
        li {{ margin: 8px 0; font-size: 14px; }}
        .footer {{ text-align: center; color: #444; padding: 30px; font-size: 12px; }}
        .grid {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
        @media(max-width:600px) {{ .grid {{ grid-template-columns: 1fr; }} }}
    </style>
</head>
<body>

<div class="header">
    <h1>🔍 EmailSleuth OSINT Report</h1>
    <p>Target: <strong style="color:#f0f6fc">{email}</strong> &nbsp;|&nbsp; Domain: <strong style="color:#f0f6fc">{domain}</strong></p>
    <p style="margin-top:5px">Generated: {timestamp}</p>
    <div class="risk-badge">Risk Level: {risk_level} ({risk_score}/100)</div>
    <div class="risk-bar-wrap" style="margin-top:10px">
        <div class="risk-bar"></div>
    </div>
</div>

<div class="container">

    <!-- Risk Flags -->
    <div class="card">
        <h2>🚩 Risk Assessment</h2>
        <ul>{flags_html}</ul>
    </div>

    <div class="grid">

        <!-- DNS -->
        <div class="card">
            <h2>📡 DNS Records</h2>
            <table>
                <tr><th>Priority</th><th>Mail Server</th></tr>
                {mx_rows}
            </table>
            <br>
            <p>SPF: <span class="{'badge-green' if dns['spf_found'] else 'badge-red'}">{'✅ Found' if dns['spf_found'] else '❌ Missing'}</span></p>
            <p style="margin-top:8px">DMARC: <span class="{'badge-green' if dns['dmarc_found'] else 'badge-red'}">{'✅ Found' if dns['dmarc_found'] else '❌ Missing'}</span></p>
            {f'<p style="margin-top:8px;font-size:12px;color:#8b949e">{dns["spf"]}</p>' if dns["spf"] else ''}
        </div>

        <!-- WHOIS -->
        <div class="card">
            <h2>🌐 WHOIS Info</h2>
            <table>
                <tr><td><strong>Registrar</strong></td><td>{whois.get('registrar') or 'N/A'}</td></tr>
                <tr><td><strong>Registered</strong></td><td>{whois.get('creation_date') or 'N/A'}</td></tr>
                <tr><td><strong>Expires</strong></td><td>{whois.get('expiration_date') or 'N/A'}</td></tr>
                <tr><td><strong>Org</strong></td><td>{whois.get('org') or 'N/A'}</td></tr>
                <tr><td><strong>Country</strong></td><td>{whois.get('country') or 'N/A'}</td></tr>
                <tr><td><strong>Domain Age</strong></td><td>{whois.get('age_days') or 'N/A'} days</td></tr>
            </table>
        </div>

    </div>

    <div class="grid">

        <!-- Breach -->
        <div class="card">
            <h2>🔓 Breach Intelligence</h2>
            <p>Hash in breach dumps: <span class="{'badge-red' if breach['hash_found'] else 'badge-green'}">{'⚠️ Yes (' + str(breach['hash_count']) + 'x)' if breach['hash_found'] else '✅ No'}</span></p>
            <p style="margin-top:8px">Disposable domain: <span class="{'badge-red' if breach['is_disposable'] else 'badge-green'}">{'🚨 Yes' if breach['is_disposable'] else '✅ No'}</span></p>
            <p style="margin-top:8px">LeakCheck: <span class="{'badge-red' if breach['leakcheck_found'] else 'badge-green'}">{'🚨 ' + str(breach['leakcheck_count']) + ' breach(es)' if breach['leakcheck_found'] else '✅ Clean'}</span></p>
            {('<br><table><tr><th>Source</th><th>Date</th></tr>' + breach_rows + '</table>') if breach_rows else ''}
        </div>

        <!-- SMTP + Gravatar -->
        <div class="card">
            <h2>📨 SMTP Validation</h2>
            <p>Status: <span class="{'badge-green' if smtp['status'] == 'exists' else 'badge-yellow'}">{smtp.get('message') or 'N/A'}</span></p>
            {f'<p style="margin-top:8px;color:#8b949e;font-size:12px">MX Host: {smtp["mx_host"]}</p>' if smtp["mx_host"] else ''}
            <br>
            <h2 style="margin-top:15px">👤 Gravatar Profile</h2>
            {gravatar_html}
        </div>

    </div>

</div>

<div class="footer">Generated by EmailSleuth — for ethical OSINT use only</div>
</body>
</html>"""

    filename = f"report_{email.replace('@','_at_')}.html"
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html)

    return filename