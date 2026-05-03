import express from "express";
import cors from "cors";
import dns from "dns/promises";
import net from "net";
import tls from "tls";
import https from "https";

const app = express();

const PORT = process.env.PORT || 10000;
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || "https://stealthitgroup.com";

app.use(express.json({ limit: "25kb" }));

app.use(cors({
  origin: ALLOWED_ORIGIN,
  methods: ["GET", "POST"],
  allowedHeaders: ["Content-Type"]
}));

function isValidDomain(domain) {
  if (!domain || typeof domain !== "string") return false;

  const clean = domain.trim().toLowerCase();

  if (clean.length > 253) return false;
  if (clean.includes("://")) return false;
  if (clean === "localhost") return false;
  if (/^\d+\.\d+\.\d+\.\d+$/.test(clean)) return false;

  return /^[a-z0-9.-]+\.[a-z]{2,}$/.test(clean);
}

function timeoutPromise(ms, fallback) {
  return new Promise(resolve => setTimeout(() => resolve(fallback), ms));
}

async function safeDnsLookup(type, domain) {
  try {
    if (type === "A") return await dns.resolve4(domain);
    if (type === "MX") return await dns.resolveMx(domain);
    if (type === "NS") return await dns.resolveNs(domain);
    if (type === "TXT") return await dns.resolveTxt(domain);
    return [];
  } catch {
    return [];
  }
}

async function checkDns(domain) {
  const [a, mx, ns, txt] = await Promise.all([
    safeDnsLookup("A", domain),
    safeDnsLookup("MX", domain),
    safeDnsLookup("NS", domain),
    safeDnsLookup("TXT", domain)
  ]);

  const flatTxt = txt.map(record => record.join(""));

  const spf = flatTxt.find(value => value.toLowerCase().startsWith("v=spf1")) || null;
  const dmarcRecords = await safeDnsLookup("TXT", `_dmarc.${domain}`);
  const flatDmarc = dmarcRecords.map(record => record.join(""));
  const dmarc = flatDmarc.find(value => value.toLowerCase().startsWith("v=dmarc1")) || null;

  return {
    a,
    mx,
    ns,
    spf: {
      present: Boolean(spf),
      value: spf,
      warning: spf && spf.includes("+all") ? "SPF uses +all, which is overly permissive." : null
    },
    dmarc: {
      present: Boolean(dmarc),
      value: dmarc
    }
  };
}

async function checkEmailSecurity(domain) {
  const txt = await safeDnsLookup("TXT", domain);
  const flatTxt = txt.map(record => record.join(""));

  const spf = flatTxt.find(value => value.toLowerCase().startsWith("v=spf1")) || null;

  const dmarcRecords = await safeDnsLookup("TXT", `_dmarc.${domain}`);
  const flatDmarc = dmarcRecords.map(record => record.join(""));
  const dmarc = flatDmarc.find(value => value.toLowerCase().startsWith("v=dmarc1")) || null;

  const commonSelectors = [
    "google",
    "selector1",
    "selector2",
    "default",
    "k1",
    "dkim",
    "mail",
    "s1",
    "s2"
  ];

  const dkimResults = [];

  for (const selector of commonSelectors) {
    const records = await safeDnsLookup("TXT", `${selector}._domainkey.${domain}`);
    const flattened = records.map(record => record.join(""));
    const found = flattened.find(value => value.toLowerCase().includes("v=dkim1"));

    if (found) {
      dkimResults.push({
        selector,
        present: true,
        value: found
      });
    }
  }

  let dmarcPolicy = null;

  if (dmarc) {
    const policyMatch = dmarc.match(/p=([^;]+)/i);
    dmarcPolicy = policyMatch ? policyMatch[1].toLowerCase() : null;
  }

  const spfPresent = Boolean(spf);
  const dmarcPresent = Boolean(dmarc);
  const dkimPresent = dkimResults.length > 0;

  let spoofingRisk = "Low";

  if (!spfPresent && !dmarcPresent) {
    spoofingRisk = "High";
  } else if (!dmarcPresent) {
    spoofingRisk = "High";
  } else if (dmarcPolicy === "none") {
    spoofingRisk = "Medium";
  } else if (!dkimPresent) {
    spoofingRisk = "Medium";
  }

  return {
    spf: {
      present: spfPresent,
      value: spf,
      overlyPermissive: spf ? spf.includes("+all") : false,
      softFail: spf ? spf.includes("~all") : false,
      hardFail: spf ? spf.includes("-all") : false
    },
    dmarc: {
      present: dmarcPresent,
      value: dmarc,
      policy: dmarcPolicy,
      reportingEnabled: dmarc ? dmarc.includes("rua=") : false
    },
    dkim: {
      present: dkimPresent,
      selectorsFound: dkimResults
    },
    summary: {
      spoofingRisk
    }
  };
}

async function runPrioritizedCheck(domain) {
  const [exposure, email] = await Promise.all([
    Promise.all([
      checkDns(domain),
      checkTls(domain),
      checkHeaders(domain),
      checkPorts(domain)
    ]),
    checkEmailSecurity(domain)
  ]);

  const [dnsResult, tlsResult, headerResult, portResult] = exposure;

  const issues = [];

  const headers = headerResult?.headers || {};
  const ports = Array.isArray(portResult) ? portResult : [];

  function addIssue({ title, severity, effort, impact, category, why, fix }) {
    issues.push({ title, severity, effort, impact, category, why, fix });
  }

  if (!email.dmarc.present) {
    addIssue({
      title: "DMARC is missing",
      severity: "High",
      effort: "Low",
      impact: "High",
      category: "Email Security",
      why: "Without DMARC, your domain is more likely to be spoofed in phishing attempts.",
      fix: "Add a DMARC record starting with monitoring, then move toward quarantine or reject once legitimate mail sources are confirmed."
    });
  } else if (email.dmarc.policy === "none") {
    addIssue({
      title: "DMARC is not enforced",
      severity: "Medium",
      effort: "Low",
      impact: "High",
      category: "Email Security",
      why: "A p=none policy monitors activity but does not prevent spoofed messages from being delivered.",
      fix: "Review reports, confirm legitimate senders, then move toward p=quarantine or p=reject."
    });
  }

  if (!email.spf.present) {
    addIssue({
      title: "SPF is missing",
      severity: "High",
      effort: "Low",
      impact: "High",
      category: "Email Security",
      why: "SPF helps receiving mail systems identify which servers are allowed to send mail for your domain.",
      fix: "Publish an SPF record that includes only approved mail senders."
    });
  } else if (email.spf.overlyPermissive) {
    addIssue({
      title: "SPF is overly permissive",
      severity: "High",
      effort: "Low",
      impact: "High",
      category: "Email Security",
      why: "An SPF record using +all allows any sender, which defeats the purpose of SPF.",
      fix: "Replace +all with a stricter mechanism such as -all after validating your mail sources."
    });
  } else if (email.spf.softFail) {
    addIssue({
      title: "SPF uses soft fail",
      severity: "Low",
      effort: "Low",
      impact: "Medium",
      category: "Email Security",
      why: "Soft fail (~all) is better than nothing, but it is less strict than hard fail.",
      fix: "After confirming all legitimate senders are included, consider moving from ~all to -all."
    });
  }

  if (!email.dkim.present) {
    addIssue({
      title: "DKIM was not detected",
      severity: "Medium",
      effort: "Medium",
      impact: "High",
      category: "Email Security",
      why: "DKIM helps prove that messages were authorized by the sending domain and were not modified in transit.",
      fix: "Enable DKIM signing in your email platform and publish the selector record provided by your mail provider."
    });
  }

  if (!tlsResult.httpsAvailable) {
    addIssue({
      title: "HTTPS is unavailable",
      severity: "High",
      effort: "Medium",
      impact: "High",
      category: "Web Security",
      why: "Visitors should not be forced onto an unencrypted connection.",
      fix: "Install a valid TLS certificate and force HTTPS."
    });
  } else if (!tlsResult.authorized) {
    addIssue({
      title: "TLS certificate is not trusted",
      severity: "High",
      effort: "Medium",
      impact: "High",
      category: "Web Security",
      why: "A broken or untrusted certificate can cause browser warnings and reduce trust.",
      fix: "Replace or renew the TLS certificate with a trusted certificate."
    });
  } else if (tlsResult.daysRemaining !== null && tlsResult.daysRemaining < 30) {
    addIssue({
      title: "TLS certificate expires soon",
      severity: "Medium",
      effort: "Low",
      impact: "Medium",
      category: "Web Security",
      why: "Expiring certificates can cause outages and browser warnings.",
      fix: "Renew the certificate before expiration."
    });
  }

  if (!headers.hsts) {
    addIssue({
      title: "HSTS header is missing",
      severity: "Medium",
      effort: "Low",
      impact: "Medium",
      category: "Web Security",
      why: "HSTS tells browsers to use HTTPS automatically after the first visit.",
      fix: "Add a Strict-Transport-Security header once HTTPS is fully working."
    });
  }

  if (!headers.csp) {
    addIssue({
      title: "Content Security Policy is missing",
      severity: "Medium",
      effort: "Medium",
      impact: "High",
      category: "Web Security",
      why: "CSP helps reduce the impact of script injection and content loading risks.",
      fix: "Add a Content-Security-Policy header that only allows trusted sources."
    });
  }

  if (!headers.xFrameOptions) {
    addIssue({
      title: "Clickjacking protection is missing",
      severity: "Medium",
      effort: "Low",
      impact: "Medium",
      category: "Web Security",
      why: "Without frame protection, your site may be embedded in a malicious page.",
      fix: "Add X-Frame-Options: DENY or use frame-ancestors in CSP."
    });
  }

  if (!headers.xContentTypeOptions) {
    addIssue({
      title: "MIME sniffing protection is missing",
      severity: "Low",
      effort: "Low",
      impact: "Medium",
      category: "Web Security",
      why: "X-Content-Type-Options helps prevent browsers from interpreting files as a different content type.",
      fix: "Add X-Content-Type-Options: nosniff."
    });
  }

  if (!headers.referrerPolicy) {
    addIssue({
      title: "Referrer policy is missing",
      severity: "Low",
      effort: "Low",
      impact: "Low",
      category: "Web Security",
      why: "A referrer policy reduces unnecessary URL information shared with other sites.",
      fix: "Add Referrer-Policy: strict-origin-when-cross-origin."
    });
  }

  const rdpOpen = ports.some(p => p.port === 3389 && p.status === "open");
  const sshOpen = ports.some(p => p.port === 22 && p.status === "open");

  if (rdpOpen) {
    addIssue({
      title: "RDP appears exposed",
      severity: "High",
      effort: "Medium",
      impact: "High",
      category: "Network Exposure",
      why: "Public RDP exposure is a common target for brute force and ransomware activity.",
      fix: "Restrict RDP behind VPN, zero trust access, or source IP allowlists."
    });
  }

  if (sshOpen) {
    addIssue({
      title: "SSH appears exposed",
      severity: "Medium",
      effort: "Medium",
      impact: "High",
      category: "Network Exposure",
      why: "Public SSH can be acceptable when hardened, but it is frequently scanned and attacked.",
      fix: "Restrict SSH access, require keys, disable password login, and monitor authentication attempts."
    });
  }

  const severityRank = { High: 3, Medium: 2, Low: 1 };

  issues.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);

  return {
    summary: {
      totalIssues: issues.length,
      high: issues.filter(i => i.severity === "High").length,
      medium: issues.filter(i => i.severity === "Medium").length,
      low: issues.filter(i => i.severity === "Low").length
    },
    issues,
    raw: {
      dns: dnsResult,
      tls: tlsResult,
      headers: headerResult,
      ports: portResult,
      email
    }
  };
}

async function checkHeaders(domain) {
  return new Promise(resolve => {
    const req = https.request(
      {
        hostname: domain,
        port: 443,
        method: "GET",
        path: "/",
        timeout: 5000,
        rejectUnauthorized: false
      },
      res => {
        resolve({
          reachable: true,
          statusCode: res.statusCode,
          headers: {
            hsts: Boolean(res.headers["strict-transport-security"]),
            csp: Boolean(res.headers["content-security-policy"]),
            xFrameOptions: Boolean(res.headers["x-frame-options"]),
            xContentTypeOptions: Boolean(res.headers["x-content-type-options"]),
            referrerPolicy: Boolean(res.headers["referrer-policy"])
          }
        });

        res.resume();
      }
    );

    req.on("timeout", () => {
      req.destroy();
      resolve({ reachable: false, error: "HTTPS request timed out." });
    });

    req.on("error", () => {
      resolve({ reachable: false, error: "HTTPS request failed." });
    });

    req.end();
  });
}

async function checkTls(domain) {
  return new Promise(resolve => {
    const socket = tls.connect(
      {
        host: domain,
        port: 443,
        servername: domain,
        timeout: 5000,
        rejectUnauthorized: false
      },
      () => {
        const cert = socket.getPeerCertificate();
        const validTo = cert?.valid_to || null;
        const expiresAt = validTo ? new Date(validTo) : null;
        const daysRemaining = expiresAt
          ? Math.ceil((expiresAt.getTime() - Date.now()) / (1000 * 60 * 60 * 24))
          : null;

        resolve({
          httpsAvailable: true,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
          issuer: cert?.issuer || null,
          subject: cert?.subject || null,
          validTo,
          daysRemaining
        });

        socket.end();
      }
    );

    socket.on("timeout", () => {
      socket.destroy();
      resolve({ httpsAvailable: false, error: "TLS check timed out." });
    });

    socket.on("error", () => {
      resolve({ httpsAvailable: false, error: "TLS connection failed." });
    });
  });
}

async function checkPort(domain, port) {
  return new Promise(resolve => {
    const socket = new net.Socket();

    const done = result => {
      socket.destroy();
      resolve({
        port,
        status: result
      });
    };

    socket.setTimeout(2500);

    socket.once("connect", () => done("open"));
    socket.once("timeout", () => done("filtered"));
    socket.once("error", () => done("closed"));

    socket.connect(port, domain);
  });
}

async function checkPorts(domain) {
  const ports = [80, 443, 22, 3389];
  const results = await Promise.all(
    ports.map(port => Promise.race([
      checkPort(domain, port),
      timeoutPromise(3000, { port, status: "timeout" })
    ]))
  );

  return results;
}

app.get("/", (req, res) => {
  res.json({
    service: "Stealth IT Group Tools API",
    status: "ok"
  });
});

app.get("/health", (req, res) => {
  res.json({ status: "ok" });
});

app.post("/api/check", async (req, res) => {
  const rawDomain = req.body?.domain;
  const domain = rawDomain?.trim().toLowerCase();

  if (!isValidDomain(domain)) {
    return res.status(400).json({
      error: "Invalid domain. Enter a public domain like example.com."
    });
  }

  const [dnsResult, tlsResult, headerResult, portResult] = await Promise.all([
    checkDns(domain),
    checkTls(domain),
    checkHeaders(domain),
    checkPorts(domain)
  ]);

  res.json({
    domain,
    checkedAt: new Date().toISOString(),
    dns: dnsResult,
    tls: tlsResult,
    headers: headerResult,
    ports: portResult
  });
});

app.post("/api/email-check", async (req, res) => {
  const rawDomain = req.body?.domain;
  const domain = rawDomain?.trim().toLowerCase();

  if (!isValidDomain(domain)) {
    return res.status(400).json({
      error: "Invalid domain. Enter a public domain like example.com."
    });
  }

  const emailSecurity = await checkEmailSecurity(domain);

  res.json({
    domain,
    checkedAt: new Date().toISOString(),
    emailSecurity
  });
});

app.post("/api/prioritized-check", async (req, res) => {
  const rawDomain = req.body?.domain;
  const domain = rawDomain?.trim().toLowerCase();

  if (!isValidDomain(domain)) {
    return res.status(400).json({
      error: "Invalid domain. Enter a public domain like example.com."
    });
  }

  const result = await runPrioritizedCheck(domain);

  res.json({
    domain,
    checkedAt: new Date().toISOString(),
    ...result
  });
});

app.listen(PORT, () => {
  console.log(`Stealth tools API listening on port ${PORT}`);
});
