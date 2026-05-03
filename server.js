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

app.listen(PORT, () => {
  console.log(`Stealth tools API listening on port ${PORT}`);
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
