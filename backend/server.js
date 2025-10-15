import express from "express";
import axios from "axios";
import dotenv from "dotenv";
import cors from "cors";
import ipRangeCheck from "ip-range-check"; // helper to validate/cidr

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors()); // restrict in prod to your frontend origin

const SHODAN_KEY = process.env.SHODAN_API_KEY;
if (!SHODAN_KEY) {
  console.error("Missing SHODAN_API_KEY in env");
  process.exit(1);
}

// simple IP regex (also handle IPv4 only here). For production use a robust validator.
const IPV4_REGEX = /^(\d{1,3}\.){3}\d{1,3}$/;

// Helper: safe fetch from Shodan host API
async function shodanHost(ip) {
  const url = `https://api.shodan.io/shodan/host/${encodeURIComponent(ip)}?key=${SHODAN_KEY}`;
  const resp = await axios.get(url, { timeout: 30000 });
  return resp.data;
}

/**
 * POST /api/scan
 * body: { target: "45.33.12.101" }
 *
 * Returns: normalized JSON with shodan host info where available.
 */
app.post("/api/scan", async (req, res) => {
  try {
    const { target } = req.body;
    if (!target || typeof target !== "string") {
      return res.status(400).json({ error: "target (ip or host) is required" });
    }

    // Basic validation: single IPv4 address for this endpoint
    const ip = target.trim();
    if (!IPV4_REGEX.test(ip)) {
      return res.status(400).json({ error: "Unsupported target format. Use IPv4 like 45.33.12.101" });
    }

    // Optionally: impose allowlist or local-network-only rule
    // if (!ipRangeCheck(ip, ["192.168.0.0/16", "10.0.0.0/8"])) { ... }

    // Query Shodan host API
    let shodanData;
    try {
      shodanData = await shodanHost(ip);
    } catch (err) {
      // Shodan returns 404 if host not found
      if (err.response && err.response.status === 404) {
        return res.json({ found: false, message: "No Shodan data for this IP" });
      }
      console.error("Shodan error:", err?.response?.data || err.message);
      return res.status(502).json({ error: "Error querying Shodan", detail: err.message });
    }

    // Normalize and return only relevant fields
    const normalized = {
      found: true,
      ip: shodanData.ip_str || ip,
      org: shodanData.org || null,
      isp: shodanData.isp || null,
      country: shodanData.country_name || shodanData.country || null,
      city: shodanData.city || null,
      latitude: shodanData.latitude || null,
      longitude: shodanData.longitude || null,
      last_update: shodanData.last_update || shodanData.timestamp || null,
      ports: shodanData.ports || [],
      hostnames: shodanData.hostnames || [],
      os: shodanData.os || null,
      // Shodan may return banners: array of services found with product/version etc
      services: (shodanData.data || []).map(s => ({
        port: s.port,
        transport: s.transport,
        product: s.product || null,
        version: s.version || null,
        banner: s.data || s.banner || null,
        http: s.http || null
      })),
      // Shodan sometimes returns 'vulns' as an object keys of CVE IDs
      vulns: shodanData.vulns ? Object.keys(shodanData.vulns) : (shodanData.vulns || []),
      raw: shodanData // include raw for debugging if you want
    };

    return res.json(normalized);

  } catch (err) {
    console.error(err);
    return res.status(500).json({ error: "internal_server_error", detail: err.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));
