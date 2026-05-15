#!/usr/bin/env node

import { FastMCP } from "fastmcp";
import { z } from "zod";
import axios from "axios";

// ตั้งค่า API Endpoint สำหรับ New Central
const CENTRAL_BASE_URL = process.env.CENTRAL_BASE_URL || "https://internal.api.central.arubanetworks.com/";
const CENTRAL_CLIENT_ID = process.env.CENTRAL_CLIENT_ID;
const CENTRAL_CLIENT_SECRET = process.env.CENTRAL_CLIENT_SECRET;

if (!CENTRAL_CLIENT_ID || !CENTRAL_CLIENT_SECRET) {
    console.error("Error: CENTRAL_CLIENT_ID and CENTRAL_CLIENT_SECRET environment variables are required for New Central.");
    process.exit(1);
}

// ─── OAuth2 Token Cache ───────────────────────────────────────────────────────
const HPE_SSO_URL = "https://sso.common.cloud.hpe.com/as/token.oauth2";

let _tokenCache = {
    token: null,
    expiresAt: 0  // Unix timestamp (ms)
};

/**
 * ดึง Access Token จาก HPE SSO โดยใช้ client_credentials
 * - Token มีอายุ 2 ชั่วโมง (7200s) ตาม Aruba Central docs
 * - Cache ไว้ใน memory และ refresh อัตโนมัติก่อนหมดอายุ 5 นาที
 */
async function getAccessToken() {
    const now = Date.now();
    // ถ้า token ยังไม่หมดอายุ ให้ใช้ cache
    if (_tokenCache.token && now < _tokenCache.expiresAt) {
        return _tokenCache.token;
    }

    const params = new URLSearchParams();
    params.append("grant_type", "client_credentials");
    params.append("client_id", CENTRAL_CLIENT_ID);
    params.append("client_secret", CENTRAL_CLIENT_SECRET);

    try {
        const response = await axios.post(HPE_SSO_URL, params, {
            headers: {
                "accept": "application/json",
                "content-type": "application/x-www-form-urlencoded"
            }
        });

        const { access_token, expires_in } = response.data;
        if (!access_token) throw new Error("No access_token in SSO response");

        // Cache token โดยลบ 5 นาที (300s) ออกเพื่อ safety margin
        const ttlMs = ((expires_in ?? 7200) - 300) * 1000;
        _tokenCache = {
            token: access_token,
            expiresAt: now + ttlMs
        };

        return access_token;
    } catch (error) {
        const errData = error.response?.data;
        const errMsg = errData?.error_description || errData?.error || error.message;
        throw new Error(`Failed to obtain access token from HPE SSO: ${errMsg}`);
    }
}


// สร้าง FastMCP Server
const server = new FastMCP({
    name: "new-aruba-central-mcp",
    version: "1.0.0"
});

// Tool ตัวอย่าง: สำหรับ New Central (เช่น AOS10)
server.addTool({
    name: "create_new_central_ssid",
    description: "Create a new SSID (WLAN profile) on New Aruba Central (AOS10)",
    parameters: z.object({
        // ── Path param ─────────────────────────────────────────────────────────
        profile_name: z.string().describe("WLAN profile name — used as {ssid} in URL path"),

        // ── Core identity ────────────────────────────────────────────────────
        ssid: z.string().optional().describe("SSID profile name sent in the request body"),
        essid: z.object({
            name: z.string()
        }).optional().describe("ESSID object e.g. { name: 'MyWifi' }"),
        type: z.string().optional().describe("EMPLOYEE | GUEST | VOICE | ..."),
        enable: z.boolean().optional().default(true).describe("Enable/disable the SSID (default: true)"),
        "hide-ssid": z.boolean().optional().default(false),
        "ssid-utf8": z.boolean().optional().default(true).describe("Enable UTF-8 SSID encoding"),
        is_locked: z.boolean().optional(),

        // ── Security / Auth ────────────────────────────────────────────────
        opmode: z.string().optional().describe("WPA2_PSK_AES | WPA3_SAE | WPA2_AES | ..."),
        "personal-security": z.object({
            "passphrase-format": z.string().optional().describe("STRING | HEX"),
            "wpa-passphrase": z.string().optional()
        }).optional().describe("PSK / passphrase object for personal security modes"),
        "mac-authentication": z.boolean().optional(),
        "cloud-auth": z.boolean().optional(),
        "default-role": z.string().optional().describe("Default role for the SSID"),
        "wpa3-transition-mode-enable": z.boolean().optional(),
        "mfp-capable": z.boolean().optional(),
        "mfp-required": z.boolean().optional(),
        dot11r: z.boolean().optional(),
        dot11k: z.boolean().optional(),
        dot11v: z.boolean().optional(),
        okc: z.boolean().optional(),
        "auth-survivability": z.boolean().optional(),
        "max-authentication-failures": z.number().int().optional(),
        "auth-req-thresh": z.number().int().optional().describe("Auth request threshold"),
        "use-ip-for-calling-station-id": z.boolean().optional(),

        // ── Forwarding / VLAN ───────────────────────────────────────────────
        "forward-mode": z.string().optional().describe("FORWARD_MODE_BRIDGE | FORWARD_MODE_TUNNEL | ..."),
        vlan: z.string().optional(),
        "vlan-selector": z.string().optional().describe("VLAN_RANGES | VLAN_ID | ..."),
        "vlan-id-range": z.array(z.string()).optional().describe("e.g. ['10', '20-30']"),
        zone: z.string().optional(),
        "out-of-service": z.string().optional().describe("NONE | ..."),
        "enforce-dhcp": z.boolean().optional(),
        "client-isolation": z.boolean().optional(),
        pan: z.boolean().optional(),

        // ── Client behavior ───────────────────────────────────────────────
        "deny-inter-user-bridging": z.boolean().optional(),
        "deny-local-routing": z.boolean().optional(),
        "broadcast-filter-ipv4": z.string().optional().describe("BCAST_FILTER_ARP | NONE | ..."),
        "broadcast-filter-ipv6": z.string().optional().describe("UCAST_FILTER_RA | FILTER_NONE | ..."),
        "local-proxy-ns": z.boolean().optional(),
        "optimize-mcast-rate": z.boolean().optional(),
        "max-clients": z.number().int().optional(),
        "max-clients-threshold": z.number().int().optional().describe("Max clients threshold per AP"),
        "inactivity-timeout": z.number().int().optional(),
        "local-probe-req-thresh": z.number().int().optional(),
        "explicit-ageout-client": z.boolean().optional(),
        blacklist: z.boolean().optional(),
        denylist: z.boolean().optional(),

        // ── Radio / 802.11 ─────────────────────────────────────────────────
        "dtim-period": z.number().int().optional(),
        "short-preamble": z.boolean().optional(),
        "advertise-apname": z.boolean().optional(),
        "advertise-location": z.boolean().optional(),
        "advertise-location-civic": z.boolean().optional(),
        "advertise-timing": z.boolean().optional(),
        "disable-on-6ghz-mesh": z.boolean().optional(),
        "ftm-responder": z.boolean().optional(),
        "rf-band": z.string().optional().describe("BAND_ALL | BAND_2GHZ | BAND_5GHZ | BAND_6GHZ"),
        "rrm-quiet-ie": z.boolean().optional(),

        // ── High-throughput modes (HT / VHT / HE / EHT) ──────────────────
        "high-throughput": z.object({
            enable: z.boolean().optional(),
            "very-high-throughput": z.boolean().optional()
        }).optional().describe("802.11n/ac HT/VHT settings"),
        "high-efficiency": z.object({
            enable: z.boolean().optional()
        }).optional().describe("802.11ax HE (Wi-Fi 6) settings"),
        "extremely-high-throughput": z.object({
            enable: z.boolean().optional(),
            mlo: z.boolean().optional(),
            "beacon-protection": z.boolean().optional()
        }).optional().describe("802.11be EHT (Wi-Fi 7) settings"),

        // ── WMM / QoS ─────────────────────────────────────────────────────
        wmm: z.boolean().optional(),
        "wmm-uapsd": z.boolean().optional(),
        "wmm-cfg": z.object({
            uapsd: z.boolean().optional()
        }).optional().describe("WMM configuration object"),
        "wmm-be-dscp": z.array(z.number()).optional(),
        "wmm-bk-dscp": z.array(z.number()).optional(),
        "wmm-vi-dscp": z.array(z.number()).optional(),
        "wmm-vo-dscp": z.array(z.number()).optional(),

        // ── Legacy rates ──────────────────────────────────────────────────
        "a-legacy-rates": z.object({
            "basic-rates": z.array(z.string()).optional(),
            "tx-rates": z.array(z.string()).optional(),
            "beacon-rate": z.string().optional(),
            "min-tx-rate": z.string().optional(),
            "max-tx-rate": z.string().optional()
        }).optional(),
        "g-legacy-rates": z.object({
            "basic-rates": z.array(z.string()).optional(),
            "tx-rates": z.array(z.string()).optional(),
            "beacon-rate": z.string().optional(),
            "min-tx-rate": z.string().optional(),
            "max-tx-rate": z.string().optional()
        }).optional(),

        // ── DMO ────────────────────────────────────────────────────────────
        dmo: z.object({
            enable: z.boolean().optional(),
            "channel-utilization-threshold": z.number().int().optional(),
            "clients-threshold": z.number().int().optional()
        }).optional(),

        // ── Bandwidth limits ───────────────────────────────────────────────
        "air-time-limit": z.number().int().optional(),
        "bandwidth-limit": z.number().int().optional(),
        "bandwidth-limit-peruser": z.number().int().optional(),

        // ── Captive portal ───────────────────────────────────────────────
        "captive-portal": z.object({
            type: z.string().optional().describe("none | internal | external")
        }).passthrough().optional(),

        // ── Access rules ──────────────────────────────────────────────────
        "access-rules": z.array(
            z.object({
                action: z.string().optional(),
                protocol: z.string().optional(),
                "src-network": z.string().optional(),
                "dst-network": z.string().optional(),
                "service-name": z.string().optional(),
                queue: z.string().optional()
            }).passthrough()
        ).optional(),

        // ── RADIUS Called-Station-ID ───────────────────────────────────────
        "called-station-id": z.object({
            type: z.string().optional().describe("MAC_ADDRESS | AP_NAME | ..."),
            "include-ssid": z.boolean().optional(),
            delimiter: z.string().optional()
        }).optional()
    }),
    execute: async (args) => {
        const { profile_name, ...payload } = args;

        try {
            // Clean up undefined values from the payload to only send what is needed
            Object.keys(payload).forEach(key => payload[key] === undefined && delete payload[key]);

            // ดึง token ก่อนเรียก API (ใช้ cache ถ้ายังไม่หมดอายุ)
            const token = await getAccessToken();

            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const apiUrl = `${baseUrl}/network-config/v1alpha1/wlan-ssids/${encodeURIComponent(profile_name)}`;

            const response = await axios.put(
                apiUrl,
                payload,
                {
                    headers: {
                        "Authorization": `Bearer ${token}`,
                        "Content-Type": "application/json"
                    }
                }
            );

            return `Successfully created SSID profile '${profile_name}' on New Central.\nAPI Response: ${JSON.stringify(response.data)}`;
        } catch (error) {
            const status = error.response?.status;
            const responseData = error.response?.data;
            const errorMsg = responseData?.message || responseData?.description || error.message;
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const debugInfo = [
                `Status: ${status}`,
                `URL: ${baseUrl}/network-config/v1alpha1/wlan-ssids/${encodeURIComponent(profile_name)}`,
                `Error: ${errorMsg}`,
                responseData ? `Response body: ${JSON.stringify(responseData)}` : null
            ].filter(Boolean).join("\n");

            throw new Error(`Failed to create SSID on New Central.\n${debugInfo}`);
        }
    }
});

// ── Tool: Create Role ───────────────────────────────────────────────────────
// สร้าง Role บน New Central (AOS10) — ต้องเรียกก่อน create_new_central_ssid
server.addTool({
    name: "create_new_central_role",
    description: "Create a role on New Aruba Central (AOS10). Must be called BEFORE creating an SSID — the role name must match the SSID profile name.",
    parameters: z.object({
        role_name: z.string().describe("Role name — must match the SSID profile name exactly")
    }),
    execute: async (args) => {
        const { role_name } = args;

        try {
            const token = await getAccessToken();
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const roleUrl = `${baseUrl}/network-config/v1alpha1/roles/${encodeURIComponent(role_name)}`;

            const response = await axios.post(roleUrl, {}, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json",
                    "accept": "application/json"
                }
            });

            return `Successfully created role '${role_name}' on New Central.\nAPI Response: ${JSON.stringify(response.data)}`;
        } catch (error) {
            const status = error.response?.status;
            const responseData = error.response?.data;

            // 409 = role already exists — not a blocker
            if (status === 409) {
                return `Role '${role_name}' already exists on New Central (no action taken).`;
            }

            const errorMsg = responseData?.message || responseData?.description || error.message;
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const debugInfo = [
                `Status: ${status}`,
                `URL: ${baseUrl}/network-config/v1alpha1/roles/${encodeURIComponent(role_name)}`,
                `Error: ${errorMsg}`,
                responseData ? `Response body: ${JSON.stringify(responseData)}` : null
            ].filter(Boolean).join("\n");

            throw new Error(`Failed to create role on New Central.\n${debugInfo}`);
        }
    }
});

// ── Tool: Create Config Assignment ─────────────────────────────────────────
// กำหนด config profile ให้กับ device/group ใน New Central (AOS10)
server.addTool({
    name: "create_config_assignment",
    description: "Assign a configuration profile (e.g. wlan-ssids) to a device or group scope on New Aruba Central (AOS10). Calls POST /network-config/v1alpha1/config-assignments.",
    parameters: z.object({
        assignments: z.array(
            z.object({
                "device-function": z.string().describe(
                    "Device function type, e.g. CAMPUS_AP | CAMPUS_GW | BRANCH_GW | SD_WAN_GW"
                ),
                "scope-id": z.string().describe(
                    "Scope ID — group ID or device serial number that the profile is assigned to"
                ),
                "profile-type": z.string().describe(
                    "Profile type to assign, e.g. wlan-ssids | roles | rf-bands | ap-system"
                ),
                "profile-instance": z.string().describe(
                    "Name of the profile instance to assign, e.g. central-bridge-ssid"
                )
            })
        ).min(1).describe("One or more config-assignment objects to create")
    }),
    execute: async (args) => {
        const { assignments } = args;

        try {
            const token = await getAccessToken();
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const apiUrl = `${baseUrl}/network-config/v1alpha1/config-assignments`;

            const payload = {
                "config-assignment": assignments
            };

            const response = await axios.post(apiUrl, payload, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "Content-Type": "application/json",
                    "accept": "application/json"
                }
            });

            return `Successfully created ${assignments.length} config assignment(s) on New Central.\nAPI Response: ${JSON.stringify(response.data)}`;
        } catch (error) {
            const status = error.response?.status;
            const responseData = error.response?.data;
            const errorMsg = responseData?.message || responseData?.description || error.message;
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const debugInfo = [
                `Status: ${status}`,
                `URL: ${baseUrl}/network-config/v1alpha1/config-assignments`,
                `Error: ${errorMsg}`,
                responseData ? `Response body: ${JSON.stringify(responseData)}` : null
            ].filter(Boolean).join("\n");

            throw new Error(`Failed to create config assignment on New Central.\n${debugInfo}`);
        }
    }
});

// ── Tool: Get AP Radio Channel Utilization Trends ───────────────────────────
// ดึงข้อมูล Channel Utilization Trends ของ radio บน AP ที่ระบุ
server.addTool({
    name: "get_ap_radio_channel_utilization_trends",
    description: "Retrieve channel utilization trend data for a specific radio on an AP from New Aruba Central. Calls GET /network-monitoring/v1/aps/{serialnumber}/radios/{radio}/channel-utilization-trends.",
    parameters: z.object({
        serialnumber: z.string().describe("Serial number of the AP"),
        radio: z.string().describe("Radio identifier, e.g. '0' (2.4 GHz), '1' (5 GHz), '2' (6 GHz)")
    }),
    execute: async (args) => {
        const { serialnumber, radio } = args;

        try {
            const token = await getAccessToken();
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const apiUrl = `${baseUrl}/network-monitoring/v1/aps/${encodeURIComponent(serialnumber)}/radios/${encodeURIComponent(radio)}/channel-utilization-trends`;

            const response = await axios.get(apiUrl, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "accept": "application/json"
                }
            });

            return `Channel utilization trends for AP '${serialnumber}' radio '${radio}':\n${JSON.stringify(response.data, null, 2)}`;
        } catch (error) {
            const status = error.response?.status;
            const responseData = error.response?.data;
            const errorMsg = responseData?.message || responseData?.description || error.message;
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const debugInfo = [
                `Status: ${status}`,
                `URL: ${baseUrl}/network-monitoring/v1/aps/${encodeURIComponent(serialnumber)}/radios/${encodeURIComponent(radio)}/channel-utilization-trends`,
                `Error: ${errorMsg}`,
                responseData ? `Response body: ${JSON.stringify(responseData)}` : null
            ].filter(Boolean).join("\n");

            throw new Error(`Failed to get channel utilization trends.\n${debugInfo}`);
        }
    }
});

// ── Tool: Get AP Radio Detail with Bandwidth Advisory ───────────────────────
// ดึงข้อมูลสถานะ radio ทั้งหมดของ AP พร้อมวิเคราะห์ channel utilization
// และให้คำแนะนำปรับ bandwidth เพื่อลด interference หรือเพิ่ม throughput
server.addTool({
    name: "get_ap_radio_detail",
    description: `Get current radio status for an AP including channelUtilization, band, bandwidth, and drops.
Analyses each radio and provides actionable recommendations:
- HIGH utilization (>70 %): suggests reducing bandwidth (e.g. 80 MHz → 40 MHz) to spread load across more channels and reduce interference.
- LOW utilization (<30 %): suggests increasing bandwidth (e.g. 40 MHz → 80 MHz / 160 MHz) to gain more throughput when the channel is clean.
- MODERATE utilization (30–70 %): reports current state as healthy.
Use together with 'get_ap_radio_channel_utilization_trends' for trend-based analysis.
Calls GET /network-monitoring/v1/aps/{serialnumber}/radios.`,
    parameters: z.object({
        serialnumber: z.string().describe("Serial number of the AP to inspect")
    }),
    execute: async (args) => {
        const { serialnumber } = args;

        try {
            const token = await getAccessToken();
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const apiUrl = `${baseUrl}/network-monitoring/v1/aps/${encodeURIComponent(serialnumber)}/radios`;

            const response = await axios.get(apiUrl, {
                headers: {
                    "Authorization": `Bearer ${token}`,
                    "accept": "application/json"
                }
            });

            const radios = response.data?.radios ?? response.data ?? [];

            if (!Array.isArray(radios) || radios.length === 0) {
                return `AP '${serialnumber}': No radio data returned from the API.\nRaw response: ${JSON.stringify(response.data, null, 2)}`;
            }

            // ── Build a structured report per radio ──────────────────────────
            const lines = [`📡 AP Radio Detail Report — Serial: ${serialnumber}\n`];

            for (const radio of radios) {
                const index          = radio.index          ?? radio.radio_number ?? "?";
                const band           = radio.band           ?? radio.radio_band   ?? "N/A";
                const bandwidth      = radio.bandwidth      ?? radio.channel_width ?? "N/A";
                const channel        = radio.channel        ?? "N/A";
                const utilization    = radio.channel_utilization ?? radio.channelUtilization ?? null;
                const drops          = radio.drops          ?? radio.tx_drops     ?? "N/A";
                const txPower        = radio.tx_power       ?? "N/A";
                const status         = radio.status         ?? "N/A";

                // ── Bandwidth advisory ───────────────────────────────────────
                let advisory = "";
                if (utilization !== null && utilization !== undefined) {
                    const util = Number(utilization);
                    if (util > 70) {
                        advisory = `⚠️  HIGH utilization (${util}%): Consider REDUCING bandwidth (e.g. ${bandwidth} MHz → lower) to widen channel availability and reduce co-channel interference. Also review neighbouring APs for channel overlap.`;
                    } else if (util < 30) {
                        advisory = `✅ LOW utilization (${util}%): Channel is clean. Consider INCREASING bandwidth (e.g. ${bandwidth} MHz → 80/160 MHz) to boost maximum throughput for connected clients.`;
                    } else {
                        advisory = `🟢 MODERATE utilization (${util}%): Current bandwidth (${bandwidth} MHz) appears healthy. Monitor trends with 'get_ap_radio_channel_utilization_trends'.`;
                    }
                } else {
                    advisory = `ℹ️  Channel utilization data not available for this radio.`;
                }

                lines.push(
                    `── Radio ${index} (${band}) ──────────────────────────`,
                    `  Status          : ${status}`,
                    `  Band            : ${band}`,
                    `  Channel         : ${channel}`,
                    `  Bandwidth       : ${bandwidth} MHz`,
                    `  Channel Util.   : ${utilization !== null && utilization !== undefined ? utilization + "%" : "N/A"}`,
                    `  Drops           : ${drops}`,
                    `  TX Power        : ${txPower} dBm`,
                    ``,
                    `  📋 Advisory: ${advisory}`,
                    ``
                );
            }

            lines.push(`\n💡 Tip: Run 'get_ap_radio_channel_utilization_trends' for each radio index above to see historical utilization patterns before making bandwidth changes.`);

            return lines.join("\n");
        } catch (error) {
            const status = error.response?.status;
            const responseData = error.response?.data;
            const errorMsg = responseData?.message || responseData?.description || error.message;
            const baseUrl = CENTRAL_BASE_URL.replace(/\/$/, "");
            const debugInfo = [
                `Status: ${status}`,
                `URL: ${baseUrl}/network-monitoring/v1/aps/${encodeURIComponent(serialnumber)}/radios`,
                `Error: ${errorMsg}`,
                responseData ? `Response body: ${JSON.stringify(responseData)}` : null
            ].filter(Boolean).join("\n");

            throw new Error(`Failed to get AP radio detail.\n${debugInfo}`);
        }
    }
});

// เปิดการเชื่อมต่อ
server.start();

