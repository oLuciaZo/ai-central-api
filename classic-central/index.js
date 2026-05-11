#!/usr/bin/env node

import { FastMCP } from "fastmcp";
import { z } from "zod";
import axios from "axios";

// ตั้งค่า API Endpoint (ใส่ค่า Default เป็น APAC Cluster ซึ่งมักใช้ในไทย)
const ARUBA_BASE_URL = process.env.ARUBA_BASE_URL || "https://internal-apigw.central.arubanetworks.com";
const ARUBA_ACCESS_TOKEN = process.env.ARUBA_ACCESS_TOKEN;

if (!ARUBA_ACCESS_TOKEN) {
    console.error("Error: ARUBA_ACCESS_TOKEN environment variable is required for Classic Central.");
    process.exit(1);
}

// สร้าง FastMCP Server
const server = new FastMCP({
    name: "classic-aruba-central-mcp",
    version: "1.0.0"
});

// Tool 1: สร้าง SSID
server.addTool({
    name: "create_aruba_ssid",
    description: "Create a new SSID (WLAN profile) on Classic Aruba Central",
    parameters: z.object({
        ssid_name: z.string().describe("Name of the SSID"),
        vlan_id: z.number().int().describe("VLAN ID for the client traffic"),
        passphrase: z.string().describe("WPA2/WPA3 Pre-shared key"),
        group_name: z.string().describe("Aruba Central Group name (UI Group) to push the config to")
    }),
    execute: async (args) => {
        const { ssid_name, vlan_id, passphrase, group_name } = args;

        try {
            // โครงสร้าง Payload อ้างอิงตาม Aruba Central WLAN Configuration API
            const payload = {
                wlan: {
                    essid: ssid_name,
                    type: "employee",
                    vlan: vlan_id.toString(),
                    wpa_passphrase: passphrase,
                    wpa_passphrase_changed: true
                }
            };

            const apiUrl = `${ARUBA_BASE_URL}/configuration/v2/wlan/${encodeURIComponent(group_name)}/${encodeURIComponent(ssid_name)}`;

            const response = await axios.post(
                apiUrl,
                payload,
                {
                    headers: {
                        "Authorization": `Bearer ${ARUBA_ACCESS_TOKEN}`,
                        "Content-Type": "application/json"
                    }
                }
            );

            return `Successfully created SSID '${ssid_name}' on group '${group_name}'.\nAPI Response: ${JSON.stringify(response.data)}`;
        } catch (error) {
            const status = error.response?.status;
            const responseData = error.response?.data;
            const errorMsg = responseData?.message || responseData?.description || error.message;
            const debugInfo = [
                `Status: ${status}`,
                `URL: ${ARUBA_BASE_URL}/configuration/v2/wlan/${encodeURIComponent(group_name)}/${encodeURIComponent(ssid_name)}`,
                `Error: ${errorMsg}`,
                responseData ? `Response body: ${JSON.stringify(responseData)}` : null
            ].filter(Boolean).join("\n");

            throw new Error(`Failed to create SSID on Classic Central.\n${debugInfo}`);
        }
    }
});

// เปิดการเชื่อมต่อ
server.start();
