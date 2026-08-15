#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const runnerUrl = (process.env.SOC_GHIDRA_RUNNER_URL || "http://soc-ghidra-runner:8080").replace(/\/$/, "");

async function postJson(path, payload) {
  const response = await fetch(`${runnerUrl}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  const text = await response.text();
  let parsed;
  try {
    parsed = JSON.parse(text || "{}");
  } catch {
    parsed = { raw: text };
  }
  if (!response.ok) {
    throw new Error(JSON.stringify(parsed));
  }
  return parsed;
}

const server = new McpServer({ name: "soc-ghidra-malware-analysis", version: "1.0.0" });

server.tool(
  "ghidra_static_analyze",
  "Run the controlled malware static-analysis pipeline for the malware analyst agent: CAPA, Ghidra Headless, and YARA. Accepts either a sample_path under the configured samples directory or a sample_url.",
  {
    sample_path: z.string().optional().describe("Path to a sample under GHIDRA_SAMPLES_DIR, usually /samples."),
    sample_url: z.string().url().optional().describe("HTTP(S) URL to download and analyze."),
  },
  async (input) => {
    const result = await postJson("/analyze", input);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  },
);

server.tool(
  "malware_static_pipeline",
  "Correlate CAPA capabilities, Ghidra Headless analysis, and YARA matches for a malware sample. Returns IOC candidates, MITRE ATT&CK candidates, suspicious functions, and verdict fields for the Malware Analyst agent.",
  {
    sample_path: z.string().optional().describe("Path to a sample under GHIDRA_SAMPLES_DIR, usually /samples."),
    sample_url: z.string().url().optional().describe("HTTP(S) URL to download and analyze."),
  },
  async (input) => {
    const result = await postJson("/analyze", input);
    return { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] };
  },
);

server.tool("ghidra_health", "Check the Ghidra runner health and malware analyst control surface.", {}, async () => {
  const response = await fetch(`${runnerUrl}/health`);
  const text = await response.text();
  return { content: [{ type: "text", text }] };
});

const transport = new StdioServerTransport();
await server.connect(transport);
