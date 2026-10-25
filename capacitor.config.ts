import type { CapacitorConfig } from "@capacitor/cli";

// This origin serves both the web UI and its same-origin Node API.
const apiBaseUrl = process.env.API_BASE_URL?.trim();
let server: CapacitorConfig["server"];

if (apiBaseUrl) {
  const parsed = new URL(apiBaseUrl);
  if (parsed.protocol !== "https:" || parsed.username || parsed.password || parsed.search || parsed.hash || parsed.pathname !== "/") {
    throw new Error("API_BASE_URL must be an HTTPS origin with no credentials, path, query, or fragment.");
  }
  server = { url: parsed.origin };
}

const config: CapacitorConfig = {
  appId: "org.ewuvoting.ballotprototype",
  appName: "Ballot Voting Prototype",
  webDir: "public",
  server
};

export default config;
