import type { NextConfig } from "next";

// Static export: the shipped artifact is plain static files. Log analysis
// runs entirely in the browser; there is no server-side processing.
const nextConfig: NextConfig = {
  output: "export",
};

export default nextConfig;
