import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AuthTrail — local SSH authentication log analysis",
  description:
    "Analyze Linux SSH authentication logs entirely in your browser. No upload, no server, no tracking.",
};

export default function RootLayout({
  children,
}: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en">
      <body>{children}</body>
    </html>
  );
}
