// Turns a bare (type, resource_name, value) challenge into the actual
// step-by-step instructions a human needs — before this, the wizard just
// dumped resource_name/value with one generic sentence, and a first-time
// user had no way to know a URL needed a *file* created at that exact path
// versus a DNS record, or which record type, or that it has to be plain
// HTTP not HTTPS. Steps are generic (not templated with the domain/value —
// those already render as their own code blocks next to these steps).
export interface ChallengeInstructionSet {
  summary: string;
  steps: string[];
  valueLabels: [string, string]; // labels for the two code blocks a manual challenge shows (resource_name, value)
}

export function getChallengeInstructions(caProvider: string, method: string): ChallengeInstructionSet {
  const key = `${caProvider}:${method}`;
  switch (key) {
    case "letsencrypt:http-01":
      return {
        summary: "Let's Encrypt needs to fetch a file from your web server over plain HTTP to confirm you control this domain.",
        steps: [
          "Copy the URL shown below as \"File URL\" — everything after the domain, starting with /.well-known/acme-challenge/, is the file's path relative to your web root.",
          "Create that file on the web server that answers for this domain on port 80 (plain HTTP — not HTTPS, and the URL must not redirect).",
          "Set the file's entire contents to exactly the text shown as \"File contents\" below — no extra spaces, blank lines, or trailing newline.",
          "Confirm the URL loads directly in a browser or with curl and returns exactly that text.",
          "Come back here and click \"Check now\".",
        ],
        valueLabels: ["File URL", "File contents"],
      };
    case "letsencrypt:dns-01":
      return {
        summary: "Let's Encrypt needs a TXT record published in this domain's DNS zone to confirm you control it.",
        steps: [
          "Log into whichever DNS provider hosts this domain's zone (Cloudflare, Route 53, your registrar, etc.).",
          "Create a new TXT record with the exact name shown below as \"Record name\" — some providers want the full name, others only the part before your zone's own domain, so check both if the first attempt doesn't take.",
          "Set the record's value to exactly the text shown as \"Record value\" (including the surrounding quotes if your provider requires them for TXT records).",
          "Save the record and wait a few minutes for DNS propagation — this varies by provider, sometimes up to the record's TTL.",
          "Come back here and click \"Check now\". If it fails, wait longer and try again — DNS propagation delay is the most common reason this doesn't verify immediately.",
        ],
        valueLabels: ["Record name (TXT)", "Record value"],
      };
    case "zerossl:http-file":
      return {
        summary: "ZeroSSL needs to fetch a file from your web server over plain HTTP to confirm you control this domain.",
        steps: [
          "Copy the exact URL shown below as \"File URL\".",
          "Create that file at the matching path on the web server that answers for this domain on port 80 (plain HTTP, no redirect).",
          "Set the file's entire contents to exactly the text shown as \"File contents\" below.",
          "Confirm the URL loads directly and returns exactly that text.",
          "Come back here and click \"Check now\".",
        ],
        valueLabels: ["File URL", "File contents"],
      };
    case "zerossl:cname":
      return {
        summary: "ZeroSSL needs a CNAME record published in this domain's DNS zone to confirm you control it.",
        steps: [
          "Log into whichever DNS provider hosts this domain's zone.",
          "Create a new CNAME record with the exact name shown below as \"Record name\".",
          "Point it at the exact target shown as \"Points to\" below.",
          "Save the record and wait a few minutes for DNS propagation.",
          "Come back here and click \"Check now\".",
        ],
        valueLabels: ["Record name (CNAME)", "Points to"],
      };
    default:
      return {
        summary: "Publish the following to prove you control this domain, then check again.",
        steps: ["Publish the values below exactly as shown.", "Come back here and click \"Check now\"."],
        valueLabels: ["Resource", "Value"],
      };
  }
}
