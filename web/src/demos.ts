// Demo URLs shown on the empty pages. None of these is in the training data; the malicious-looking ones use
// .example domains (RFC 2606: reserved, owned by no one). The app never fetches or opens any of them.
export type Demo = { url: string; title: string; kind: "benign" | "malicious"; trick: string };

export const DEMOS: Demo[] = [
  { url: "https://www.wikipedia.org/wiki/Finite-state_machine", title: "Wikipedia article", kind: "benign", trick: "Ordinary site with a path" },
  { url: "https://github.com/prakhar-1611", title: "GitHub profile", kind: "benign", trick: "Popular host, clean structure" },
  { url: "http://3232235777/login", title: "Hidden IP address", kind: "malicious", trick: "192.168.1.1 written as one number" },
  { url: "https://paypal.com@evil.example/login", title: "Fake username trick", kind: "malicious", trick: "Everything before @ is ignored" },
  { url: "https://xn--pypal-4ve.com/signin", title: "Look-alike letters", kind: "malicious", trick: "Punycode for pаypal (Cyrillic а)" },
  { url: "http://paypal.com.verify.account.secure-login.example/update", title: "Deep subdomains", kind: "malicious", trick: "paypal.com is only a subdomain" },
];

// Batch demo set: every URL here was scored with the trained model before the review.
export const BATCH_DEMO = [
  "https://www.wikipedia.org/wiki/Finite-state_machine",
  "https://www.vit.ac.in/",
  "https://github.com/prakhar-1611",
  "https://docs.python.org/3/library/re.html",
  "http://3232235777/login",
  "http://0xC0A80101/admin",
  "https://paypal.com@evil.example/login",
  "https://xn--pypal-4ve.com/signin",
  "https://аpple.com/id",
  "http://paypal.com.verify.account.secure-login.example/update",
  "http://secure-bank.example:8443/login",
  "http://example.com/redirect?url=http%3A%2F%2Fevil.example",
  "http://login.example/%2561%2564%256d%2569%256e",
  "http://update-account.example//login.php",
  "http://free-gift.tk/claim.exe",
];
