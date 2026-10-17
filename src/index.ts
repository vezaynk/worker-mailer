export interface Env {
  ALLOWED: KVNamespace;
  MAILGUN_API_KEY: string;
  TURNSTILE_SECRET: string;
}

const ALLOWED_ORIGINS = new Set([
  "https://knyazev.io",
  "https://www.knyazev.io",
]);
const ALLOWED_HOSTNAMES = new Set(["knyazev.io", "www.knyazev.io"]);
const SITEVERIFY_URL =
  "https://challenges.cloudflare.com/turnstile/v0/siteverify";
const MAILGUN_URL = "https://api.mailgun.net/v3/mg.knyazev.io/messages";

interface SiteverifyResult {
  success: boolean;
  hostname?: string;
  "error-codes"?: string[];
  action?: string;
  challenge_ts?: string;
}

function corsHeaders(request: Request): Record<string, string> {
  const origin = request.headers.get("Origin");
  const headers: Record<string, string> = { Vary: "Origin" };
  if (origin && ALLOWED_ORIGINS.has(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
    headers["Access-Control-Allow-Methods"] = "POST, OPTIONS";
    headers["Access-Control-Allow-Headers"] = "Content-Type";
    headers["Access-Control-Max-Age"] = "86400";
  }
  return headers;
}

function json(
  request: Request,
  status: number,
  body: { ok: true } | { ok: false; error: string },
  extra: Record<string, string> = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json;charset=UTF-8",
      ...corsHeaders(request),
      ...extra,
    },
  });
}

async function verifyTurnstile(
  token: string,
  secret: string,
  remoteip: string | null
): Promise<SiteverifyResult> {
  const body = new URLSearchParams({ secret, response: token });
  if (remoteip) body.set("remoteip", remoteip);
  const res = await fetch(SITEVERIFY_URL, { method: "POST", body });
  if (!res.ok) return { success: false, "error-codes": [`http-${res.status}`] };
  return (await res.json()) as SiteverifyResult;
}

async function handleSend(request: Request, env: Env): Promise<Response> {
  let formData: FormData;
  try {
    formData = await request.formData();
  } catch {
    return json(request, 400, { ok: false, error: "Invalid form data" });
  }

  const field = (name: string) => formData.get(name)?.toString().trim() || "";
  const token = field("cf-turnstile-response");
  const senderName = field("name");
  const senderContact = field("contact");
  const messageBody = field("body");
  const messageTitle = field("subject") || senderName;
  const selectedTo = field("to");
  const senderIP = request.headers.get("CF-Connecting-IP");

  if (!token) {
    return json(request, 403, { ok: false, error: "Captcha verification failed" });
  }
  if (!env.TURNSTILE_SECRET) {
    console.error("TURNSTILE_SECRET is not configured");
    return json(request, 500, { ok: false, error: "Server misconfigured" });
  }

  const verification = await verifyTurnstile(
    token,
    env.TURNSTILE_SECRET,
    senderIP
  );
  if (
    !verification.success ||
    !verification.hostname ||
    !ALLOWED_HOSTNAMES.has(verification.hostname)
  ) {
    console.log("Turnstile rejected", JSON.stringify(verification));
    return json(request, 403, { ok: false, error: "Captcha verification failed" });
  }

  if (!senderName || !senderContact || !messageBody || !selectedTo) {
    return json(request, 400, { ok: false, error: "Missing required fields" });
  }

  const to = await env.ALLOWED.get(selectedTo);
  if (!to) {
    return json(request, 400, { ok: false, error: "No such contact" });
  }

  const mail = new URLSearchParams({
    from: "contact@mg.knyazev.io",
    to,
    subject: `Message from website ${messageTitle}`,
    template: "contact-message",
    "v:title": messageTitle,
    "v:message": messageBody,
    "v:name": senderName,
    "v:contact": senderContact,
    "v:ip": senderIP ?? "unknown",
  });
  if (senderContact.includes("@")) mail.set("h:Reply-To", senderContact);

  const mailRes = await fetch(MAILGUN_URL, {
    method: "POST",
    headers: {
      Authorization: "Basic " + btoa(env.MAILGUN_API_KEY),
    },
    body: mail,
  });

  if (!mailRes.ok) {
    console.error("Mailgun error", mailRes.status, await mailRes.text());
    return json(request, 502, { ok: false, error: "Could not send message" });
  }

  return json(request, 200, { ok: true });
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    try {
      const { pathname } = new URL(request.url);

      if (pathname !== "/send") {
        return json(request, 404, { ok: false, error: "Not found" });
      }
      if (request.method === "OPTIONS") {
        return new Response(null, { status: 204, headers: corsHeaders(request) });
      }
      if (request.method !== "POST") {
        return json(
          request,
          405,
          { ok: false, error: "Method not allowed" },
          { Allow: "POST, OPTIONS" }
        );
      }
      return await handleSend(request, env);
    } catch (err) {
      console.error("Unhandled error", err instanceof Error ? err.stack : err);
      return json(request, 500, { ok: false, error: "Internal error" });
    }
  },
};
