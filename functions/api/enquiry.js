/**
 * Cloudflare Pages Function — enquiry form handler.
 * Route: POST /api/enquiry  (Content-Type: application/json)
 *
 * Validates the submission, drops honeypot spam, verifies reCAPTCHA v3
 * (fail-closed), then delivers the enquiry by email to Andrew via the Resend
 * HTTP API. The API key is read from the RESEND_API_KEY environment
 * variable/secret — server-side only, never hardcoded, never sent to the
 * browser.
 *
 * Responses: { ok: true } only once Resend has accepted the message for
 * delivery; { ok: false, error } on any failure, with an appropriate HTTP
 * status so the front-end shows success (redirect to /enquiry-received/) or an
 * inline error. Nothing is sent to Go High Level.
 */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const MAX = { name: 200, email: 320, dates: 300, group: 60, tour: 200, message: 5000, hp: 100, token: 4000 };
const RECAPTCHA_MIN_SCORE = 0.5;
const RECAPTCHA_ACTION = "enquiry";

function json(body, status) {
  return new Response(JSON.stringify(body), {
    status: status,
    headers: { "content-type": "application/json; charset=utf-8" }
  });
}

function clean(value, max) {
  return (typeof value === "string" ? value : "").trim().slice(0, max);
}

export async function onRequestPost({ request, env }) {
  // 1. Parse JSON body
  let data;
  try {
    data = await request.json();
  } catch (_err) {
    return json({ ok: false, error: "Invalid request." }, 400);
  }

  // 2. Honeypot — a real user never fills this. Pretend success, forward nothing.
  if (clean(data && data._hp, MAX.hp)) {
    return json({ ok: true }, 200);
  }

  // 3. Validate the essentials
  const name = clean(data && data.name, MAX.name);
  const email = clean(data && data.email, MAX.email);
  if (!name) return json({ ok: false, error: "Please enter your name." }, 400);
  if (!EMAIL_RE.test(email)) return json({ ok: false, error: "Please enter a valid email address." }, 400);

  // 4. Verify the reCAPTCHA v3 token with Google before doing anything else.
  //    Fail closed: a missing secret, a missing token, a failed check, or an
  //    unreachable Google all reject the submission and never send an email.
  const secret = env && env.RECAPTCHA_SECRET_KEY;
  if (!secret) {
    console.error("RECAPTCHA_SECRET_KEY is not set");
    return json({ ok: false, error: "Sorry, the enquiry form is temporarily unavailable." }, 500);
  }
  const token = clean(data && data.recaptcha_token, MAX.token);
  if (!token) {
    return json({ ok: false, error: "Could not confirm you're human. Please reload the page and try again." }, 400);
  }
  let verdict;
  try {
    const params = new URLSearchParams({ secret: secret, response: token });
    const ip = request.headers.get("CF-Connecting-IP");
    if (ip) params.append("remoteip", ip);
    const vres = await fetch("https://www.google.com/recaptcha/api/siteverify", {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: params.toString()
    });
    verdict = await vres.json();
  } catch (err) {
    console.error("reCAPTCHA siteverify request failed", err);
    return json({ ok: false, error: "We couldn't verify your submission just now. Please try again in a moment." }, 502);
  }
  const passed =
    verdict &&
    verdict.success === true &&
    (verdict.action === undefined || verdict.action === RECAPTCHA_ACTION) &&
    (typeof verdict.score !== "number" || verdict.score >= RECAPTCHA_MIN_SCORE);
  if (!passed) {
    console.error("reCAPTCHA verification rejected", {
      success: verdict && verdict.success,
      score: verdict && verdict.score,
      action: verdict && verdict.action,
      errors: verdict && verdict["error-codes"]
    });
    return json({ ok: false, error: "Your submission couldn't be verified. Please try again." }, 403);
  }

  // 5. Ensure the email service is configured (server-side secret only)
  const resendKey = env && env.RESEND_API_KEY;
  if (!resendKey) {
    console.error("RESEND_API_KEY is not set");
    return json({ ok: false, error: "Sorry, the enquiry form is temporarily unavailable." }, 500);
  }

  // 6. Gather the enquiry fields (tour/page context preserved)
  const dates = clean(data.dates, MAX.dates);
  const group = clean(data.group, MAX.group);
  const tour = clean(data.tour, MAX.tour);
  const message = clean(data.message, MAX.message);

  // 7. Build the notification email. Reply-To is the customer's own address so
  //    Andrew can reply straight back to them from his inbox.
  const esc = (s) =>
    String(s == null ? "" : s)
      .replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
  const rows = [
    ["Name", name],
    ["Email", email],
    ["Preferred dates", dates],
    ["Group size", group],
    ["Tour / interest", tour],
    ["Message", message]
  ];
  const subject = "Website enquiry — " + name + (tour ? " — " + tour : "");
  const textBody =
    "New enquiry from the Expedition Yorkshire website\n\n" +
    rows.map(function (r) { return r[0] + ": " + (r[1] || "—"); }).join("\n") + "\n";
  const htmlBody =
    '<div style="font-family:Arial,Helvetica,sans-serif;font-size:15px;color:#1F2A24;line-height:1.6">' +
    '<h2 style="font-family:Georgia,serif;font-weight:normal;color:#324B3E;margin:0 0 16px">New website enquiry</h2>' +
    '<table cellpadding="0" cellspacing="0" style="border-collapse:collapse">' +
    rows.map(function (r) {
      return '<tr>' +
        '<td style="padding:6px 16px 6px 0;vertical-align:top;color:#6B7F70;white-space:nowrap">' + esc(r[0]) + '</td>' +
        '<td style="padding:6px 0;vertical-align:top;white-space:pre-wrap">' + esc(r[1] || "—") + '</td>' +
        '</tr>';
    }).join("") +
    '</table></div>';

  // 8. Deliver via Resend. Only report success once Resend accepts the message.
  let sendRes;
  try {
    sendRes = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: {
        "authorization": "Bearer " + resendKey,
        "content-type": "application/json"
      },
      body: JSON.stringify({
        from: "Expedition Yorkshire Website <enquiries@expeditionyorkshire.com>",
        to: ["andrew@expeditionyorkshire.com"],
        reply_to: email,
        subject: subject,
        text: textBody,
        html: htmlBody
      })
    });
  } catch (err) {
    console.error("Resend request failed", err);
    return json({ ok: false, error: "We couldn't send your enquiry. Please try again in a moment." }, 502);
  }
  if (!sendRes.ok) {
    let detail = "";
    try { detail = await sendRes.text(); } catch (_e) {}
    console.error("Resend responded with status", sendRes.status, detail);
    return json({ ok: false, error: "We couldn't send your enquiry. Please try again in a moment." }, 502);
  }

  return json({ ok: true }, 200);
}
