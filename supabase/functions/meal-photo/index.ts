// AT Fitness — meal photo → foods + estimated grams (Supabase Edge Function, Deno)
// Deploy:  supabase functions deploy meal-photo --project-ref zqmorfrtnmcpfgeqligp
// Secret (one of): supabase secrets set OPENAI_API_KEY=... | ANTHROPIC_API_KEY=... | GEMINI_API_KEY=... | XAI_API_KEY=...
const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const PROMPT = `You are a nutrition assistant. Identify every distinct food or drink visible in this meal photo and estimate the edible weight in grams (ml for drinks) of each portion as served.
Use plain generic UK/Irish food names (e.g. "chicken breast, grilled", "white rice, boiled", "broccoli", "olive oil"). Include sauces/oils only if clearly visible.
Reply ONLY with JSON: {"items":[{"name":string,"grams":number,"confidence":number 0-1,"alt":[up to 2 alternative names]}],"meal":short description}. If no food is visible reply {"items":[],"meal":"no food"}.`;
const j = (o: unknown, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { ...CORS, "Content-Type": "application/json" } });

function parse(t: string) {
  const m = t.match(/\{[\s\S]*\}/);
  if (!m) throw new Error("no json");
  const o = JSON.parse(m[0]);
  const items = (Array.isArray(o.items) ? o.items : []).slice(0, 12).map((x: any) => ({
    name: String(x.name || "").slice(0, 80),
    grams: Math.max(1, Math.min(1500, Math.round(Number(x.grams) || 100))),
    confidence: Math.max(0, Math.min(1, Number(x.confidence) || 0.5)),
    alt: (Array.isArray(x.alt) ? x.alt : []).slice(0, 2).map((a: any) => String(a).slice(0, 80)),
  })).filter((x: any) => x.name);
  return { items, meal: String(o.meal || "").slice(0, 120) };
}

async function openai(key: string, img: string, base = "https://api.openai.com/v1", model = Deno.env.get("MEAL_PHOTO_MODEL") || "gpt-4o-mini") {
  const r = await fetch(base + "/chat/completions", {
    method: "POST", headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/json" },
    body: JSON.stringify({ model, temperature: 0.2, max_tokens: 700, messages: [{ role: "user", content: [{ type: "text", text: PROMPT }, { type: "image_url", image_url: { url: `data:image/jpeg;base64,${img}` } }] }] }),
  });
  if (!r.ok) throw new Error("vision " + r.status);
  return (await r.json()).choices[0].message.content as string;
}
async function anthropic(key: string, img: string) {
  const r = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST", headers: { "x-api-key": key, "anthropic-version": "2023-06-01", "Content-Type": "application/json" },
    body: JSON.stringify({ model: Deno.env.get("MEAL_PHOTO_MODEL") || "claude-3-5-haiku-latest", max_tokens: 700, messages: [{ role: "user", content: [{ type: "image", source: { type: "base64", media_type: "image/jpeg", data: img } }, { type: "text", text: PROMPT }] }] }),
  });
  if (!r.ok) throw new Error("vision " + r.status);
  return (await r.json()).content[0].text as string;
}
async function gemini(key: string, img: string) {
  const m = Deno.env.get("MEAL_PHOTO_MODEL") || "gemini-2.0-flash";
  const r = await fetch(`https://generativelanguage.googleapis.com/v1beta/models/${m}:generateContent?key=${key}`, {
    method: "POST", headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ contents: [{ parts: [{ text: PROMPT }, { inline_data: { mime_type: "image/jpeg", data: img } }] }], generationConfig: { temperature: 0.2, responseMimeType: "application/json" } }),
  });
  if (!r.ok) throw new Error("vision " + r.status);
  return (await r.json()).candidates[0].content.parts[0].text as string;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return j({ error: "method" }, 405);
  const E = (k: string) => Deno.env.get(k) || "";
  const prov = E("OPENAI_API_KEY") ? "openai" : E("ANTHROPIC_API_KEY") ? "anthropic" : E("GEMINI_API_KEY") ? "gemini" : E("XAI_API_KEY") ? "xai" : "";
  if (!prov) return j({ error: "not_configured" }, 503);
  let body: any;
  try { body = await req.json(); } catch { return j({ error: "bad_json" }, 400); }
  const img = String(body?.image || "").replace(/^data:image\/\w+;base64,/, "");
  if (!img || img.length > 2_500_000) return j({ error: "bad_image" }, 400);
  try {
    const t = prov === "openai" ? await openai(E("OPENAI_API_KEY"), img)
      : prov === "anthropic" ? await anthropic(E("ANTHROPIC_API_KEY"), img)
      : prov === "gemini" ? await gemini(E("GEMINI_API_KEY"), img)
      : await openai(E("XAI_API_KEY"), img, "https://api.x.ai/v1", E("MEAL_PHOTO_MODEL") || "grok-2-vision-latest");
    return j({ ...parse(t), provider: prov });
  } catch (e) {
    return j({ error: "vision_failed", detail: String((e as Error).message || e).slice(0, 120) }, 502);
  }
});
