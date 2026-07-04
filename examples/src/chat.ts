import OpenAI from "openai";

const client = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function askGpt(prompt: string) {
  const res = await client.chat.completions.create({
    model: "gpt-4o",
    messages: [{ role: "user", content: prompt }],
  });
  return res.choices[0].message.content;
}

export async function callAnthropicDirect(prompt: string) {
  const url = `${process.env.ANTHROPIC_BASE ?? "https://api.anthropic.com"}/v1/messages`;
  const res = await fetch(url, {
    method: "POST",
    headers: { "x-api-key": process.env.ANTHROPIC_API_KEY! },
    body: JSON.stringify({ model: "claude-3-opus", messages: [{ role: "user", content: prompt }] }),
  });
  return res.json();
}
