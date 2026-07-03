const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '700mb' }));

const PORT = process.env.PORT || 3000;

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

function formatBytes(bytes) {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

function formatReport(data, fileName, hash, fileSize) {
  const stats = data.attributes?.last_analysis_stats || {};
  const mal = stats.malicious || 0;
  const sus = stats.suspicious || 0;
  const harm = stats.harmless || 0;
  const undet = stats.undetected || 0;
  const total = mal + sus + harm + undet;

  let estado, riesgo, accion;
  if (mal > 0) {
    estado = "🚨 MALICIOSO"; riesgo = "CRÍTICO";
    accion = "❌ NO ABRAS ESTE ARCHIVO. Eliminálo inmediatamente.";
  } else if (sus > 0) {
    estado = "⚠️ SOSPECHOSO"; riesgo = "MEDIO";
    accion = "🔍 No lo abras a menos que confíes 100% en el remitente.";
  } else {
    estado = "✅ LIMPIO"; riesgo = "BAJO";
    accion = "✓ No se detectaron amenazas en " + total + " motores.";
  }

  let text = "🛡️ *ANÁLISIS VIRUSTOTAL*\n\n";
  text += `📄 Archivo: ${fileName}\n`;
  text += `📏 Tamaño: ${formatBytes(fileSize)}\n`;
  text += `🔐 SHA256: \`${hash}\`\n`;
  text += `🔍 Motores: ${total}\n`;
  text += `🟢 Inofensivo: ${harm} | 🟡 No detectado: ${undet}\n`;
  text += `🟠 Sospechoso: ${sus} | 🔴 Malicioso: ${mal}\n\n`;
  text += `📊 Estado: ${estado}\n`;
  text += `⚡ Riesgo: ${riesgo}\n\n`;
  text += `🎯 Decisión: ${accion}\n`;
  text += `🔗 https://www.virustotal.com/gui/file/${hash}`;
  return text;
}

app.post('/analyze', async (req, res) => {
  try {
    const { base64, filename, vt_api_key } = req.body;
    if (!base64 || !vt_api_key) {
      return res.status(400).json({ error: "Faltan base64 o vt_api_key" });
    }

    const fileName = filename || "documento.pdf";
    const cleanBase64 = base64.replace(/^data:[^;]+;base64,/, "").trim();
    const fileBuffer = Buffer.from(cleanBase64, "base64");
    const fileSize = fileBuffer.length;
    const fileSizeMB = fileSize / (1024 * 1024);

    if (fileSizeMB > 650) {
      return res.json({ report: "🛡️ El archivo excede 650MB. No se puede analizar. No lo abras." });
    }

    const hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');

    let vtData = null;
    try {
      const lookup = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
        headers: { "x-apikey": vt_api_key }
      });
      vtData = lookup.data.data;
    } catch (e) {
      if (e.response?.status !== 404) console.error("Lookup error:", e.message);
    }

    if (vtData) {
      return res.json({ report: formatReport(vtData, fileName, hash, fileSize) });
    }

    let uploadUrl = "https://www.virustotal.com/api/v3/files";
    if (fileSizeMB > 32) {
      const urlRes = await axios.get("https://www.virustotal.com/api/v3/files/upload_url", {
        headers: { "x-apikey": vt_api_key }
      });
      uploadUrl = urlRes.data.data;
    }

    const form = new FormData();
    form.append('file', fileBuffer, fileName);

    await axios.post(uploadUrl, form, {
      headers: { ...form.getHeaders(), "x-apikey": vt_api_key }
    });

    await sleep(15000);

    const final = await axios.get(`https://www.virustotal.com/api/v3/files/${hash}`, {
      headers: { "x-apikey": vt_api_key }
    });

    if (final.data?.data) {
      return res.json({ report: formatReport(final.data.data, fileName, hash, fileSize) });
    }

    return res.json({
      report: `⏳ *ANÁLISIS EN PROCESO*\n\n📄 ${fileName}\n🔐 \`${hash}\`\n\n✅ Enviado a VT. Consultá en 2 minutos:\n🔗 https://www.virustotal.com/gui/file/${hash}`
    });

  } catch (error) {
    console.error("Error:", error.message);
    const status = error.response?.status;
    let msg = "Error técnico en el servidor.";
    if (status === 413) msg = "El archivo es demasiado grande.";
    if (status === 429) msg = "Límite de quota excedido. Esperá 1 minuto.";
    if (status === 401) msg = "API Key de VirusTotal inválida.";
    res.json({ report: `🚨 *Error:* ${msg}\n\n🚨 Decisión: No abras el archivo.` });
  }
});

app.get('/health', (req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => console.log(`VT Analyzer en puerto ${PORT}`));
