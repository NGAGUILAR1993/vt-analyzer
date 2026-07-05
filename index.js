const express = require('express');
const axios = require('axios');
const FormData = require('form-data');
const crypto = require('crypto');

const app = express();
app.use(express.json({ limit: '700mb' }));
app.use((req, res, next) => {
  console.log(`📥 ${req.method} ${req.path} - ${new Date().toISOString()}`);
  next();
});
const PORT = process.env.PORT || 3000;

// Caché simple en memoria: hash → { result, timestamp }
const cache = {};
const CACHE_TTL = 30 * 60 * 1000; // 30 minutos

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
  
  const names = (data.attributes?.popular_threat_classification?.popular_threat_name || [])
    .map(t => t[0]).filter(Boolean).join(", ") || 'Desconocido';

  let mensaje = "";
  let motivos = [];

  if (mal > 0) {
    mensaje = mensaje + "🔴 DOCUMENTO PELIGROSO — Riesgo ALTO\n\n";
    motivos.push("Este archivo fue reportado como malicioso por múltiples motores antivirus.");
    if (names && names !== 'Desconocido') {
      motivos.push("Clasificación detectada: " + names + ".");
    }
  } else if (sus > 0) {
    mensaje = mensaje + "🟡 DOCUMENTO SOSPECHOSO — Riesgo MEDIO\n\n";
    motivos.push("Algunos motores de seguridad detectaron comportamiento raro en este archivo.");
  } else {
    mensaje = mensaje + "🟢 DOCUMENTO SEGURO — Riesgo BAJO\n\n";
  }

  mensaje = mensaje + "Archivo analizado: " + fileName + "\n";
  mensaje = mensaje + "Tamaño: " + formatBytes(fileSize) + "\n";
  mensaje = mensaje + "Hash SHA256: " + hash + "\n";
  
  if (total > 0) {
    mensaje = mensaje + "Motores analizados: " + total + " (" + mal + " maliciosos, " + sus + " sospechosos, " + harm + " limpios, " + undet + " sin detectar)\n";
  } else {
    mensaje = mensaje + "Motores analizados: Sin datos suficientes\n";
  }

  if (motivos.length > 0) {
    mensaje = mensaje + "\n⚠️ Por qué es peligroso:\n";
    for (var k = 0; k < motivos.length; k++) {
      mensaje = mensaje + "• " + motivos[k] + "\n";
    }
    mensaje = mensaje + "• Los archivos así suelen usarse para robar datos, instalar virus o estafar.\n";
    mensaje = mensaje + "• Si te lo enviaron por WhatsApp, email o link, es probable que sea una trampa.\n";
  }

  mensaje = mensaje + "\n🟡 Qué hacer:\n";
  mensaje = mensaje + "• La reputación de un archivo puede cambiar; uno seguro hoy puede estar comprometido mañana.\n";
  mensaje = mensaje + "• Si te llegó este archivo de alguien que no esperabas, no lo abras. Verificá con la persona por otro medio (llamada, otro chat).\n";
  mensaje = mensaje + "• Si ya tocaste el archivo o lo descargaste, no ingreses datos personales y cambia tus claves rápido.\n";
  
  if (mal > 0) {
    mensaje = mensaje + "• No interactúes con este archivo. Eliminalo inmediatamente.\n";
    mensaje = mensaje + "• Si ya ingresaste datos bancarios o personales, avisá a tu banco y cambiá todas las claves.\n";
  }

  if (sus > 0) {
    mensaje = mensaje + "• No abras el archivo a menos que confíes 100% en el remitente y esperes este documento específico.\n";
  }

  mensaje = mensaje + "\n✅ Decisión final: La herramienta revisa reportes de seguridad, pero la decisión de confiar o no es siempre tuya. Cuando dudes, no abras nada.\n";
  mensaje = mensaje + "🔗 Ver detalle: https://www.virustotal.com/gui/file/" + hash;

  return mensaje;
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

    // Verificar caché
    const cached = cache[hash];
    if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
      console.log("Cache hit para hash:", hash);
      return res.json({ report: cached.result });
    }

    // Lookup en VT
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
      const report = formatReport(vtData, fileName, hash, fileSize);
      cache[hash] = { result: report, timestamp: Date.now() };
      return res.json({ report });
    }

    // No está en VT → Subir
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
      const report = formatReport(final.data.data, fileName, hash, fileSize);
      cache[hash] = { result: report, timestamp: Date.now() };
      return res.json({ report });
    }

    const pendingReport = `⏳ *ANÁLISIS EN PROCESO*\n\n📄 ${fileName}\n🔐 \`${hash}\`\n\n✅ Enviado a VT. Consultá en 2 minutos:\n🔗 https://www.virustotal.com/gui/file/${hash}`;
    return res.json({ report: pendingReport });

  } catch (error) {
    console.error("Error:", error.message);
    const status = error.response?.status;
    let msg = "Error técnico en el servidor.";
    if (status === 413) msg = "El archivo es demasiado grande.";
    if (status === 429) msg = "Límite de quota excedido en VirusTotal. Esperá 1 minuto.";
    if (status === 401) msg = "API Key de VirusTotal inválida.";
    res.json({ report: `🚨 *Error:* ${msg}\n\n🚨 Decisión: No abras el archivo.` });
  }
});

app.get('/health', (req, res) => res.json({ status: "ok" }));

app.listen(PORT, () => console.log(`VT Analyzer en puerto ${PORT}`));
