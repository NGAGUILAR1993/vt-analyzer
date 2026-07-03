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
