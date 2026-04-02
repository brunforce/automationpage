const admin = require('firebase-admin');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const fs = require('fs');
const path = require('path');

// ==========================================
// CONFIGURACIÓN DE SEGURIDAD
// ==========================================

const ALLOWED_ORIGINS = [
  'https://bcpscore.vercel.app',
  'https://bcpscore2.vercel.app'
];

const VALID_LEVELS = ['Crítico', 'En Desarrollo', 'Madurez Alta'];
const MAX_ANSWERS = 30;
const MAX_LABEL_LENGTH = 300;
const SCORE_MIN = 0;
const SCORE_MAX = 50;

// ==========================================
// HELPERS DE SEGURIDAD
// ==========================================

function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

const ipCache = new Map();
const RATE_LIMIT_WINDOW_MS = 120 * 1000;
const MAX_REQUESTS = 3; 

// ==========================================
// FUNCIÓN AUXILIAR: GENERADOR DE PLANTILLA HTML
// ==========================================
function generarHtmlCorreo(tituloHTML, subtitulo, tituloSeccion, contenidoHTML, safeName, safeEmail, safePhone, score, level) {
  return `
<html lang="es" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<!--[if gte mso 9]><xml><o:OfficeDocumentSettings><o:AllowPNG/><o:PixelsPerInch>96</o:PixelsPerInch></o:OfficeDocumentSettings></xml><![endif]-->
</head>
<body style="margin:0;padding:0;background-color:#f0f4f8;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f0f4f8" style="background-color:#f0f4f8;padding:40px 0;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%;">
  <tr>
    <td bgcolor="#1a3a6e" style="padding:0;background:#1a3a6e;">
      <!--[if gte mso 9]>
      <v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false" style="width:620px;">
        <v:fill type="gradient" color="#0a1628" color2="#1e4d9b" angle="160" focus="100%"/>
        <v:textbox inset="0,0,0,0" style="mso-fit-shape-to-text:true">
      <![endif]-->
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" bgcolor="#1a3a6e" style="padding:52px 52px 40px;background:linear-gradient(160deg,#0a1628 0%,#1a3a6e 55%,#1e4d9b 100%);">
            <img src="BASE64ENCODED IMG GOES HERE" alt="BCMEX" width="70" height="70" style="display:block;margin:0 auto 24px;border:0;outline:none;text-decoration:none;" border="0">
            <table cellpadding="0" cellspacing="0" align="center" style="margin:0 auto 20px;">
              <tr>
                <td align="center" bgcolor="#1e4d9b" style="background:#1e4d9b;border:1px solid #3b6bbf;padding:6px 20px;">
                  <span style="font-size:10px;color:#bfdbfe;letter-spacing:3px;text-transform:uppercase;font-weight:600;">${subtitulo}</span>
                </td>
              </tr>
            </table>
            <h1 style="margin:0 0 10px;font-size:28px;font-weight:300;color:#ffffff;letter-spacing:0.5px;line-height:36px;mso-line-height-rule:exactly;">
              ${tituloHTML}
            </h1>
            <p style="margin:0;font-size:12px;color:#bfdbfe;letter-spacing:2.5px;text-transform:uppercase;">Puntaje: ${score} / 50 (${level})</p>
            <table width="80" cellpadding="0" cellspacing="0" align="center" style="margin:28px auto 0;">
              <tr><td height="1" bgcolor="#5b8dd9" style="font-size:0;line-height:0;">&nbsp;</td></tr>
            </table>
          </td>
        </tr>
      </table>
      <!--[if gte mso 9]></v:textbox></v:rect><![endif]-->
    </td>
  </tr>
  <tr>
    <td bgcolor="#ffffff" style="background:#ffffff;padding:36px 52px 24px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
      <p style="margin:0 0 6px;font-size:13px;color:#4a7cb5;letter-spacing:2px;text-transform:uppercase;font-weight:600;">Datos del Prospecto</p>
      <p style="margin:0 0 20px;font-size:22px;font-weight:700;color:#0a1628;">${safeName}</p>
      <table width="100%" cellpadding="0" cellspacing="0" style="margin-bottom:24px; border:1px solid #e2e8f0; border-radius: 4px; background:#f8fafc;">
        <tr>
          <td style="padding:12px 15px; border-bottom:1px solid #e2e8f0; font-size:14px; color:#334155;"><strong>Email:</strong> <a href="mailto:${safeEmail}" style="color:#1a3a6e; text-decoration:none;">${safeEmail}</a></td>
        </tr>
        <tr>
          <td style="padding:12px 15px; font-size:14px; color:#334155;"><strong>Teléfono:</strong> ${safePhone}</td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td bgcolor="#ffffff" style="background:#ffffff;padding:8px 52px 20px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td width="70" height="1" bgcolor="#bdd7f5" style="font-size:0;line-height:0;">&nbsp;</td>
          <td align="center" style="padding:0 12px;">
            <span style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:#4a7cb5;font-weight:600;">&#9670;&nbsp; ${tituloSeccion} &nbsp;&#9670;</span>
          </td>
          <td width="70" height="1" bgcolor="#bdd7f5" style="font-size:0;line-height:0;">&nbsp;</td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td bgcolor="#ffffff" style="background:#ffffff;padding:0 52px 36px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td bgcolor="#f5f9ff" style="background:#f5f9ff;border-left:5px solid #1a3a6e;padding:28px 30px;">
            <div style="margin:0;font-size:14px;color:#0a1628;line-height:28px;mso-line-height-rule:exactly;white-space:pre-wrap;">${contenidoHTML}</div>
          </td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td bgcolor="#ffffff" style="background:#ffffff;padding:0 52px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
      <table width="100%" cellpadding="0" cellspacing="0"><tr><td height="1" bgcolor="#dce8f7" style="font-size:0;line-height:0;">&nbsp;</td></tr></table>
    </td>
  </tr>
  <tr>
    <td bgcolor="#ffffff" style="background:#ffffff;padding:32px 52px 44px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" bgcolor="#e8f0fd" style="background:#e8f0fd;border:1px solid #bdd7f5;padding:28px 32px;">
            <p style="margin:0 0 6px;font-size:17px;font-weight:700;color:#0a1628;">Información del Sistema</p>
            <p style="margin:0 0 22px;font-size:13px;color:#334155;line-height:1.7;">Este correo es de uso exclusivamente interno.<br>Requiere revisión humana antes de ser enviado al prospecto.</p>
            <table cellpadding="0" cellspacing="0" align="center">
              <tr>
                <td align="center" bgcolor="#1a3a6e" style="background:#1a3a6e;padding:14px 40px;">
                  <a href="https://bcmex.mx" style="color:#ffffff;text-decoration:none;font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;">Ir al portal &nbsp;&#8594;</a>
                </td>
              </tr>
            </table>
          </td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td bgcolor="#0f2348" style="padding:0;background:#0f2348;">
      <!--[if gte mso 9]>
      <v:rect xmlns:v="urn:schemas-microsoft-com:vml" fill="true" stroke="false" style="width:620px;">
        <v:fill type="gradient" color="#0a1628" color2="#1a3a6e" angle="135" focus="100%"/>
        <v:textbox inset="0,0,0,0" style="mso-fit-shape-to-text:true">
      <![endif]-->
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" bgcolor="#0f2348" style="padding:30px 52px;background:linear-gradient(135deg,#0a1628,#1a3a6e);">
            <p style="margin:0 0 4px;font-size:15px;color:#ffffff;letter-spacing:4px;font-weight:300;">BCMEX</p>
            <p style="margin:0 0 16px;font-size:10px;color:#8fb8e8;letter-spacing:1.5px;text-transform:uppercase;">Resiliencia Empresarial &nbsp;&#183;&nbsp; Continuidad de Negocio</p>
            <table width="40" cellpadding="0" cellspacing="0" align="center" style="margin:0 auto 16px;">
              <tr><td height="1" bgcolor="#2d5a9e" style="font-size:0;line-height:0;">&nbsp;</td></tr>
            </table>
            <p style="margin:0;font-size:11px;color:#6b8cba;line-height:18px;mso-line-height-rule:exactly;">
              Este correo es confidencial y est&#225; dirigido exclusivamente al equipo interno.<br>
              <a href="https://bcmex.mx" style="color:#8fb8e8;text-decoration:none;">www.bcmex.mx</a>
            </p>
          </td>
        </tr>
      </table>
      <!--[if gte mso 9]></v:textbox></v:rect><![endif]-->
    </td>
  </tr>
  <tr><td bgcolor="#f0f4f8" style="height:40px;">&nbsp;</td></tr>
</table>
</td></tr>
</table>
</body>
</html>
  `;
}

// ==========================================
// FUNCIÓN AUXILIAR: PROCESAMIENTO IA Y POSTMARK
// ==========================================
async function procesarIAyCorreo(data, dbKey) {
  try {
    const promptPath = path.join(process.cwd(), 'api', 'prompt.txt');
    if (!fs.existsSync(promptPath)) {
      throw new Error("No se encontró el archivo prompt.txt en la carpeta api/");
    }
    let promptText = fs.readFileSync(promptPath, 'utf8');

    promptText = promptText.replace(/{{Nombre del Cliente}}/g, data.name || 'Cliente');
    promptText = promptText.replace(/{{Puntaje}}/g, String(data.score || 0));
    promptText = promptText.replace(/{{Nivel de Riesgo}}/g, data.level || 'Desconocido');

    const respuestas = data.answers || {};
    for (const [key, answerObj] of Object.entries(respuestas)) {
      const shortId = key.split('_')[0].toUpperCase();
      const label = typeof answerObj === 'object' ? answerObj.label : String(answerObj);
      const regex = new RegExp(`{{Respuesta ${shortId}}}`, 'g');
      promptText = promptText.replace(regex, label);
    }

    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    // Cambiado al modelo solicitado en el script de Python original
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" }); 
    const result = await model.generateContent(promptText);
    
    const analisisCrudo = result.response.text().trim();

    if (!analisisCrudo) {
      throw new Error("Gemini devolvió una respuesta vacía.");
    }

    // Extracción de etiquetas como en Python
    const matchEmail = analisisCrudo.match(/\[EMAIL_CLIENTE_START\]([\s\S]*?)\[EMAIL_CLIENTE_END\]/i);
    const matchInterno = analisisCrudo.match(/\[ANALISIS_INTERNO_START\]([\s\S]*?)\[ANALISIS_INTERNO_END\]/i);

    const textoCorreoCliente = matchEmail ? matchEmail[1].trim() : "No se generó correctamente el bloque para el cliente.";
    const textoAnalisisInterno = matchInterno ? matchInterno[1].trim() : analisisCrudo; // Fallback

    const safeName = escapeHtml(data.name);
    const safeEmail = escapeHtml(data.email);
    const safePhone = escapeHtml(data.phone);

    const fromEmail = process.env.POSTMARK_FROM_EMAIL;
    const toEmail = process.env.POSTMARK_INTERNAL_EMAIL;
    const postmarkToken = process.env.POSTMARK_TOKEN;
    
    if (!postmarkToken || !fromEmail || !toEmail) {
         console.error("Faltan variables de entorno para Postmark.");
         return;
    }

    const postmarkUrl = "https://api.postmarkapp.com/email";
    const headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "X-Postmark-Server-Token": postmarkToken
    };

    // CORREO 1: Borrador para el cliente (Se envía al comercial)
    const payloadBorradorCliente = {
      From: fromEmail, 
      To: toEmail,
      ReplyTo: safeEmail, 
      MessageStream: "outbound",
      Subject: `[BORRADOR] Correo para Cliente - BCP: ${safeName}`,
      HtmlBody: generarHtmlCorreo(
          "Borrador de<br><strong style=\"font-weight:700;\">Correo para Cliente</strong>",
          "Revisión Humana Requerida",
          "Borrador Sugerido por IA",
          escapeHtml(textoCorreoCliente).replace(/\n/g, '<br>'),
          safeName, safeEmail, safePhone, data.score, data.level
      )
    };

    // CORREO 2: Análisis en crudo (Se envía al comercial)
    const payloadAnalisisInterno = {
      From: fromEmail, 
      To: toEmail,
      ReplyTo: safeEmail,
      MessageStream: "outbound",
      Subject: `🔥 NUEVO LEAD BCP (Análisis Interno): ${safeName}`,
      HtmlBody: generarHtmlCorreo(
          "Análisis Interno de<br><strong style=\"font-weight:700;\">Resiliencia Empresarial</strong>",
          "Informe Confidencial (No compartir)",
          "Análisis Crudo de IA",
          escapeHtml(textoAnalisisInterno).replace(/\n/g, '<br>'),
          safeName, safeEmail, safePhone, data.score, data.level
      )
    };

    // Enviar ambos correos en paralelo
    await Promise.all([
        fetch(postmarkUrl, { method: 'POST', headers, body: JSON.stringify(payloadBorradorCliente) }),
        fetch(postmarkUrl, { method: 'POST', headers, body: JSON.stringify(payloadAnalisisInterno) })
    ]);
    
    // Actualizar Firebase
    const db = admin.database();
    await db.ref(`respuestas_bcmex/${dbKey}`).update({ procesado: true });

  } catch (error) {
    console.error("Error Faltal en la IA o Postmark:", error);
  }
}

// ==========================================
// FUNCIÓN PRINCIPAL DEL SERVIDOR (HANDLER)
// ==========================================
export default async function handler(req, res) {
  const payloadString = JSON.stringify(req.body || {});
  if (Buffer.byteLength(payloadString, 'utf8') > 50000) {
    return res.status(413).json({ error: 'Payload Too Large' });
  }

  const origin = req.headers.origin;
  
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', origin && ALLOWED_ORIGINS.includes(origin) ? origin : ALLOWED_ORIGINS[0]);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, version');
    return res.status(200).end();
  }

  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ error: 'Acceso denegado. Origen no permitido.' });
  }

  res.setHeader('Access-Control-Allow-Origin', origin || ALLOWED_ORIGINS[0]);

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  const clientToken = req.headers['version'];
  if (!clientToken || clientToken !== process.env.API_SECRET) {
    return res.status(401).json({ error: 'No autorizado. Token inválido o ausente.' });
  }

  const rawForwarded = req.headers['x-forwarded-for'] || '';
  const clientIp = req.headers['x-real-ip'] || rawForwarded.split(',')[0].trim() || req.socket.remoteAddress || 'ip-desconocida';
  const currentTime = Date.now();

  if (ipCache.has(clientIp)) {
    const rateData = ipCache.get(clientIp);
    if (currentTime - rateData.startTime < RATE_LIMIT_WINDOW_MS) {
      if (rateData.count >= MAX_REQUESTS) {
        return res.status(429).json({ error: 'Demasiadas solicitudes.' });
      }
      rateData.count++;
    } else {
      ipCache.set(clientIp, { count: 1, startTime: currentTime });
    }
  } else {
    ipCache.set(clientIp, { count: 1, startTime: currentTime });
  }

  if (ipCache.size > 1000) ipCache.clear();

  const dbUrl = process.env.FIREBASE_DATABASE_URL;
  if (!dbUrl || !process.env.FIREBASE_PRIVATE_KEY || !process.env.API_SECRET) {
    return res.status(500).json({ error: 'Error de configuración interna.' });
  }

  try {
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        }),
        databaseURL: dbUrl
      });
    }

    const db = admin.database();
    const data = req.body;

    // FASE 1: CREAR LEAD
    if (data.action === 'create') {
        if (!data.email || typeof data.email !== 'string' || !data.email.includes('@')) {
            return res.status(400).json({ error: 'Correo electrónico inválido' });
        }
        if (!data.name || typeof data.name !== 'string' || data.name.trim() === '') {
            return res.status(400).json({ error: 'Nombre inválido' });
        }

        const cleanData = {
            name: escapeHtml(data.name.trim()),
            email: escapeHtml(data.email.trim().toLowerCase()),
            timestamp: admin.database.ServerValue.TIMESTAMP,
            source: 'Vercel-API-Secure',
            status: 'incompleto', 
            procesado: false
        };

        const newLeadRef = db.ref('respuestas_bcmex').push();
        await newLeadRef.set(cleanData);

        return res.status(200).json({ success: true, leadId: newLeadRef.key });
    }

    // FASE 2: ACTUALIZAR Y PROCESAR
    else if (data.action === 'update') {
        if (!data.leadId) return res.status(400).json({ error: 'Falta ID de lead' });

        if (!data.phone || typeof data.phone !== 'string' || !/^\+[0-9]{10,15}$/.test(data.phone.trim())) {
            return res.status(400).json({ error: 'El teléfono es obligatorio y debe incluir código de país.' });
        }

        const rawScore = typeof data.score === 'number' ? data.score : parseInt(data.score, 10);
        if (isNaN(rawScore) || rawScore < SCORE_MIN || rawScore > SCORE_MAX) {
            return res.status(400).json({ error: 'Puntaje inválido.' });
        }

        let cleanAnswers = {};
        if (data.answers && typeof data.answers === 'object') {
            const keys = Object.keys(data.answers).slice(0, MAX_ANSWERS);
            for (const key of keys) {
                const rawLabel = data.answers[key]?.label || "Sin respuesta";
                const rawValue = data.answers[key]?.value || 0;
                cleanAnswers[key] = {
                    value: typeof rawValue === 'number' ? rawValue : 0,
                    label: escapeHtml(String(rawLabel).substring(0, MAX_LABEL_LENGTH))
                };
            }
        }

        const leadSnapshot = await db.ref(`respuestas_bcmex/${data.leadId}`).once('value');
        if (!leadSnapshot.exists()) {
            return res.status(404).json({ error: 'Lead no encontrado' });
        }
        const existingData = leadSnapshot.val();

        await db.ref(`respuestas_bcmex/${data.leadId}`).update({
            phone: escapeHtml(data.phone.trim()),
            level: escapeHtml(data.level),
            score: rawScore,
            answers: cleanAnswers,
            status: 'completado'
        });

        const mergedData = {
            ...existingData,
            phone: escapeHtml(data.phone.trim()),
            level: escapeHtml(data.level),
            score: rawScore,
            answers: cleanAnswers
        };

        // Esperar el procesamiento de IA y Correos
        await procesarIAyCorreo(mergedData, data.leadId);

        return res.status(200).json({ success: true, message: 'Lead completado y procesado' });
    } 
    
    else {
        return res.status(400).json({ error: 'Acción no válida' });
    }

  } catch (error) {
    console.error('Error interno de servidor:', error);
    return res.status(500).json({ error: 'Error interno al procesar' });
  }
}
