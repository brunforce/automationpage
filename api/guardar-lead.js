const admin = require('firebase-admin');
const { GoogleGenerativeAI } = require('@google/generative-ai');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto'); // Módulo nativo para evitar Timing Attacks

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

// MAPA DE PREGUNTAS (Para formatear el correo interno)
const QUESTION_MAP = {
  p1_market: "¿Cuál es la participación de mercado de su empresa en el país?",
  p2_employees: "¿Cuántas personas participan directamente en la operación diaria del negocio?",
  p3_dependency: "¿Qué tan dependiente es su operación de sistemas digitales para generar ingresos?",
  p4_systems: "¿Cuántos sistemas o aplicaciones son críticos para la operación diaria?",
  p5_impact: "Una interrupción tecnológica impactaría principalmente en:",
  p6_team: "¿Existe un equipo o área responsable de continuidad, riesgos o tecnología?",
  q1_financial: "Considerando la duración estimada de una interrupción en sus procesos clave, ¿qué nivel de pérdida financiera generaría para la organización?",
  q2_operational: "Si ocurre un incidente crítico en sus procesos clave, ¿Cuál sería el nivel de interrupción operativa a organización?",
  q3_prioritization: "¿Cómo identifican y priorizan sus procesos críticos para continuidad?",
  q4_rto: "Para sus procesos críticos, el RTO definido es:",
  q5_rpo: "En caso de incidente, la pérdida aceptable de información es:",
  q6_recovery: "La recuperación de sistemas críticos es principalmente:",
  q7_responsibility: "Si ocurre una falla grave, la responsabilidad de recuperación recae en:",
  q8_tests: "¿Con qué frecuencia se prueban los planes BCP/DRP?",
  q9_detection: "¿Cómo detectan riesgos de interrupción antes de que ocurran?"
};

// ==========================================
// HELPERS DE SEGURIDAD Y SANITIZACIÓN
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

// Bloquea intentos de Prompt Injection hacia Gemini
function sanitizeForPrompt(str, maxLength = 200) {
    if (typeof str !== 'string') return '';
    return str
      .replace(/[\[\]{}<>$]/g, '') // Elimina caracteres usados en inyección
      .replace(/ignora|instrucciones|system|prompt|olvida/gi, '') 
      .trim()
      .substring(0, maxLength);
}

const ipCache = new Map();
const RATE_LIMIT_WINDOW_MS = 120 * 1000;
const MAX_REQUESTS = 3; 

// ==========================================
// FUNCIÓN AUXILIAR: GENERADOR DE PLANTILLA HTML
// ==========================================
function generarHtmlCorreo({
  tituloHTML, 
  subtitulo, 
  tituloSeccion, 
  contenidoHTML, 
  safeName, 
  safeEmail, 
  safePhone, 
  score, 
  level, 
  isInternal = false, 
  respuestas = {}
}) {
  
  let datosProspectoHtml = `<p style="margin:0 0 10px;font-size:22px;font-weight:700;color:#0a1628;">${safeName}</p>`;
  let respuestasHtml = '';

  if (isInternal) {
    datosProspectoHtml = `
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
    `;

    const respArray = Object.entries(respuestas);
    if (respArray.length > 0) {
        const filasRespuestas = respArray.map(([key, ans], idx) => {
            const pregunta = QUESTION_MAP[key] || escapeHtml(key);
            const borderStyle = idx !== respArray.length - 1 ? 'border-bottom:1px solid #e2e8f0;' : '';
            return `
            <tr>
              <td style="padding:12px 15px; ${borderStyle} font-size:13px; color:#334155;">
                  <strong style="color:#0a1628; display:block; margin-bottom:4px;">${pregunta}</strong>
                  <span style="color:#4a7cb5;">&#10148; ${escapeHtml(ans.label)}</span>
              </td>
            </tr>`;
        }).join('');

        respuestasHtml = `
        <tr>
          <td bgcolor="#ffffff" style="background:#ffffff;padding:8px 52px 20px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
            <table width="100%" cellpadding="0" cellspacing="0">
              <tr>
                <td width="70" height="1" bgcolor="#bdd7f5" style="font-size:0;line-height:0;">&nbsp;</td>
                <td align="center" style="padding:0 12px;">
                  <span style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:#4a7cb5;font-weight:600;">&#9670;&nbsp; Respuestas del Cuestionario &nbsp;&#9670;</span>
                </td>
                <td width="70" height="1" bgcolor="#bdd7f5" style="font-size:0;line-height:0;">&nbsp;</td>
              </tr>
            </table>
          </td>
        </tr>
        <tr>
          <td bgcolor="#ffffff" style="background:#ffffff;padding:0 52px 24px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
            <table width="100%" cellpadding="0" cellspacing="0" style="border:1px solid #e2e8f0; border-radius: 4px; background:#f8fafc;">
              ${filasRespuestas}
            </table>
          </td>
        </tr>
        `;
    }
  }

  return `
<html lang="es" xmlns:v="urn:schemas-microsoft-com:vml" xmlns:o="urn:schemas-microsoft-com:office:office">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#f0f4f8;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" bgcolor="#f0f4f8" style="background-color:#f0f4f8;padding:40px 0;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%;">
  <tr>
    <td bgcolor="#1a3a6e" style="padding:0;background:#1a3a6e;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td align="center" bgcolor="#1a3a6e" style="padding:52px 52px 40px;background:linear-gradient(160deg,#0a1628 0%,#1a3a6e 55%,#1e4d9b 100%);">
            <img src="data:image/png;base64,TU_CODIGO_BASE64_LARGUISIMO_AQUI" alt="BCMEX" width="180" style="display:block;margin:0 auto 24px;border:0;outline:none;text-decoration:none;background-color:#ffffff;padding:12px 24px;border-radius:8px;" border="0">
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
    </td>
  </tr>
  <tr>
    <td bgcolor="#ffffff" style="background:#ffffff;padding:36px 52px 24px;border-left:1px solid #c5d9f0;border-right:1px solid #c5d9f0;">
      ${datosProspectoHtml}
    </td>
  </tr>
  ${respuestasHtml}
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
          </td>
        </tr>
      </table>
    </td>
  </tr>
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
// Se agrega "reqHost" para construir dinámicamente la URL de reintento manual
async function procesarIAyCorreo(data, dbKey, reqHost) {
  const db = admin.database();
  try {
    const promptPath = path.join(process.cwd(), 'api', 'prompt.txt');
    if (!fs.existsSync(promptPath)) throw new Error("No se encontró el archivo prompt.txt en la carpeta api/");
    let promptText = fs.readFileSync(promptPath, 'utf8');

    // Sanitización específica contra Prompt Injection
    promptText = promptText.replace(/{{Nombre del Cliente}}/g, sanitizeForPrompt(data.name));
    promptText = promptText.replace(/{{Puntaje}}/g, String(data.score));
    promptText = promptText.replace(/{{Nivel de Riesgo}}/g, sanitizeForPrompt(data.level));

    const respuestas = data.answers || {};
    for (const [key, answerObj] of Object.entries(respuestas)) {
      const shortId = key.split('_')[0].toUpperCase();
      const label = typeof answerObj === 'object' ? answerObj.label : String(answerObj);
      const regex = new RegExp(`{{Respuesta ${shortId}}}`, 'g');
      promptText = promptText.replace(regex, sanitizeForPrompt(label, MAX_LABEL_LENGTH));
    }

    if (!process.env.GEMINI_API_KEY) throw new Error("Falta la variable de entorno GEMINI_API_KEY en Vercel.");

    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" }); 
    const result = await model.generateContent(promptText);
    const analisisCrudo = result.response.text().trim();

    if (!analisisCrudo) throw new Error("Gemini devolvió una respuesta vacía.");

    const matchEmail = analisisCrudo.match(/(?:\[|\$\$)\s*EMAIL_CLIENTE_START\s*(?:\]|\$\$)([\s\S]*?)(?:\[|\$\$)\s*EMAIL_CLIENTE_END\s*(?:\]|\$\$)/i);
    const matchInterno = analisisCrudo.match(/(?:\[|\$\$)\s*ANALISIS_INTERNO_START\s*(?:\]|\$\$)([\s\S]*?)(?:\[|\$\$)\s*ANALISIS_INTERNO_END\s*(?:\]|\$\$)/i);

    const textoCorreoCliente = matchEmail ? matchEmail[1].trim() : "No se generó correctamente el bloque para el cliente.";
    const textoAnalisisInterno = matchInterno ? matchInterno[1].trim() : analisisCrudo; 

    // Escapamos los datos solo al inyectarlos en HTML
    const safeName = escapeHtml(data.name);
    const safeEmail = escapeHtml(data.email);
    const safePhone = escapeHtml(data.phone);

    const fromEmail = process.env.POSTMARK_FROM_EMAIL;
    const toEmail = process.env.POSTMARK_INTERNAL_EMAIL;
    const postmarkToken = process.env.POSTMARK_TOKEN;
    
    if (!postmarkToken || !fromEmail || !toEmail) throw new Error("Faltan variables de entorno para Postmark (POSTMARK_TOKEN, POSTMARK_FROM_EMAIL, o POSTMARK_INTERNAL_EMAIL).");

    const postmarkUrl = "https://api.postmarkapp.com/email";
    const headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "X-Postmark-Server-Token": postmarkToken
    };

    const payloadBorradorCliente = {
      From: fromEmail, 
      To: toEmail,
      ReplyTo: safeEmail, 
      MessageStream: "outbound",
      Subject: `[BORRADOR] Correo para Cliente - BCP: ${safeName}`,
      HtmlBody: generarHtmlCorreo({
          tituloHTML: "Borrador de<br><strong style=\"font-weight:700;\">Correo para Cliente</strong>",
          subtitulo: "Revisión Humana Requerida",
          tituloSeccion: "Borrador Sugerido por IA",
          contenidoHTML: escapeHtml(textoCorreoCliente).replace(/\n/g, '<br>'),
          safeName, safeEmail, safePhone, score: data.score, level: escapeHtml(data.level),
          isInternal: false 
      })
    };

    const payloadAnalisisInterno = {
      From: fromEmail, 
      To: toEmail,
      ReplyTo: safeEmail,
      MessageStream: "outbound",
      Subject: `🔥 NUEVO LEAD BCP (Análisis Interno): ${safeName}`,
      HtmlBody: generarHtmlCorreo({
          tituloHTML: "Análisis Interno de<br><strong style=\"font-weight:700;\">Resiliencia Empresarial</strong>",
          subtitulo: "Informe Confidencial (No compartir)",
          tituloSeccion: "Análisis Crudo de IA",
          contenidoHTML: escapeHtml(textoAnalisisInterno).replace(/\n/g, '<br>'),
          safeName, safeEmail, safePhone, score: data.score, level: escapeHtml(data.level),
          isInternal: true,
          respuestas: data.answers 
      })
    };

    // Verificamos respuesta de Postmark
    const [res1, res2] = await Promise.all([
        fetch(postmarkUrl, { method: 'POST', headers, body: JSON.stringify(payloadBorradorCliente) }),
        fetch(postmarkUrl, { method: 'POST', headers, body: JSON.stringify(payloadAnalisisInterno) })
    ]);
    
    if (!res1.ok) {
        const errText1 = await res1.text();
        throw new Error(`Fallo en Postmark (Correo 1): ${errText1}`);
    }
    if (!res2.ok) {
        const errText2 = await res2.text();
        throw new Error(`Fallo en Postmark (Correo 2): ${errText2}`);
    }

    await db.ref(`respuestas_bcmex/${dbKey}`).update({ procesado: true });

  } catch (error) {
    console.error("Error en procesamiento secundario:", error);
    await db.ref(`respuestas_bcmex/${dbKey}`).update({ procesado: 'error_email' });

    // ==============================================================
    // PLAN B: ALERTA DE RESCATE CON DETALLE DE ERROR
    // ==============================================================
    try {
        const safeName = escapeHtml(data.name);
        const safeEmail = escapeHtml(data.email);
        const safePhone = escapeHtml(data.phone);
        
        // Creamos la URL segura y CODIFICAMOS el token para evitar que el símbolo '#' lo rompa
        const host = reqHost || 'bcpscore.vercel.app';
        const retrySecret = process.env.RETRY_SECRET || process.env.API_SECRET || ''; 
        const encodedToken = encodeURIComponent(retrySecret); // ← ¡AQUÍ ESTÁ LA MAGIA PARA EL SIMBOLO #!
        
        const retryUrl = `https://${host}/api/guardar-lead?action=retry&leadId=${dbKey}&token=${encodedToken}`;

        const fallbackHtml = generarHtmlCorreo({
            tituloHTML: "Alerta de Fallo en Procesamiento<br><strong style=\"font-weight:700;\">Datos Rescatados</strong>",
            subtitulo: "ACCIÓN MANUAL REQUERIDA",
            tituloSeccion: "Datos Crudos del Prospecto",
            contenidoHTML: `
                <div style="background-color:#fee2e2; border:1px solid #f87171; border-radius:6px; padding:16px; margin-bottom:20px;">
                    <p style="color:#b91c1c; font-weight:bold; margin:0 0 8px 0;">⚠️ Falló la generación de los correos automáticos.</p>
                    <p style="color:#7f1d1d; font-size:13px; margin:0 0 8px 0;">El servidor reportó el siguiente error técnico:</p>
                    <pre style="background:#fef2f2; color:#991b1b; padding:10px; border-radius:4px; font-size:11px; overflow-x:auto; border:1px solid #fca5a5;">${escapeHtml(error.message || 'Error desconocido')}</pre>
                    <p style="color:#7f1d1d; font-size:13px; margin-top:8px;">Tus datos de prospecto están a salvo en la base de datos.</p>
                </div>
                <div style="text-align:center; padding:20px 0;">
                    <a href="${retryUrl}" style="background-color:#1a3a6e; color:#ffffff; padding:14px 28px; text-decoration:none; border-radius:6px; font-weight:bold; display:inline-block; letter-spacing:1px; font-size:14px;">🔄 REINTENTAR PROCESAMIENTO</a>
                </div>
                <p style="color:#475569; font-size:13px; text-align:center;">Al hacer clic, el sistema volverá a intentarlo usando este ID.</p>
            `,
            safeName, safeEmail, safePhone, score: data.score, level: escapeHtml(data.level),
            isInternal: true,
            respuestas: data.answers 
        });

        const fallbackPayload = {
            From: process.env.POSTMARK_FROM_EMAIL,
            To: process.env.POSTMARK_INTERNAL_EMAIL,
            ReplyTo: safeEmail,
            MessageStream: "outbound",
            Subject: `⚠️ ERROR IA - Lead Rescatado: ${safeName}`,
            HtmlBody: fallbackHtml
        };

        await fetch("https://api.postmarkapp.com/email", {
            method: 'POST',
            headers: { "Accept": "application/json", "Content-Type": "application/json", "X-Postmark-Server-Token": process.env.POSTMARK_TOKEN },
            body: JSON.stringify(fallbackPayload)
        });
        console.log("Correo de rescate enviado con éxito.");
    } catch (fallbackErr) {
        console.error("Fallo crítico: No se pudo enviar el correo de rescate.", fallbackErr);
    }
  }
}

// Inicialización de Firebase
if (!admin.apps.length && process.env.FIREBASE_DATABASE_URL) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

// ==========================================
// FUNCIÓN PRINCIPAL DEL SERVIDOR (HANDLER)
// ==========================================
export default async function handler(req, res) {

  // ======================================================================
  // NUEVA RUTA 'GET': REINTENTO MANUAL (Webhook Seguro mediante Clic)
  // ======================================================================
  if (req.method === 'GET' && req.query.action === 'retry') {
      const clientToken = req.query.token || '';
      
      // La validación se hace contra la llave exclusiva del backend
      const serverToken = process.env.RETRY_SECRET || process.env.API_SECRET || '';

      // Validación criptográfica estricta
      if (clientToken.length !== serverToken.length || !crypto.timingSafeEqual(Buffer.from(clientToken), Buffer.from(serverToken))) {
          return res.status(401).send('<h1 style="color:red; text-align:center; margin-top:50px;">⛔ Acceso Denegado. Credencial inválida.</h1>');
      }

      const leadId = req.query.leadId;
      if (!leadId || typeof leadId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(leadId)) {
          return res.status(400).send('<h1 style="color:red; text-align:center; margin-top:50px;">❌ ID de lead inválido.</h1>');
      }

      try {
          const db = admin.database();
          const leadSnapshot = await db.ref(`respuestas_bcmex/${leadId}`).once('value');
          
          if (!leadSnapshot.exists()) {
              return res.status(404).send('<h1 style="color:red; text-align:center; margin-top:50px;">🔍 Lead no encontrado en la base de datos.</h1>');
          }

          const leadData = leadSnapshot.val();
          
          // Enviamos una respuesta HTML bonita e iniciamos el reprocesamiento (con await para garantizar envío)
          await procesarIAyCorreo(leadData, leadId, req.headers.host);

          return res.status(200).send(`
            <div style="font-family:sans-serif; text-align:center; margin-top:100px; color:#1a3a6e;">
              <h1 style="font-size:40px;">✅ ¡Reintento Procesado!</h1>
              <p style="font-size:18px; color:#475569;">El servidor ha intentado reprocesar el lead de <b>${escapeHtml(leadData.name)}</b>.</p>
              <p style="font-size:18px; color:#475569;">Por favor, cierra esta ventana y verifica si el correo llegó a tu bandeja.</p>
            </div>
          `);

      } catch (err) {
          console.error(err);
          return res.status(500).send('<h1 style="color:red; text-align:center; margin-top:50px;">💥 Ocurrió un error en el servidor al intentar reprocesar.</h1>');
      }
  }


  // ======================================================================
  // RUTA 'POST': FLUJO NORMAL (Protecciones de Seguridad Originales)
  // ======================================================================
  
  // Límite de tamaño de Payload
  const payloadString = req.body ? JSON.stringify(req.body) : '';
  if (Buffer.byteLength(payloadString, 'utf8') > 50000) {
    return res.status(413).json({ error: 'Payload Too Large' });
  }

  const origin = req.headers.origin;
  
  if (req.method === 'OPTIONS') {
    res.setHeader('Access-Control-Allow-Origin', (origin && ALLOWED_ORIGINS.includes(origin)) ? origin : ALLOWED_ORIGINS[0]);
    res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS, GET');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, version');
    return res.status(200).end();
  }

  // Se permite bloquear POSTs sin origin legítimo
  if (req.method !== 'GET') {
      if (!origin || !ALLOWED_ORIGINS.includes(origin)) {
        return res.status(403).json({ error: 'Acceso denegado. Origen no permitido.' });
      }
      res.setHeader('Access-Control-Allow-Origin', origin);
  }

  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  // Validación de Token para POST (Frontend)
  const clientToken = req.headers['version'] || '';
  const serverToken = process.env.API_SECRET || '';
  if (clientToken.length !== serverToken.length || !crypto.timingSafeEqual(Buffer.from(clientToken), Buffer.from(serverToken))) {
    return res.status(401).json({ error: 'No autorizado. Token inválido o ausente.' });
  }

  // Rate Limiting
  const clientIp = req.headers['x-vercel-forwarded-for'] || 'ip-desconocida';
  const currentTime = Date.now();

  if (ipCache.has(clientIp)) {
    const rateData = ipCache.get(clientIp);
    if (currentTime - rateData.startTime < RATE_LIMIT_WINDOW_MS) {
      if (rateData.count >= MAX_REQUESTS) return res.status(429).json({ error: 'Demasiadas solicitudes.' });
      rateData.count++;
    } else {
      ipCache.set(clientIp, { count: 1, startTime: currentTime });
    }
  } else {
    ipCache.set(clientIp, { count: 1, startTime: currentTime });
  }

  // Limpieza de caché
  if (ipCache.size > 1000) {
    for (const [key, val] of ipCache.entries()) {
      if (currentTime - val.startTime >= RATE_LIMIT_WINDOW_MS) ipCache.delete(key);
    }
    if (ipCache.size > 1000) {
      const oldest = [...ipCache.entries()].sort((a, b) => a[1].startTime - b[1].startTime);
      oldest.slice(0, 200).forEach(([k]) => ipCache.delete(k));
    }
  }

  if (!process.env.FIREBASE_DATABASE_URL) return res.status(500).json({ error: 'Error de configuración interna.' });

  try {
    const db = admin.database();
    const data = req.body;

    // FASE 1: CREAR LEAD
    if (data.action === 'create') {
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!data.email || typeof data.email !== 'string' || !emailRegex.test(data.email)) {
            return res.status(400).json({ error: 'Correo electrónico inválido' });
        }
        if (!data.name || typeof data.name !== 'string' || data.name.trim() === '') {
            return res.status(400).json({ error: 'Nombre inválido' });
        }

        const rawData = {
            name: data.name.trim().substring(0, 80),
            email: data.email.trim().toLowerCase().substring(0, 100),
            timestamp: admin.database.ServerValue.TIMESTAMP,
            source: 'Vercel-API-Secure',
            status: 'incompleto', 
            procesado: false
        };

        const newLeadRef = db.ref('respuestas_bcmex').push();
        await newLeadRef.set(rawData);

        return res.status(200).json({ success: true, leadId: newLeadRef.key });
    }

    // FASE 2: ACTUALIZAR Y PROCESAR
    else if (data.action === 'update') {
        if (!data.leadId || typeof data.leadId !== 'string' || !/^[a-zA-Z0-9_-]+$/.test(data.leadId)) {
            return res.status(400).json({ error: 'Falta ID de lead o es inválido' });
        }
        if (!data.phone || typeof data.phone !== 'string' || !/^\+[0-9]{10,15}$/.test(data.phone.trim())) {
            return res.status(400).json({ error: 'El teléfono es obligatorio y debe incluir código de país.' });
        }
        if (!VALID_LEVELS.includes(data.level)) {
            return res.status(400).json({ error: 'Nivel de riesgo inválido' });
        }

        const rawScore = typeof data.score === 'number' ? data.score : parseInt(data.score, 10);
        if (isNaN(rawScore) || rawScore < SCORE_MIN || rawScore > SCORE_MAX) {
            return res.status(400).json({ error: 'Puntaje inválido.' });
        }

        let rawAnswers = {};
        if (data.answers && typeof data.answers === 'object') {
            const keys = Object.keys(data.answers).slice(0, MAX_ANSWERS);
            for (const key of keys) {
                const answerLabel = data.answers[key]?.label || "Sin respuesta";
                const answerValue = data.answers[key]?.value || 0;
                rawAnswers[key] = {
                    value: typeof answerValue === 'number' ? answerValue : 0,
                    label: String(answerLabel).substring(0, MAX_LABEL_LENGTH)
                };
            }
        }

        const leadSnapshot = await db.ref(`respuestas_bcmex/${data.leadId}`).once('value');
        if (!leadSnapshot.exists()) return res.status(404).json({ error: 'Lead no encontrado' });
        
        const existingData = leadSnapshot.val();

        await db.ref(`respuestas_bcmex/${data.leadId}`).update({
            phone: data.phone.trim(),
            level: data.level,
            score: rawScore,
            answers: rawAnswers,
            status: 'completado'
        });

        const mergedData = {
            ...existingData,
            phone: data.phone.trim(),
            level: data.level,
            score: rawScore,
            answers: rawAnswers
        };

        // Pasamos req.headers.host para saber qué dominio usar en el botón de rescate
        await procesarIAyCorreo(mergedData, data.leadId, req.headers.host);

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
