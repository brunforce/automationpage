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

const VALID_LEVELS = ['Crítico', 'En Desarrollo', 'Madurez Alta']; // Ajusta a tus valores reales
const MAX_ANSWERS = 30;       // Máximo de preguntas esperadas en el formulario
const MAX_LABEL_LENGTH = 300; // Máximo de caracteres por respuesta
const SCORE_MIN = 0;
const SCORE_MAX = 50;

// ==========================================
// HELPERS DE SEGURIDAD
// ==========================================

/**
 * Escapa caracteres HTML peligrosos para evitar XSS en los correos.
 * Se aplica a cualquier dato del usuario que se inserte en HTML.
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;');
}

/**
 * Sanitiza texto plano para insertarlo en un prompt de IA.
 * Elimina caracteres que permiten inyectar instrucciones (prompt injection).
 * Conserva letras, números, espacios y puntuación básica.
 */
function sanitizeForPrompt(str, maxLength = 200) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/[\[\]{}<>]/g, '')   // Elimina corchetes y angulares usados en injection
    .replace(/ignore|olvida|system|instrucción|instruction|jailbreak/gi, '') // Palabras clave de injection
    .trim()
    .substring(0, maxLength);
}

/**
 * Valida formato básico de email con regex más estricto que solo includes('@').
 */
function isValidEmail(email) {
  const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
  return emailRegex.test(email) && email.length <= 100;
}

/**
 * Valida y sanitiza el objeto answers. Aplica límites estrictos de estructura.
 */
function sanitizeAnswers(rawAnswers) {
  if (typeof rawAnswers !== 'object' || Array.isArray(rawAnswers) || rawAnswers === null) {
    return {};
  }

  const keys = Object.keys(rawAnswers);

  // Limitar número de respuestas
  if (keys.length > MAX_ANSWERS) {
    throw new Error(`Número de respuestas excede el límite permitido (${MAX_ANSWERS})`);
  }

  const clean = {};
  for (const key of keys) {
    // Validar que la key sea alfanumérica con guión bajo (ej: q1_pregunta)
    if (!/^[a-zA-Z0-9_]{1,50}$/.test(key)) continue;

    const answerObj = rawAnswers[key];

    // Solo aceptar objetos con value y label, sin anidamiento profundo
    if (typeof answerObj !== 'object' || Array.isArray(answerObj) || answerObj === null) continue;

    const value = answerObj.value;
    const label = answerObj.label;

    if (typeof label !== 'string' || label.length > MAX_LABEL_LENGTH) continue;
    if (typeof value !== 'string' && typeof value !== 'number') continue;

    clean[key] = {
      value: typeof value === 'number' ? value : String(value).substring(0, 50),
      label: label.trim().substring(0, MAX_LABEL_LENGTH)
    };
  }

  return clean;
}

// ==========================================
// FUNCIÓN AUXILIAR: PROCESAMIENTO IA Y POSTMARK
// ==========================================
async function procesarIAyCorreo(data, dbKey) {
  try {
    console.log(`[Procesador] Iniciando análisis IA para: ${data.name}`);

    // 1. Leer el archivo prompt.txt
    const promptPath = path.join(process.cwd(), 'api', 'prompt.txt');
    if (!fs.existsSync(promptPath)) {
      throw new Error("No se encontró el archivo prompt.txt en la carpeta api/");
    }
    let promptText = fs.readFileSync(promptPath, 'utf8');

    // 2. Reemplazar variables en el prompt con valores sanitizados (anti prompt injection)
    promptText = promptText.replace(/{{Nombre del Cliente}}/g, sanitizeForPrompt(data.name, 80));
    promptText = promptText.replace(/{{Puntaje}}/g, String(data.score));
    promptText = promptText.replace(/{{Nivel de Riesgo}}/g, sanitizeForPrompt(data.level, 50));

    const respuestas = data.answers || {};
    for (const [key, answerObj] of Object.entries(respuestas)) {
      const shortId = key.split('_')[0].toUpperCase();
      // sanitizeForPrompt también aplicado al label de cada respuesta
      const label = typeof answerObj === 'object'
        ? sanitizeForPrompt(answerObj.label, MAX_LABEL_LENGTH)
        : sanitizeForPrompt(String(answerObj), MAX_LABEL_LENGTH);
      const regex = new RegExp(`{{Respuesta ${shortId}}}`, 'g');
      promptText = promptText.replace(regex, label);
    }

    // 3. Consultar a Gemini
    const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
    const model = genAI.getGenerativeModel({ model: "gemini-2.5-flash" });
    const result = await model.generateContent(promptText);
    const textoCrudo = result.response.text();

    // 4. Extraer los bloques usando Regex
    const matchEmail = textoCrudo.match(/\[EMAIL_CLIENTE_START\]([\s\S]*?)\[EMAIL_CLIENTE_END\]/i);
    const matchInterno = textoCrudo.match(/\[ANALISIS_INTERNO_START\]([\s\S]*?)\[ANALISIS_INTERNO_END\]/i);

    if (!matchEmail || !matchInterno) {
      throw new Error("Gemini no devolvió las etiquetas correctamente.");
    }

    // El contenido de Gemini va directo al HTML del correo: sanitizar contra XSS
    // Nota: correoCliente proviene de Gemini (confiable), pero sanitizamos por si
    // el modelo repitió verbatim datos del usuario con HTML malicioso.
    const correoCliente = escapeHtml(matchEmail[1].trim());
    const analisisInterno = escapeHtml(matchInterno[1].trim());

    // 5. Enviar por Postmark — datos del usuario escapados antes de insertar en HTML
    const postmarkUrl = "https://api.postmarkapp.com/email";
    const headers = {
      "Accept": "application/json",
      "Content-Type": "application/json",
      "X-Postmark-Server-Token": process.env.POSTMARK_TOKEN
    };

    const safeName  = escapeHtml(data.name);
    const safeEmail = escapeHtml(data.email);
    const safePhone = escapeHtml(data.phone);

    // Correo Cliente
    const htmlCliente = `<!DOCTYPE html>
<html lang="es">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
</head>
<body style="margin:0;padding:0;background-color:#0d1117;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background-color:#0d1117;padding:48px 0;">
<tr><td align="center">
<table width="620" cellpadding="0" cellspacing="0" style="max-width:620px;width:100%;">
  <tr>
    <td style="background:linear-gradient(90deg,#1d4ed8,#0ea5e9,#6366f1);height:4px;border-radius:4px 4px 0 0;font-size:0;line-height:0;">&nbsp;</td>
  </tr>
  <tr>
    <td style="background:linear-gradient(160deg,#0f172a 0%,#1e2d4a 60%,#162040 100%);padding:52px 52px 40px;text-align:center;">
      <img src="https://bcpscore.vercel.app/logo1.png" alt="BCMEX" style="height:56px;width:auto;display:block;margin:0 auto 28px;">
      <div style="display:inline-block;background:rgba(30,64,175,0.35);border:1px solid rgba(96,165,250,0.25);border-radius:20px;padding:5px 18px;margin-bottom:20px;">
        <span style="font-size:10px;color:#93c5fd;letter-spacing:3px;text-transform:uppercase;font-weight:600;">Informe Confidencial</span>
      </div>
      <h1 style="margin:0 0 10px;font-size:28px;font-weight:300;color:#f0f6ff;letter-spacing:0.5px;line-height:1.3;">
        Diagn&#243;stico de<br><strong style="font-weight:700;">Resiliencia Empresarial</strong>
      </h1>
      <p style="margin:0;font-size:12px;color:rgba(148,163,184,0.7);letter-spacing:2.5px;text-transform:uppercase;">Plan de Continuidad de Negocio</p>
      <div style="margin:28px auto 0;width:80px;height:1px;background:linear-gradient(90deg,transparent,rgba(96,165,250,0.6),transparent);"></div>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:36px 52px 24px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;">
      <p style="margin:0 0 6px;font-size:13px;color:#64748b;letter-spacing:2px;text-transform:uppercase;">Preparado para</p>
      <p style="margin:0 0 20px;font-size:22px;font-weight:600;color:#e2e8f0;">${safeName}</p>
      <p style="margin:0;font-size:14px;color:#94a3b8;line-height:1.85;">
        Hemos concluido el an&#225;lisis de resiliencia de su organizaci&#243;n.
        A continuaci&#243;n encontrar&#225; los resultados detallados y las recomendaciones
        de nuestro equipo especializado en continuidad de negocio.
      </p>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:8px 52px 20px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;text-align:center;">
      <div style="height:1px;width:70px;background:linear-gradient(90deg,transparent,#334155);display:inline-block;vertical-align:middle;"></div>
      <span style="font-size:9px;letter-spacing:4px;text-transform:uppercase;color:#475569;padding:0 12px;vertical-align:middle;">&#9670;&nbsp; Resultados del An&#225;lisis &nbsp;&#9670;</span>
      <div style="height:1px;width:70px;background:linear-gradient(90deg,#334155,transparent);display:inline-block;vertical-align:middle;"></div>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:0 52px 36px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;">
      <div style="background:#0f172a;border:1px solid #1e3a5f;border-left:4px solid #3b82f6;border-radius:0 12px 12px 0;padding:28px 30px;">
        <p style="margin:0 0 16px;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#3b82f6;font-weight:600;">&#128203; An&#225;lisis de Resultados</p>
        <p style="margin:0;font-size:14px;color:#cbd5e1;line-height:2;white-space:pre-line;">${correoCliente.replace(/\n/g, '<br>')}</p>
      </div>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:0 52px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;">
      <div style="height:1px;background:linear-gradient(90deg,transparent,#1e3a5f,transparent);"></div>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:32px 52px 44px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="background:linear-gradient(135deg,#0f2044,#162952);border:1px solid #1e3f7a;border-radius:14px;padding:28px 32px;text-align:center;">
            <p style="margin:0 0 6px;font-size:16px;font-weight:600;color:#e2e8f0;">&#191;Listo para el siguiente paso?</p>
            <p style="margin:0 0 22px;font-size:13px;color:#64748b;line-height:1.7;">Nuestro equipo de especialistas est&#225; disponible para<br>acompa&#241;arle en cada etapa del proceso.</p>
            <a href="https://bcmex.mx" style="display:inline-block;background:linear-gradient(135deg,#1d4ed8,#2563eb);color:#ffffff;text-decoration:none;font-size:12px;font-weight:700;letter-spacing:2px;text-transform:uppercase;padding:14px 40px;border-radius:30px;">
              Visitar BCMEX.mx &nbsp;&#8594;
            </a>
          </td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td style="background:#0a0f1a;border-top:1px solid #1e293b;border-left:1px solid #1e293b;border-right:1px solid #1e293b;padding:30px 52px;text-align:center;">
      <p style="margin:0 0 4px;font-size:15px;color:#e2e8f0;letter-spacing:4px;font-weight:300;">BCMEX</p>
      <p style="margin:0 0 16px;font-size:10px;color:#334155;letter-spacing:1.5px;text-transform:uppercase;">Resiliencia Empresarial &nbsp;&#183;&nbsp; Continuidad de Negocio</p>
      <div style="height:1px;background:#1e293b;margin:0 auto 16px;width:40px;"></div>
      <p style="margin:0;font-size:11px;color:#334155;line-height:1.8;">
        Este correo es confidencial y est&#225; dirigido exclusivamente a su destinatario.<br>
        <a href="https://bcmex.mx" style="color:#475569;text-decoration:none;">www.bcmex.mx</a>
      </p>
    </td>
  </tr>
  <tr>
    <td style="background:linear-gradient(90deg,#6366f1,#0ea5e9,#1d4ed8);height:3px;border-radius:0 0 4px 4px;font-size:0;line-height:0;">&nbsp;</td>
  </tr>
  <tr><td style="height:40px;"></td></tr>
</table>
</td></tr>
</table>
</body>
</html>`;

    const payloadCliente = {
      From: process.env.POSTMARK_FROM_EMAIL,
      To: data.email,
      Subject: "Diagnóstico de Resiliencia BCP - Resultados BCMEX",
      HtmlBody: htmlCliente
    };

    // Correo Interno — todos los campos del usuario van escapados
    const htmlInterno = `<!DOCTYPE html>
<html lang="es">
<head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#0d1117;font-family:'Helvetica Neue',Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#0d1117;padding:30px 0;">
<tr><td align="center">
<table width="600" cellpadding="0" cellspacing="0" style="max-width:600px;width:100%;">
  <tr>
    <td style="background:linear-gradient(90deg,#f59e0b,#ef4444);height:3px;border-radius:3px 3px 0 0;font-size:0;line-height:0;">&nbsp;</td>
  </tr>
  <tr>
    <td style="background:linear-gradient(135deg,#1a1a2e,#16213e);padding:28px 36px;text-align:center;">
      <p style="margin:0 0 6px;font-size:10px;letter-spacing:4px;color:rgba(251,191,36,0.8);text-transform:uppercase;">&#128293; Nuevo Lead Detectado</p>
      <h2 style="margin:0 0 6px;font-size:20px;font-weight:600;color:#f0f6ff;">${safeName}</h2>
      <p style="margin:0;font-size:12px;color:rgba(147,197,253,0.6);">${safeEmail}</p>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:24px 36px 8px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;">
      <table width="100%" cellpadding="0" cellspacing="0">
        <tr>
          <td style="padding:8px 12px;background:#0f172a;border-radius:8px;border:1px solid #1e293b;">
            <span style="font-size:11px;color:#64748b;">Tel&#233;fono</span><br>
            <span style="font-size:13px;color:#e2e8f0;font-weight:500;">${safePhone}</span>
          </td>
        </tr>
      </table>
    </td>
  </tr>
  <tr>
    <td style="background:#111827;padding:16px 36px 32px;border-left:1px solid #1e293b;border-right:1px solid #1e293b;">
      <p style="margin:0 0 12px;font-size:10px;letter-spacing:3px;text-transform:uppercase;color:#f59e0b;font-weight:600;">&#128202; An&#225;lisis Interno · Equipo BCMEX</p>
      <div style="background:#0f172a;border-left:4px solid #f59e0b;border-radius:0 8px 8px 0;padding:20px 22px;">
        <p style="margin:0;font-size:13px;color:#cbd5e1;line-height:1.85;white-space:pre-line;">${analisisInterno.replace(/\n/g, '<br>')}</p>
      </div>
    </td>
  </tr>
  <tr>
    <td style="background:#0a0f1a;border-top:1px solid #1e293b;border-left:1px solid #1e293b;border-right:1px solid #1e293b;border-radius:0 0 4px 4px;padding:16px 36px;text-align:center;">
      <p style="margin:0;font-size:11px;color:#334155;">Notificaci&#243;n interna BCMEX &nbsp;&#183;&nbsp; No responder a este correo</p>
    </td>
  </tr>
  <tr>
    <td style="background:linear-gradient(90deg,#ef4444,#f59e0b);height:3px;border-radius:0 0 3px 3px;font-size:0;line-height:0;">&nbsp;</td>
  </tr>
</table>
</td></tr>
</table>
</body>
</html>`;
      From: process.env.POSTMARK_FROM_EMAIL,
      To: process.env.POSTMARK_INTERNAL_EMAIL,
      Subject: `🔥 NUEVO LEAD BCP: ${safeName}`,
      HtmlBody: htmlInterno
    };

    console.log(`[Postmark] Enviando correos...`);
    await fetch(postmarkUrl, { method: 'POST', headers, body: JSON.stringify(payloadCliente) });
    await fetch(postmarkUrl, { method: 'POST', headers, body: JSON.stringify(payloadInterno) });

    // 6. Actualizar Firebase marcando como procesado
    const db = admin.database();
    await db.ref(`respuestas_bcmex/${dbKey}`).update({ procesado: true });
    console.log(`[Procesador] Lead ${dbKey} finalizado exitosamente.`);

  } catch (error) {
    console.error("[Procesador] Error en la IA o Postmark:", error);
    // Aunque falle el correo, no tumbamos la petición para no asustar al usuario.
  }
}

// ==========================================
// FUNCIÓN PRINCIPAL DEL SERVIDOR (HANDLER)
// ==========================================
export default async function handler(req, res) {


  // ------------------------------------------
  // 1. LÍMITE DE TAMAÑO DE PAYLOAD
  // ------------------------------------------
  const payloadString = JSON.stringify(req.body || {});
  if (Buffer.byteLength(payloadString, 'utf8') > 20000) { // Reducido de 50KB a 20KB
    return res.status(413).json({ error: 'Payload Too Large' });
  }

  // ------------------------------------------
  // 2. CORS — bloquear si no hay origin O si no está en la lista
  //    (antes pasaba si origin era undefined)
  // ------------------------------------------
  const origin = req.headers.origin;
  if (!origin || !ALLOWED_ORIGINS.includes(origin)) {
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, X-Api-Secret');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  // ------------------------------------------
  // 3. SECRET TOKEN — segunda capa de autenticación
  //    Tu frontend debe enviar este header en cada POST.
  //    Agrégalo en tus env vars de Vercel como API_SECRET.
  // ------------------------------------------
  const apiSecret = req.headers['version'];
  if (!apiSecret || apiSecret !== process.env.API_SECRET) {
    return res.status(403).json({ error: 'No autorizado' });
  }

  // ------------------------------------------
  // 4. RATE LIMIT POR EMAIL (no por IP — IP es spoofeable)
  //    Nota: este rate limit en memoria es de respaldo.
  //    Para producción real, migrar a Upstash Redis.
  //    Ver: https://upstash.com/docs/redis/sdks/ratelimit-ts/overview
  // ------------------------------------------
  const bodyForRateLimit = req.body || {};
  const emailKey = typeof bodyForRateLimit.email === 'string'
    ? bodyForRateLimit.email.toLowerCase().trim()
    : null;

  // Rate limit secundario por IP (con cabecera de Vercel, más confiable que x-forwarded-for del cliente)
  // x-vercel-forwarded-for es seteado por la infraestructura de Vercel, no por el cliente
  const clientIp = req.headers['x-vercel-forwarded-for'] || 'ip-desconocida';
  const currentTime = Date.now();

  // Función interna para evaluar y registrar en el caché
  function checkRateLimit(cacheKey) {
    if (!cacheKey) return false; // Sin clave, dejar pasar (se validará abajo)
    if (ipCache.has(cacheKey)) {
      const rateData = ipCache.get(cacheKey);
      if (currentTime - rateData.startTime < RATE_LIMIT_WINDOW_MS) {
        if (rateData.count >= MAX_REQUESTS) return true; // Bloqueado
        rateData.count++;
      } else {
        ipCache.set(cacheKey, { count: 1, startTime: currentTime });
      }
    } else {
      ipCache.set(cacheKey, { count: 1, startTime: currentTime });
    }
    return false;
  }

  if (checkRateLimit(clientIp) || checkRateLimit(emailKey)) {
    return res.status(429).json({ error: 'Demasiadas solicitudes. Intenta más tarde.' });
  }

  // Limpiar entradas expiradas en lugar de borrar todo el caché de golpe
  if (ipCache.size > 1000) {
    for (const [key, val] of ipCache.entries()) {
      if (currentTime - val.startTime >= RATE_LIMIT_WINDOW_MS) {
        ipCache.delete(key);
      }
    }
    // Si aún hay más de 1000 tras limpiar expirados, eliminar los más antiguos
    if (ipCache.size > 1000) {
      const oldest = [...ipCache.entries()].sort((a, b) => a[1].startTime - b[1].startTime);
      oldest.slice(0, 200).forEach(([k]) => ipCache.delete(k));
    }
  }

  // ------------------------------------------
  // 5. VERIFICAR ENV VARS CRÍTICAS
  // ------------------------------------------
  const dbUrl = process.env.FIREBASE_DATABASE_URL;
  if (
    !dbUrl ||
    !process.env.FIREBASE_PRIVATE_KEY ||
    !process.env.GEMINI_API_KEY ||
    !process.env.POSTMARK_TOKEN ||
    !process.env.API_SECRET
  ) {
    console.error('[Config] Faltan variables de entorno críticas');
    return res.status(500).json({ error: 'Configuración de servidor incompleta' });
  }

  try {
    // ------------------------------------------
    // 6. INICIALIZAR FIREBASE (una sola vez)
    // ------------------------------------------
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


    // ------------------------------------------
    // 7. VALIDACIONES DE CAMPOS
    // ------------------------------------------

    // Email
    if (!data.email || !isValidEmail(data.email)) {
      return res.status(400).json({ error: 'Correo electrónico inválido' });
    }

    // Nombre
    if (!data.name || typeof data.name !== 'string' || data.name.trim() === '' || data.name.length > 80) {
      return res.status(400).json({ error: 'Nombre inválido' });
    }

    // Score — validación de rango estricta
    const cleanScore = typeof data.score === 'number' ? data.score : parseInt(data.score, 10);
    if (isNaN(cleanScore) || cleanScore < SCORE_MIN || cleanScore > SCORE_MAX) {
      return res.status(400).json({ error: `Score debe estar entre ${SCORE_MIN} y ${SCORE_MAX}` });
    }

    // Level — solo valores del enum permitido
    if (!data.level || !VALID_LEVELS.includes(data.level)) {
      return res.status(400).json({ error: 'Nivel de riesgo inválido' });
    }

    // Phone — vacío o exactamente 10 dígitos
    const rawPhone = typeof data.phone === 'string' ? data.phone.trim() : '';
    const phoneToSave = (rawPhone === '' || rawPhone === 'No proporcionado') 
      ? 'No proporcionado' 
      : rawPhone;
    
    if (phoneToSave !== 'No proporcionado' && !/^[0-9]{10}$/.test(phoneToSave)) {
      return res.status(400).json({ error: 'Teléfono inválido' });
    }

    // Answers — validación y sanitización profunda
    let cleanAnswers;
    try {
      cleanAnswers = sanitizeAnswers(data.answers);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }

    // ------------------------------------------
    // 8. CONSTRUIR OBJETO LIMPIO PARA FIREBASE
    // ------------------------------------------
    const cleanData = {
      name:      data.name.trim().substring(0, 80),
      email:     data.email.trim().toLowerCase().substring(0, 100),
      phone:     phoneToSave,
      level:     data.level,
      score:     cleanScore,
      answers:   cleanAnswers,
      timestamp: admin.database.ServerValue.TIMESTAMP,
      source:    'Vercel-API-Secure',
      procesado: false
    };

    // ------------------------------------------
    // 9. GUARDAR EN FIREBASE
    // ------------------------------------------
    const newLeadRef = db.ref('respuestas_bcmex').push();
    const pushId = newLeadRef.key;
    await newLeadRef.set(cleanData);

    // ------------------------------------------
    // 10. PROCESAR IA Y ENVIAR CORREOS
    // ------------------------------------------
    await procesarIAyCorreo(cleanData, pushId);

    // ------------------------------------------
    // 11. RESPONDER ÉXITO AL CLIENTE
    // ------------------------------------------
    return res.status(200).json({ success: true, message: 'Lead guardado y procesado con éxito' });

  } catch (error) {
    console.error('Error interno de servidor:', error);
    return res.status(500).json({ error: 'Error interno al procesar la solicitud' });
  }
}

// ==========================================
// RATE LIMIT CACHE (módulo-level, respaldo en memoria)
// IMPORTANTE: En serverless esto se reinicia entre instancias frías.
// Para mayor robustez, migrar a Upstash Redis:
// https://upstash.com/docs/redis/sdks/ratelimit-ts/overview
// ==========================================
const ipCache = new Map();
const RATE_LIMIT_WINDOW_MS = 120 * 1000;
const MAX_REQUESTS = 1;
