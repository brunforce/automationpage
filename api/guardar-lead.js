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
    const model = genAI.getGenerativeModel({ model: "gemini-1.5-flash" });
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
    const payloadCliente = {
      From: process.env.POSTMARK_FROM_EMAIL,
      To: data.email,
      Subject: "Diagnóstico de Resiliencia BCP - Resultados BCMEX",
      HtmlBody: `<html><body style="font-family: Arial, sans-serif; color: #333; line-height: 1.6;">
          <p>${correoCliente.replace(/\n/g, '<br>')}</p>
          <br><p>Saludos cordiales,<br><b>El equipo de BCMEX</b><br><a href="https://bcmex.mx">www.bcmex.mx</a></p>
      </body></html>`
    };

    // Correo Interno — todos los campos del usuario van escapados
    const payloadInterno = {
      From: process.env.POSTMARK_FROM_EMAIL,
      To: process.env.POSTMARK_INTERNAL_EMAIL,
      Subject: `🔥 NUEVO LEAD BCP: ${safeName}`,
      HtmlBody: `<html><body style="font-family: Arial, sans-serif; color: #1a202c;">
          <h2 style="color: #2b6cb0;">Nuevo prospecto evaluado: ${safeName}</h2>
          <p><b>Email de contacto:</b> <a href="mailto:${safeEmail}">${safeEmail}</a></p>
          <p><b>Teléfono:</b> ${safePhone}</p>
          <hr style="border: 1px solid #e2e8f0; margin: 20px 0;">
          <div style="background-color: #f7fafc; padding: 15px; border-radius: 8px;">
              ${analisisInterno.replace(/\n/g, '<br>')}
          </div>
      </body></html>`
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
  console.log('HEADER VERSION:', req.headers['version']);
  console.log('ENV API_SECRET:', process.env.API_SECRET ? 'EXISTE' : 'NO EXISTE');
  console.log('ORIGIN:', req.headers.origin);

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
    if (rawPhone !== '' && !/^[0-9]{10}$/.test(rawPhone)) {
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
      phone:     rawPhone || 'No proporcionado',
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
