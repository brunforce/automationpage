const admin = require('firebase-admin');

const ipCache = new Map();
const RATE_LIMIT_WINDOW_MS = 120 * 1000; 
const MAX_REQUESTS = 1; 

const ALLOWED_ORIGINS = [
  'https://bcpscore.vercel.app' 
];

export default async function handler(req, res) {
  // --- INICIO SEGURIDAD: LÍMITE DE TAMAÑO (PAYLOAD BLOAT) ---
  // Vercel permite limitar el tamaño del body. Si el payload en formato string es mayor a 50KB, lo bloqueamos.
  const payloadString = JSON.stringify(req.body || {});
  if (Buffer.byteLength(payloadString, 'utf8') > 50000) {
    console.warn('[SEGURIDAD] Intento de inyección de payload gigante bloqueado.');
    return res.status(413).json({ error: 'Payload Too Large: El paquete de datos excede el límite permitido.' });
  }

  // --- INICIO DE SEGURIDAD CORS ---
  const origin = req.headers.origin;

  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    console.warn(`[CORS] Intento bloqueado desde: ${origin}`);
    return res.status(403).json({ error: 'Acceso denegado' });
  }

  res.setHeader('Access-Control-Allow-Origin', origin || ALLOWED_ORIGINS[0]);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  // --- INICIO DE SISTEMA ANTI-SPAM ---
  const rawForwarded = req.headers['x-forwarded-for'] || '';
  const clientIp = req.headers['x-real-ip'] || rawForwarded.split(',')[0].trim() || req.socket.remoteAddress || 'ip-desconocida';
  const currentTime = Date.now();

  if (ipCache.has(clientIp)) {
    const rateData = ipCache.get(clientIp);
    if (currentTime - rateData.startTime < RATE_LIMIT_WINDOW_MS) {
      if (rateData.count >= MAX_REQUESTS) {
        return res.status(429).json({ error: 'Demasiadas solicitudes. Por favor, espera unos minutos.' });
      }
      rateData.count++;
    } else {
      ipCache.set(clientIp, { count: 1, startTime: currentTime });
    }
  } else {
    ipCache.set(clientIp, { count: 1, startTime: currentTime });
  }

  if (ipCache.size > 1000) {
    ipCache.clear();
  }

  // --- VALIDACIONES ESTRICTAS DE ENTORNO ---
  const dbUrl = process.env.FIREBASE_DATABASE_URL;
  if (!dbUrl || !dbUrl.startsWith('http')) {
    return res.status(500).json({ error: 'Database URL inválida' });
  }

  if (!process.env.FIREBASE_PRIVATE_KEY) {
    return res.status(500).json({ error: 'Falta Private Key' });
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

    // --- INICIO SEGURIDAD: SANITIZACIÓN DE DATOS (DATA VALIDATION) ---
    // Si un bot envía datos por Postman ignorando el HTML, validamos que no mande basura.
    if (!data.email || typeof data.email !== 'string' || !data.email.includes('@') || data.email.length > 100) {
      return res.status(400).json({ error: 'Correo electrónico inválido o demasiado largo' });
    }
    if (!data.name || typeof data.name !== 'string' || data.name.trim() === '' || data.name.length > 80) {
      return res.status(400).json({ error: 'Nombre inválido o demasiado largo' });
    }
    
    // Validamos que el score sea numérico y tenga sentido (ej. de 0 a 100) para evitar inyecciones.
    const cleanScore = typeof data.score === 'number' ? data.score : parseInt(data.score, 10);
    if (isNaN(cleanScore) || cleanScore < 0 || cleanScore > 500) {
      return res.status(400).json({ error: 'El puntaje (score) proporcionado no es válido' });
    }

    // Limpiamos los strings básicos para evitar scripts largos
    const cleanData = {
      name: data.name.trim().substring(0, 80),
      email: data.email.trim().toLowerCase().substring(0, 100),
      phone: typeof data.phone === 'string' ? data.phone.trim().substring(0, 20) : "No proporcionado",
      level: typeof data.level === 'string' ? data.level.substring(0, 50) : "Desconocido",
      score: cleanScore,
      answers: typeof data.answers === 'object' ? data.answers : {}, // Aceptamos objeto de respuestas
      timestamp: admin.database.ServerValue.TIMESTAMP,
      source: 'Vercel-API-Secure'
    };

    // 6. Guardado seguro
    const newLeadRef = db.ref('respuestas_bcmex').push();
    await newLeadRef.set(cleanData);

    return res.status(200).json({ success: true, message: 'Lead guardado con éxito' });
    
  } catch (error) {
    console.error('Error interno de Firebase Admin:', error);
    return res.status(500).json({ error: 'Error interno al procesar la solicitud' });
  }
}
