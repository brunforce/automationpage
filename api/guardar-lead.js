const admin = require('firebase-admin');

// Memoria temporal para guardar las IPs y evitar el Spam (Rate Limiting)
const ipCache = new Map();
const RATE_LIMIT_WINDOW_MS = 120 * 1000; // 2 minutos
const MAX_REQUESTS = 1; // Máximo 1 petición cada 2 minutos

// --- LISTA BLANCA DE CORS ---
// IMPORTANTE: Debes reemplazar esta URL con el enlace real de tu aplicación en Vercel
const ALLOWED_ORIGINS = [
  'https://bcpscore.vercel.app' 
];

export default async function handler(req, res) {
  // --- INICIO DE SEGURIDAD CORS ---
  const origin = req.headers.origin;

  // Si la petición viene de un navegador (tiene origen) y no está en tu lista blanca: ¡Bloquear!
  if (origin && !ALLOWED_ORIGINS.includes(origin)) {
    console.warn(`[CORS] Ataque o intento de acceso bloqueado desde dominio no autorizado: ${origin}`);
    return res.status(403).json({ error: 'Acceso denegado por políticas de CORS' });
  }

  // Si está autorizado, le enviamos los permisos correctos
  res.setHeader('Access-Control-Allow-Origin', origin || ALLOWED_ORIGINS[0]);
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  // El navegador siempre hace una petición "preflight" (OPTIONS) para comprobar seguridad antes del POST
  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }
  // --- FIN DE SEGURIDAD CORS ---

  // 1. Solo permitimos peticiones POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  // --- INICIO DE SISTEMA ANTI-SPAM ---
  // Obtenemos la IP del usuario (Vercel la inyecta en este header)
  const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'ip-desconocida';
  const currentTime = Date.now();

  if (ipCache.has(clientIp)) {
    const rateData = ipCache.get(clientIp);
    
    // Si estamos dentro de la ventana de 1 minuto
    if (currentTime - rateData.startTime < RATE_LIMIT_WINDOW_MS) {
      if (rateData.count >= MAX_REQUESTS) {
        console.warn(`[ANTI-SPAM] IP Bloqueada temporalmente: ${clientIp}`);
        return res.status(429).json({ error: 'Demasiadas solicitudes. Por favor, espera un minuto.' });
      }
      rateData.count++;
    } else {
      // Pasó el minuto, reseteamos su contador
      ipCache.set(clientIp, { count: 1, startTime: currentTime });
    }
  } else {
    // Es la primera vez que esta IP hace una petición
    ipCache.set(clientIp, { count: 1, startTime: currentTime });
  }

  // Limpieza de memoria (para evitar que el Map crezca al infinito si hay un ataque)
  if (ipCache.size > 1000) {
    ipCache.clear();
  }
  // --- FIN DE SISTEMA ANTI-SPAM ---

  // 2. Validaciones estrictas de Variables de Entorno
  const dbUrl = process.env.FIREBASE_DATABASE_URL;
  if (!dbUrl || !dbUrl.startsWith('http')) {
    console.error('CRÍTICO: FIREBASE_DATABASE_URL es incorrecta o no es un enlace válido:', dbUrl);
    return res.status(500).json({ error: 'Error de configuración en servidor: Database URL inválida' });
  }

  if (!process.env.FIREBASE_PRIVATE_KEY) {
    console.error('CRÍTICO: FIREBASE_PRIVATE_KEY está vacía o no existe.');
    return res.status(500).json({ error: 'Error de configuración en servidor: Falta Private Key' });
  }

  try {
    // 3. Inicialización segura de Firebase Admin
    if (!admin.apps.length) {
      admin.initializeApp({
        credential: admin.credential.cert({
          projectId: process.env.FIREBASE_PROJECT_ID,
          clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
          // Manejo seguro de saltos de línea en la llave privada
          privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
        }),
        databaseURL: dbUrl
      });
    }

    // 4. Conexión a la base de datos
    const db = admin.database();
    const data = req.body;

    // 5. Validación de los datos (Previene que manden basura vacía)
    if (!data.email || typeof data.email !== 'string' || !data.email.includes('@')) {
      return res.status(400).json({ error: 'Correo electrónico inválido' });
    }
    if (!data.name || data.name.trim() === '') {
      return res.status(400).json({ error: 'El nombre es obligatorio' });
    }

    // 6. Guardado seguro en Realtime Database
    const newLeadRef = db.ref('respuestas_bcmex').push();
    
    await newLeadRef.set({
      ...data,
      timestamp: admin.database.ServerValue.TIMESTAMP,
      source: 'Vercel-API-Secure'
    });

    return res.status(200).json({ success: true, message: 'Lead guardado con éxito' });
    
  } catch (error) {
    console.error('Error interno de Firebase Admin:', error);
    return res.status(500).json({ error: 'Error interno al procesar y guardar la solicitud' });
  }
}
