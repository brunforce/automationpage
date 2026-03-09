const admin = require('firebase-admin');

// Inicialización segura de Firebase Admin
if (!admin.apps.length) {
  admin.initializeApp({
    credential: admin.credential.cert({
      projectId: process.env.FIREBASE_PROJECT_ID,
      clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
      // Manejo de saltos de línea en la llave privada
      privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n'),
    }),
    databaseURL: process.env.FIREBASE_DATABASE_URL
  });
}

const db = admin.database();

export default async function handler(req, res) {
  // Solo permitimos peticiones POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método no permitido' });
  }

  try {
    const data = req.body;

    // Validación básica en servidor
    if (!data.email || !data.name) {
      return res.status(400).json({ error: 'Faltan campos obligatorios' });
    }

    // Referencia a la colección en Realtime Database
    const newLeadRef = db.ref('respuestas_bcmex').push();
    
    await newLeadRef.set({
      ...data,
      timestamp: admin.database.ServerValue.TIMESTAMP,
      source: 'Vercel-API-Secure'
    });

    return res.status(200).json({ success: true, message: 'Lead guardado con éxito' });
  } catch (error) {
    console.error('Error en el servidor:', error);
    return res.status(500).json({ error: 'Error interno al procesar la solicitud' });
  }
}
