const https = require('https');
const fs = require('fs');

const env = fs.readFileSync('.env.local', 'utf8');
const match = env.match(/GEMINI_API_KEY=(.+)/);

if (!match) {
  console.log('❌ No se encontró GEMINI_API_KEY en .env.local');
  console.log('Contenido del archivo:');
  console.log(env);
  process.exit(1);
}

const key = match[1].trim().replace(/^["']|["']$/g, ''); // quita comillas si las hay
console.log('✅ API Key encontrada:', key.substring(0, 8) + '...');

https.get('https://generativelanguage.googleapis.com/v1beta/models?key=' + key, r => {
  let d = '';
  r.on('data', c => d += c);
  r.on('end', () => {
    const parsed = JSON.parse(d);
    if (parsed.error) {
      console.log('❌ Error de API:', parsed.error.message);
      return;
    }
    const models = parsed.models || [];
    console.log(`\n=== ${models.length} modelos encontrados ===\n`);
    models
      .filter(m => m.supportedGenerationMethods?.includes('generateContent'))
      .forEach(m => console.log(m.name));
  });
});
