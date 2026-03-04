import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method Not Allowed' });
  }

  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  try {
    const data = req.body;
    await client.connect();

    const query = `
      INSERT INTO behavior_logs (mouse_data, click_data, key_data, idle_data, features) 
      VALUES ($1, $2, $3, $4, $5)
    `;
    
    const values = [
      data.mouse_data || {},
      data.click_data || {},
      data.key_data || {},
      data.idle_data || {},
      data.features || {}
    ];

    await client.query(query, values);
    await client.end();

    return res.status(200).json({ message: "Success" });

  } catch (err) {
    if (client) {
      try { await client.end(); } catch (e) {}
    }
    console.error("DB Error:", err.message);
    return res.status(500).json({ error: err.message });
  }
}