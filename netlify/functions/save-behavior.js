const { Client } = require('pg');

exports.handler = async (event) => {
  if (event.httpMethod !== "POST") return { statusCode: 405, body: "Method Not Allowed" };

  const data = JSON.parse(event.body);
  const client = new Client({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  try {
    await client.connect();
    const query = 'INSERT INTO behavior_logs (mouse_data, click_data, key_data, idle_data) VALUES ($1, $2, $3, $4)';
    await client.query(query, [data.mouse, data.click, data.key, data.idle]);
    await client.end();
    return { statusCode: 200, body: JSON.stringify({ message: "Success" }) };
  } catch (err) {
    return { statusCode: 500, body: JSON.stringify({ error: err.message }) };
  }
};