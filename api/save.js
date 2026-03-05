import pkg from 'pg';
const { Client } = pkg;

export default async function handler(req, res) {
    // 1. ตรวจสอบ Method
    if (req.method !== 'POST') {
        return res.status(405).json({ error: 'Method Not Allowed' });
    }

    // 2. ตั้งค่าการเชื่อมต่อฐานข้อมูล
    const client = new Client({
        connectionString: process.env.DATABASE_URL,
        ssl: { 
            rejectUnauthorized: false
        }
    });

    try {
        await client.connect();
        const data = req.body;

        // 3. เตรียม Query (ชื่อคอลัมน์ต้องตรงกับที่สร้างใน SQL: mouse, click, key, idle, features)
        const query = `
            INSERT INTO behavior_logs (mouse, click, key, idle, features) 
            VALUES ($1, $2, $3, $4, $5)
        `;
        
        // 4. เตรียมข้อมูล (ดึงจาก JSON ที่ Frontend ส่งมา)
        // ใช้ JSON.stringify เพื่อความชัวร์ว่าข้อมูลเข้าคอลัมน์ JSONB ได้ 100%
        const values = [
            data.mouse || {},  
            data.click || {},  
            data.key || {},    
            data.idle || {},   
            data.features || {}
        ];

        // 5. บันทึกลง Database
        await client.query(query, values);
        
        // 6. ปิดการเชื่อมต่อและส่งผลลัพธ์
        await client.end();
        return res.status(200).json({ message: "Success" });

    } catch (err) {
        // กรณีเกิด Error ให้ปิด Client ก่อนส่ง Response
        if (client) {
            try { await client.end(); } catch (e) { console.error("Error closing client:", e); }
        }
        
        console.error("DB Error:", err.message);
        
        // ส่งรายละเอียด Error กลับไปให้ตรวจเช็คได้ง่ายขึ้น
        return res.status(500).json({ 
            error: "Database Error", 
            details: err.message 
        });
    }
}