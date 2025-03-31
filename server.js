const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const axios = require('axios');
const app = express();
app.use(express.json());
const PORT = 4000;

app.listen(PORT, () => {
    console.log(`서버가 http://localhost:${PORT} 에서 실행 중입니다.`);
});

// SQLite3 데이터베이스 연결
const db = new sqlite3.Database('./database.db', sqlite3.OPEN_READWRITE | sqlite3.OPEN_CREATE, (err) => {
    if (err) {
        console.error("DB 연결 실패:", err.message);
    } else {
        console.log("DB 연결됨");
    }
});

db.serialize(() => {
    db.run(`CREATE TABLE IF NOT EXISTS users (
        username TEXT NOT NULL,
        password TEXT NOT NULL,
        email TEXT NOT NULL
    )`);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'main.html'));
});

app.get('/auth', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth.html'));
});

app.post('/logout', (req, res) => {
    res.status(200).json({ message: '로그아웃 성공' });
});

app.get('/quote', async (req, res) => {
    try {
        const response = await axios.get('https://zenquotes.io/api/random');
        res.json(response.data[0]); // 명언 데이터를 클라이언트로 전달
    } catch (error) {
        console.error('명언 API 요청 실패:', error.message);
        res.status(500).json({ error: '명언을 불러오는 데 실패했습니다.' });
    }
});