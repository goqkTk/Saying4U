const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
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

    db.run(`CREATE TABLE IF NOT EXISTS saying (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        author TEXT NOT NULL
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

const SECRET_KEY = 'superduperholymolylegendpublickey';

// 회원가입 API
app.post('/register', async (req, res) => {
    const { username, password, email } = req.body;

    if (!username || !password || !email) {
        return res.status(400).json({ message: '모든 필드를 입력해주세요.' });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        db.run(
            `INSERT INTO users (username, password, email) VALUES (?, ?, ?)`,
            [username, hashedPassword, email],
            (err) => {
                if (err) {
                    console.error('회원가입 실패:', err.message);
                    return res.status(500).json({ message: '회원가입 중 오류가 발생했습니다.' });
                }
                res.status(201).json({ message: '회원가입 성공!' });
            }
        );
    } catch (error) {
        console.error('회원가입 처리 실패:', error.message);
        res.status(500).json({ message: '회원가입 중 오류가 발생했습니다.' });
    }
});

// 로그인 API
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    if (!username || !password) {
        return res.status(400).json({ message: '아이디와 비밀번호를 입력해주세요.' });
    }

    db.get(
        `SELECT * FROM users WHERE username = ?`,
        [username],
        async (err, user) => {
            if (err) {
                console.error('로그인 실패:', err.message);
                return res.status(500).json({ message: '로그인 중 오류가 발생했습니다.' });
            }

            if (!user) {
                return res.status(404).json({ message: '사용자를 찾을 수 없습니다.' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                return res.status(401).json({ message: '비밀번호가 일치하지 않습니다.' });
            }

            const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
            res.status(200).json({ message: '로그인 성공!', token });
        }
    );
});

// 인증 미들웨어
function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: '토큰이 필요합니다.' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: '유효하지 않은 토큰입니다.' });
        req.user = user;
        next();
    });
}

// 보호된 API 예시
app.get('/protected', authenticateToken, (req, res) => {
    res.status(200).json({ message: `안녕하세요, ${req.user.username}님!` });
});