const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sayings = require('./sayings');
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

    db.run(`CREATE TABLE IF NOT EXISTS user_saying (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        author TEXT NOT NULL
    )`);

    db.run(`CREATE TABLE IF NOT EXISTS saying (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        content TEXT NOT NULL,
        author TEXT NOT NULL
    )`);

    // 명언 데이터 삽입
    db.run(`DELETE FROM saying`); // 기존 데이터 삭제
    const stmt = db.prepare(`INSERT INTO saying (id, content, author) VALUES (?, ?, ?)`);
    sayings.forEach(({ id, content, author }) => {
        stmt.run(id, content, author);
    });
    stmt.finalize();
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

// 단일 명언 가져오기 API
app.get('/quote', (req, res) => {
    const exclude = req.query.exclude || ''; // 제외할 명언 내용
    db.get(
        `SELECT content, author FROM saying WHERE content != ? ORDER BY RANDOM() LIMIT 1`,
        [exclude],
        (err, row) => {
            if (err) {
                return res.status(500).json({ error: '명언을 불러오는 데 실패했습니다.' });
            }
            if (!row) {
                return res.status(404).json({ error: '명언이 없습니다.' });
            }
            res.status(200).json({ content: row.content, author: row.author }); // 명언 반환
        }
    );
});

// 내 명언 페이지
app.get('/quotes', (req, res) => {
    db.all(`SELECT content, author FROM saying ORDER BY RANDOM() LIMIT 5`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ error: '명언 리스트를 불러오는 데 실패했습니다.' });
        }
        if (!rows || rows.length === 0) {
            return res.status(404).json({ error: '명언이 없습니다.' });
        }
        res.status(200).json(rows); // 명언 리스트 반환
    });
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
                    return res.status(500).json({ message: '회원가입 중 오류가 발생했습니다.' });
                }
                res.status(201).json({ message: '회원가입 성공!' });
            }
        );
    } catch (error) {
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
                return res.status(500).json({ message: '로그인 중 오류가 발생했습니다.' });
            }

            if (!user) {
                // 상태 코드를 200으로 설정하고 메시지만 반환
                return res.status(200).json({ message: '사용자를 찾을 수 없습니다.' });
            }

            const isPasswordValid = await bcrypt.compare(password, user.password);
            if (!isPasswordValid) {
                // 상태 코드를 200으로 설정하고 메시지만 반환
                return res.status(200).json({ message: '비밀번호가 일치하지 않습니다.' });
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

// 모든 명언 가져오기 API
app.get('/all-quotes', (req, res) => {
    db.all(`SELECT content, author FROM user_saying`, [], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: '유저 명언 목록을 불러오는 데 실패했습니다.' });
        }
        res.status(200).json(rows); // 유저 명언 리스트 반환
    });
});

// 명언 추가 API
app.post('/add-quote', authenticateToken, (req, res) => {
    const { content } = req.body;
    const author = req.user.username; // 토큰에서 가져온 사용자 이름을 작성자로 설정

    if (!content) {
        return res.status(400).json({ message: '명언 내용을 입력해주세요.' });
    }

    db.run(
        `INSERT INTO user_saying (content, author) VALUES (?, ?)`,
        [content, author],
        (err) => {
            if (err) {
                return res.status(500).json({ message: '명언 추가 중 오류가 발생했습니다.' });
            }
            res.status(201).json({ message: '명언이 성공적으로 추가되었습니다.' });
        }
    );
});

// 내 명언 페이지 (HTML 파일 제공)
app.get('/my-quotes', (req, res) => {
    res.sendFile(path.join(__dirname, 'my-quotes.html'));
});

// 내 명언 가져오기 API
app.get('/api/my-quotes', authenticateToken, (req, res) => {
    const username = req.user.username;
    db.all(`SELECT id, content, author FROM user_saying WHERE author = ?`, [username], (err, rows) => {
        if (err) {
            return res.status(500).json({ message: '내 명언을 불러오는 데 실패했습니다.' });
        }
        res.status(200).json(rows);
    });
});

// 내 명언 수정 API
app.put('/my-quotes/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const { content } = req.body;
    const username = req.user.username;

    if (!content) {
        return res.status(400).json({ message: '명언 내용을 입력해주세요.' });
    }

    db.run(
        `UPDATE user_saying SET content = ? WHERE id = ? AND author = ?`,
        [content, id, username],
        function (err) {
            if (err) {
                return res.status(500).json({ message: '명언 수정 중 오류가 발생했습니다.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ message: '명언을 찾을 수 없습니다.' });
            }
            res.status(200).json({ message: '명언이 성공적으로 수정되었습니다.' });
        }
    );
});

// 내 명언 삭제 API
app.delete('/my-quotes/:id', authenticateToken, (req, res) => {
    const { id } = req.params;
    const username = req.user.username;

    db.run(
        `DELETE FROM user_saying WHERE id = ? AND author = ?`,
        [id, username],
        function (err) {
            if (err) {
                return res.status(500).json({ message: '명언 삭제 중 오류가 발생했습니다.' });
            }
            if (this.changes === 0) {
                return res.status(404).json({ message: '명언을 찾을 수 없습니다.' });
            }
            res.status(200).json({ message: '명언이 성공적으로 삭제되었습니다.' });
        }
    );
});