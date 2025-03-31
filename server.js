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

    // 명언 데이터 초기화
    const sayings = [
        {'id': 1, 'content': '시작이 반이다.', 'author': '아리스토텔레스'},
        {'id': 2, 'content': '천 마디 말보다 한 번의 행동이 더 가치 있다.', 'author': '공자'},
        {'id': 3, 'content': '고생 없이 얻을 수 있는 진정한 가치는 없다.', 'author': '괴테'},
        {'id': 4, 'content': '행복은 습관이다. 그것을 몸에 지녀라.', 'author': '허버트'},
        {'id': 5, 'content': '오늘 할 수 있는 일을 내일로 미루지 말라.', 'author': '벤자민 프랭클린'},
        {'id': 6, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 7, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 8, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 9, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 10, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 11, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 12, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 13, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 14, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 15, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 16, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 17, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 18, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 19, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 20, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 21, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 22, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 23, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 24, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 25, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 26, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 27, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 28, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 29, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 30, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 31, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 32, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 33, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 34, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 35, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 36, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 37, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 38, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 39, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 40, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 41, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 42, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 43, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 44, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 45, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 46, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 47, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 48, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 49, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 50, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 51, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 52, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 53, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 54, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 55, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 56, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 57, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 58, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 59, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 60, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 61, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 62, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 63, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 64, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 65, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 66, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 67, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 68, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 69, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 70, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 71, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 72, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 73, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 74, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 75, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 76, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 77, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 78, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 79, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 80, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 81, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 82, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 83, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 84, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 85, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 86, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 87, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 88, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 89, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 90, 'content': '너 자신을 믿어라.', 'author': '피카소'},
        {'id': 91, 'content': '사랑은 모든 것을 이긴다.', 'author': '베르길리우스'},
        {'id': 92, 'content': '지금이 바로 행동할 순간이다.', 'author': '가디너'},
        {'id': 93, 'content': '성공이란 넘어지는 횟수가 아니라 다시 일어서는 횟수다.', 'author': '빈스 롬바르디'},
        {'id': 94, 'content': '위대한 꿈을 꾸는 자만이 위대한 사람이 될 수 있다.', 'author': '네이팜 힐'},
        {'id': 95, 'content': '기회는 스스로 만드는 것이다.', 'author': '크리스 가드너'},
        {'id': 96, 'content': '위대한 목표 없이 위대한 결과는 없다.', 'author': '에머슨'},
        {'id': 97, 'content': '사람은 자기가 생각하는 대로 된다.', 'author': '마르쿠스 아우렐리우스'},
        {'id': 98, 'content': '위대한 사람은 기회를 기다리지 않는다.', 'author': '나폴레옹'},
        {'id': 99, 'content': '실패는 곧 배움이다.', 'author': '헨리 포드'},
        {'id': 100, 'content': '너 자신을 믿어라.', 'author': '피카소'}
    ];

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
    db.get(`SELECT content, author FROM saying ORDER BY RANDOM() LIMIT 1`, [], (err, row) => {
        if (err) {
            console.error('명언 조회 실패:', err.message);
            return res.status(500).json({ error: '명언을 불러오는 데 실패했습니다.' });
        }
        if (!row) {
            return res.status(404).json({ error: '명언이 없습니다.' });
        }
        res.status(200).json({ content: row.content, author: row.author }); // 명언 반환
    });
});

// 다수의 명언 가져오기 API
app.get('/quotes', (req, res) => {
    db.all(`SELECT content, author FROM saying ORDER BY RANDOM() LIMIT 5`, [], (err, rows) => {
        if (err) {
            console.error('명언 리스트 조회 실패:', err.message);
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

// 모든 명언 가져오기 API
app.get('/all-quotes', (req, res) => {
    db.all(`SELECT content, author FROM user_saying`, [], (err, rows) => {
        if (err) {
            console.error('유저 명언 목록 조회 실패:', err.message);
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
                console.error('명언 추가 실패:', err.message);
                return res.status(500).json({ message: '명언 추가 중 오류가 발생했습니다.' });
            }
            res.status(201).json({ message: '명언이 성공적으로 추가되었습니다.' });
        }
    );
});