const express = require('express');
const multer = require('multer');
const csv = require('csv-parser');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { Pool } = require('pg');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Railway 프록시 설정
app.set('trust proxy', true);

// 환경변수 디버깅
console.log('🔍 모든 환경변수 확인:');
console.log('NODE_ENV:', process.env.NODE_ENV);
console.log('PORT:', process.env.PORT);
console.log('모든 환경변수:', Object.keys(process.env).filter(key => key.startsWith('SUPABASE')));

// 환경변수 검증
const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_KEY = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;

console.log('🔍 Supabase 환경변수 확인:');
console.log('SUPABASE_URL:', SUPABASE_URL ? `✅ ${SUPABASE_URL.substring(0, 30)}...` : '❌ 없음');
console.log('SUPABASE_SERVICE_ROLE_KEY:', process.env.SUPABASE_SERVICE_ROLE_KEY ? '✅ 설정됨' : '❌ 없음');
console.log('SUPABASE_ANON_KEY:', process.env.SUPABASE_ANON_KEY ? '✅ 설정됨' : '❌ 없음');

console.log('🔍 Railway DB 환경변수 확인:');
console.log('DATABASE_URL:', process.env.DATABASE_URL ? `✅ ${process.env.DATABASE_URL.substring(0, 30)}...` : '❌ 없음');

if (!SUPABASE_URL) {
  console.error('❌ SUPABASE_URL 환경변수가 설정되지 않았습니다');
  console.error('Railway Variables에서 SUPABASE_URL을 확인해주세요');
  process.exit(1);
}

if (!SUPABASE_KEY) {
  console.error('❌ SUPABASE 키 환경변수가 설정되지 않았습니다');
  console.error('SUPABASE_SERVICE_ROLE_KEY 또는 SUPABASE_ANON_KEY를 설정해주세요');
  process.exit(1);
}

// Supabase 클라이언트 설정 (최종 데이터용)
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// Railway PostgreSQL 연결 설정 (임시 데이터용)
let railwayDB = null;

if (process.env.DATABASE_URL) {
  railwayDB = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
  });
  console.log('🔗 Railway PostgreSQL 설정 완료');
} else {
  console.log('⚠️ DATABASE_URL 없음 - Railway PostgreSQL을 추가해주세요');
}

// Railway DB 연결 테스트 및 테이블 생성
async function initializeRailwayDB() {
  if (!railwayDB) {
    console.log('⏭️ Railway PostgreSQL 없음 - Supabase fallback 사용');
    return;
  }
  
  try {
    await railwayDB.query('SELECT NOW()');
    console.log('✅ Railway PostgreSQL 연결 성공');
    
    // submissions 테이블 생성 (검증 링크, 시즌 정보 추가)
    await railwayDB.query(`
      CREATE TABLE IF NOT EXISTS submissions (
        submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academy_name TEXT NOT NULL,
        instructor_name TEXT,
        contact_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT,
        verification_url TEXT,
        target_season TEXT,
        notes TEXT,
        csv_data JSONB NOT NULL,
        status TEXT DEFAULT 'pending' CHECK (status IN ('pending', 'reviewing', 'approved', 'rejected')),
        rejection_reason TEXT,
        submitted_at TIMESTAMPTZ DEFAULT now(),
        reviewed_at TIMESTAMPTZ,
        reviewed_by TEXT,
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      
      CREATE INDEX IF NOT EXISTS idx_submissions_status ON submissions(status);
      CREATE INDEX IF NOT EXISTS idx_submissions_submitted_at ON submissions(submitted_at DESC);
    `);
    
    // 관리자 계정 테이블 생성
    await railwayDB.query(`
      CREATE TABLE IF NOT EXISTS admin_users (
        admin_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        name TEXT NOT NULL,
        role TEXT DEFAULT 'admin' CHECK (role IN ('admin', 'super_admin')),
        status TEXT DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        last_login_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      
      CREATE INDEX IF NOT EXISTS idx_admin_users_username ON admin_users(username);
    `);
    
    // 기본 관리자 계정 생성 (없을 경우)
    const defaultAdmin = await railwayDB.query('SELECT admin_id FROM admin_users WHERE username = $1', ['admin']);
    if (defaultAdmin.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('admin123', 10);
      await railwayDB.query(`
        INSERT INTO admin_users (username, password_hash, name, role)
        VALUES ($1, $2, $3, $4)
      `, ['admin', hashedPassword, '기본 관리자', 'super_admin']);
      
      console.log('👤 기본 관리자 계정 생성: admin/admin123');
    }
    
    // academies 테이블 생성
    await railwayDB.query(`
      CREATE TABLE IF NOT EXISTS academies (
        academy_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        academy_name TEXT NOT NULL,
        contact_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        status TEXT DEFAULT 'active' CHECK (status IN ('active', 'suspended')),
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      
      CREATE INDEX IF NOT EXISTS idx_academies_email ON academies(email);
    `);
    
    // approved_bundles 테이블 생성 (승인된 번들 데이터 저장)
    await railwayDB.query(`
      CREATE TABLE IF NOT EXISTS approved_bundles (
        approved_bundle_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        submission_id UUID NOT NULL,
        target_season TEXT NOT NULL,
        bundle_data JSONB NOT NULL,
        session_data JSONB NOT NULL,
        academy_name TEXT NOT NULL,
        instructor_name TEXT,
        contact_name TEXT NOT NULL,
        phone TEXT NOT NULL,
        email TEXT NOT NULL,
        notes TEXT,
        approved_at TIMESTAMPTZ DEFAULT now(),
        approved_by TEXT DEFAULT 'admin',
        deployed_to_supabase BOOLEAN DEFAULT false,
        deployed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ DEFAULT now(),
        updated_at TIMESTAMPTZ DEFAULT now()
      );
      
      CREATE INDEX IF NOT EXISTS idx_approved_bundles_season ON approved_bundles(target_season);
      CREATE INDEX IF NOT EXISTS idx_approved_bundles_submission ON approved_bundles(submission_id);
      CREATE INDEX IF NOT EXISTS idx_approved_bundles_deployed ON approved_bundles(deployed_to_supabase);
      CREATE INDEX IF NOT EXISTS idx_approved_bundles_approved_at ON approved_bundles(approved_at DESC);
    `);
    
    // 임시 강사 계정 생성 (테스트용)
    const testAcademy = await railwayDB.query('SELECT academy_id FROM academies WHERE email = $1', ['test@timebuilder.com']);
    if (testAcademy.rows.length === 0) {
      const hashedPassword = await bcrypt.hash('test123', 10);
      await railwayDB.query(`
        INSERT INTO academies (academy_name, contact_name, phone, email, password_hash)
        VALUES ($1, $2, $3, $4, $5)
      `, ['테스트 학원', '표종승', '010-1234-5678', 'test@timebuilder.com', hashedPassword]);
      
      console.log('🧪 테스트 강사 계정 생성: test@timebuilder.com/test123 (테스트 학원 - 표종승)');
    }
    
    // submissions 테이블 컬럼 추가 (기존 테이블에 없는 경우)
    await railwayDB.query(`
      ALTER TABLE submissions 
      ADD COLUMN IF NOT EXISTS verification_url TEXT,
      ADD COLUMN IF NOT EXISTS target_season TEXT
    `);
    
    console.log('✅ Railway DB submissions 테이블 준비 완료 (컬럼 업데이트 포함)');
    console.log('✅ Railway DB approved_bundles 테이블 준비 완료');
  } catch (error) {
    console.error('❌ Railway PostgreSQL 초기화 실패:', error);
  }
}

// DB 초기화 실행
initializeRailwayDB();

// JWT 토큰 생성/검증 헬퍼
const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.JWT_SECRET || 'academy-jwt-secret-2025';

function generateToken(academyData) {
  return jwt.sign(academyData, JWT_SECRET, { expiresIn: '7d' });
}

function verifyToken(token) {
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch (error) {
    return null;
  }
}

// 학원 인증 미들웨어
function requireAcademyAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: '인증 토큰이 필요합니다' });
  }

  const token = authHeader.substring(7);
  const decoded = verifyToken(token);
  
  if (!decoded) {
    return res.status(401).json({ error: '유효하지 않은 토큰입니다' });
  }

  req.academy = decoded;
  next();
}

// 학원 승인 상태 체크 미들웨어
async function requireApprovedAcademy(req, res, next) {
  if (!railwayDB) {
    return res.status(503).json({ error: '서비스 준비 중입니다' });
  }

  try {
    // DB에서 최신 승인 상태 확인
    const result = await railwayDB.query(
      'SELECT status FROM academies WHERE academy_id = $1',
      [req.academy.academy_id]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: '학원 정보를 찾을 수 없습니다' });
    }

    const academy = result.rows[0];
    
    if (academy.status !== 'active') {
      const statusMessages = {
        'pending': '학원 승인 대기 중입니다. 관리자 승인 후 이용 가능합니다.',
        'rejected': '학원 가입이 거절되었습니다. 자세한 내용은 연락처로 문의해주세요.',
        'suspended': '학원 계정이 정지되었습니다. 자세한 내용은 연락처로 문의해주세요.'
      };
      
      return res.status(403).json({ 
        error: statusMessages[academy.status] || '이용할 수 없는 계정입니다',
        status: academy.status
      });
    }

    next();
  } catch (error) {
    console.error('학원 승인 상태 체크 실패:', error);
    res.status(500).json({ error: '인증 확인 중 오류가 발생했습니다' });
  }
}

// 보안 미들웨어 (CSP 완화 - 인라인 이벤트 핸들러 허용)
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'", "'unsafe-hashes'", "https://cdn.tailwindcss.com"],
      scriptSrcAttr: ["'unsafe-inline'"], // onclick 등 인라인 이벤트 핸들러 허용
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      connectSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"]
    }
  }
}));

// Rate limiting (API 남용 방지)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분
  max: 100, // 최대 100회 요청
  message: '너무 많은 요청입니다. 잠시 후 다시 시도해주세요.'
});
app.use('/api/', limiter);

// 관리자 로그인용 더 엄격한 제한
const adminLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15분  
  max: 5, // 최대 5회 로그인 시도
  message: '로그인 시도 횟수가 초과되었습니다.'
});

// 세션 관리 (Railway 호환)
app.use(session({
  secret: process.env.SESSION_SECRET || 'timetable-admin-secret-key-2025',
  resave: false,
  saveUninitialized: false,
  name: 'timetable.sid', // 세션 이름 설정
  cookie: {
    secure: false, // Railway에서 HTTPS 프록시 문제로 임시 false
    httpOnly: true, // XSS 방지
    maxAge: 24 * 60 * 60 * 1000, // 24시간
    sameSite: 'lax' // CSRF 방지
  }
}));

// 기본 미들웨어
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// 관리자 인증 미들웨어
function requireAuth(req, res, next) {
  console.log('🔍 인증 체크:', {
    path: req.path,
    sessionId: req.session.id,
    isAdmin: req.session.isAdmin,
    loginTime: req.session.loginTime
  });

  if (!req.session.isAdmin) {
    console.log('❌ 인증 실패: isAdmin =', req.session.isAdmin);
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: '인증이 필요합니다' });
    }
    return res.redirect('/admin/login');
  }
  
  // 세션 만료 체크 (24시간)
  if (req.session.loginTime) {
    const loginTime = new Date(req.session.loginTime);
    const now = new Date();
    if (now - loginTime > 24 * 60 * 60 * 1000) {
      console.log('⏰ 세션 만료:', { loginTime, now });
      req.session.destroy();
      if (req.path.startsWith('/api/')) {
        return res.status(401).json({ error: '세션이 만료되었습니다' });
      }
      return res.redirect('/admin/login');
    }
  }
  
  console.log('✅ 인증 성공');
  next();
}

// 관리자 활동 로깅 미들웨어
function logAdminActivity(action) {
  return async (req, res, next) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action: action,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.session.id
    };
    
    console.log('🔍 Admin Activity:', logEntry);
    
    // DB에 로그 저장 (선택적) - Railway DB 사용으로 변경
    try {
      if (railwayDB) {
        await railwayDB.query(`
          CREATE TABLE IF NOT EXISTS admin_logs (
            log_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            timestamp TIMESTAMPTZ NOT NULL,
            action TEXT NOT NULL,
            ip TEXT,
            user_agent TEXT,
            session_id TEXT,
            created_at TIMESTAMPTZ DEFAULT now()
          )
        `);
        
        await railwayDB.query(`
          INSERT INTO admin_logs (timestamp, action, ip, user_agent, session_id)
          VALUES ($1, $2, $3, $4, $5)
        `, [logEntry.timestamp, logEntry.action, logEntry.ip, logEntry.userAgent, logEntry.sessionId]);
      }
    } catch (logError) {
      console.error('⚠️ 관리자 로그 저장 실패:', logError);
    }
    
    next();
  };
}

// 파일 업로드 설정
const upload = multer({ 
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB 제한
});

// 학교명 → NEIS 코드 변환 매핑
const schoolCodeMapping = {
  '세화고': 'B10_7010197',
  '세화고등학교': 'B10_7010197', 
  '세화여고': 'B10_7010198',
  '세화여자고등학교': 'B10_7010198',
  '서울고': 'B10_7010083',
  '서울고등학교': 'B10_7010083',
  '상문고': 'B10_7010179', 
  '상문고등학교': 'B10_7010179',
  '반포고': 'B10_7010080',
  '반포고등학교': 'B10_7010080',
  '서초고': 'B10_7010087',
  '서초고등학교': 'B10_7010087',
  // 필요시 더 추가...
};

/**
 * 학교명을 NEIS 코드 배열로 변환
 */
function convertSchoolNames(schoolText) {
  if (!schoolText || schoolText.trim() === '연합반') {
    return ['UNION'];
  }
  
  // 복합 학교 처리 (예: "반포고, 서초고")
  if (schoolText.includes(',')) {
    const schools = schoolText.split(',').map(s => s.trim());
    const codes = schools
      .map(school => schoolCodeMapping[school])
      .filter(code => code);
    return codes.length > 0 ? codes : ['UNION'];
  }
  
  // 단일 학교
  const school = schoolText.trim();
  const code = schoolCodeMapping[school];
  return code ? [code] : ['UNION'];
}

/**
 * CSV 업로드 및 Supabase 업로드 API
 */
app.post('/api/upload-csv', upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'CSV 파일이 필요합니다' });
    }

    console.log('📁 CSV 파일 수신:', req.file.originalname);
    
    const bundles = [];
    const sessions = [];
    const csvContent = req.file.buffer.toString('utf-8');

    // CSV 파싱
    const rows = csvContent.split('\n').slice(1); // 헤더 제외
    
    // 행 개수 제한 체크 (악용 방지)
    if (rows.filter(row => row.trim()).length > 300) {
      return res.status(400).json({ 
        error: '너무 많은 데이터입니다. 악용 방지를 위해 300개 행까지만 허용됩니다.',
        maxRows: 300,
        currentRows: rows.filter(row => row.trim()).length
      });
    }
    
    for (let i = 0; i < rows.length; i++) {
      const row = rows[i];
      if (!row.trim()) continue;
      
      const columns = row.split(',').map(col => col.replace(/"/g, '').trim());
      
      if (columns.length < 17) continue; // 필수 컬럼 체크
      
      const bundleId = generateUUID();
      const teacher = columns[0];        // 강사명
      const subject = columns[1];        // 과목
      const targetSchool = columns[2];   // 대상 학교
      const schoolLevel = columns[3];    // 초,중,고
      const targetGrade = columns[4];    // 대상 학년
      const topic = columns[5];          // 주제
      const academy = columns[6];        // 출강 학원
      const startDate = columns[7];      // 개강 일자
      const region = columns[8];         // 지역
      
      // 학교 코드 변환
      const schoolCodes = convertSchoolNames(targetSchool);
      
      // 번들 데이터
      bundles.push({
        bundle_id: bundleId,
        teacher_name: teacher,
        subject: subject,
        target_school_codes: schoolCodes,
        school_level: schoolLevel,
        target_grade: targetGrade,
        topic: topic,
        academy: academy,
        region: region,
        published: true,
        status: 'active',
        updated_at: new Date().toISOString()
      });
      
      // 세션 데이터 (일~토요일 체크)
      const days = [9, 10, 11, 12, 13, 14, 15]; // CSV 컬럼 인덱스
      const dayNames = ['일요일', '월요일', '화요일', '수요일', '목요일', '금요일', '토요일'];
      
      for (let j = 0; j < days.length; j++) {
        const timeSlot = columns[days[j]];
        if (timeSlot && timeSlot.includes('~')) {
          const [startTime, endTime] = timeSlot.split('~').map(t => t.trim());
          
          sessions.push({
            session_id: generateUUID(),
            bundle_id: bundleId,
            weekday: j,
            start_time: startTime,
            end_time: endTime,
            status: 'active'
          });
        }
      }
    }

    console.log(`📊 처리 완료: ${bundles.length}개 번들, ${sessions.length}개 세션`);

    // Supabase에 bulk insert
    console.log('🚀 Supabase 업로드 시작...');
    
    // 기존 데이터 삭제 (선택적)
    if (req.body.clearExisting === 'true') {
      await supabase.from('sessions_2025_4').delete().neq('bundle_id', '');
      await supabase.from('bundles_2025_4').delete().neq('bundle_id', '');
      console.log('🗑️ 기존 데이터 삭제 완료');
    }
    
    // 번들 업로드 (1000개씩 배치)
    for (let i = 0; i < bundles.length; i += 1000) {
      const batch = bundles.slice(i, i + 1000);
      const { error } = await supabase.from('bundles_2025_4').insert(batch);
      if (error) throw error;
      console.log(`📦 번들 배치 ${Math.floor(i/1000)+1} 업로드 완료`);
    }
    
    // 세션 업로드 (1000개씩 배치)
    for (let i = 0; i < sessions.length; i += 1000) {
      const batch = sessions.slice(i, i + 1000);
      const { error } = await supabase.from('sessions_2025_4').insert(batch);
      if (error) throw error;
      console.log(`⏰ 세션 배치 ${Math.floor(i/1000)+1} 업로드 완료`);
    }
    
    res.json({
      success: true,
      message: '업로드 완료',
      bundles: bundles.length,
      sessions: sessions.length
    });
    
    console.log('✅ 전체 업로드 완료!');
    
  } catch (error) {
    console.error('❌ 업로드 실패:', error);
    res.status(500).json({ 
      error: '업로드 중 오류가 발생했습니다',
      details: error.message 
    });
  }
});

/**
 * UUID 생성 헬퍼
 */
function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
    const r = Math.random() * 16 | 0;
    const v = c == 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

// ===== 공개 라우트 (학원/강사용) =====

// 메인 페이지 - 새로운 포털 사이트
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// 관리자 직접 업로드 (CSV → Supabase 직접) - submit.html 사용
app.get('/direct-upload', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/submit.html');
});

// 광고 문의 제출 API
app.post('/api/submit-inquiry', async (req, res) => {
  try {
    const { companyName, contactPerson, phone, email, inquiryType, message } = req.body;
    
    if (!companyName || !contactPerson || !phone || !email || !inquiryType || !message) {
      return res.status(400).json({ error: '모든 필수 항목을 입력해주세요' });
    }

    const inquiryId = generateUUID();
    
    // Railway DB에 문의 저장 (inquiries 테이블 추가 필요)
    if (railwayDB) {
      await railwayDB.query(`
        CREATE TABLE IF NOT EXISTS inquiries (
          inquiry_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
          company_name TEXT NOT NULL,
          contact_person TEXT NOT NULL,
          phone TEXT NOT NULL,
          email TEXT NOT NULL,
          inquiry_type TEXT NOT NULL,
          message TEXT NOT NULL,
          status TEXT DEFAULT 'new' CHECK (status IN ('new', 'contacted', 'closed')),
          submitted_at TIMESTAMPTZ DEFAULT now(),
          created_at TIMESTAMPTZ DEFAULT now()
        )
      `);
      
      await railwayDB.query(`
        INSERT INTO inquiries (inquiry_id, company_name, contact_person, phone, email, inquiry_type, message, submitted_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
      `, [inquiryId, companyName, contactPerson, phone, email, inquiryType, message, new Date()]);
    }

    console.log(`💬 새로운 문의: ${companyName} (${inquiryType}) - ${inquiryId}`);
    
    res.json({
      success: true,
      inquiryId: inquiryId,
      message: '문의가 성공적으로 접수되었습니다.'
    });
    
  } catch (error) {
    console.error('❌ 문의 접수 실패:', error);
    res.status(500).json({ 
      error: '문의 접수 중 오류가 발생했습니다',
      details: error.message 
    });
  }
});

// 레거시 API 제거됨 - 웹 테이블 제출(/api/submit-timetable-web)만 사용

// ===== 관리자 라우트 =====

// 관리자 로그인 페이지
app.get('/admin/login', (req, res) => {
  if (req.session.isAdmin) {
    return res.redirect('/admin/dashboard');
  }
  res.sendFile(__dirname + '/public/admin-login.html');
});

// 관리자 로그인 처리 (DB 기반)
app.post('/admin/login', adminLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    
    if (!username || !password) {
      return res.status(400).json({ error: '아이디와 비밀번호를 모두 입력해주세요' });
    }

    if (!railwayDB) {
      // Railway DB 없을 때 fallback
      const adminPassword = process.env.ADMIN_PASSWORD || 'admin123';
      if (username === 'admin' && password === adminPassword) {
        req.session.isAdmin = true;
        req.session.loginTime = new Date();
        req.session.adminInfo = { username: 'admin', name: '기본 관리자' };
        
        console.log(`🔓 관리자 로그인 (fallback): ${username} (IP ${req.ip})`);
        return res.json({ success: true });
      } else {
        return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다' });
      }
    }

    // DB에서 관리자 계정 확인
    const result = await railwayDB.query(
      'SELECT * FROM admin_users WHERE username = $1 AND status = $2',
      [username, 'active']
    );
    
    if (result.rows.length === 0) {
      console.log(`❌ 관리자 로그인 실패: 존재하지 않는 계정 ${username} (IP ${req.ip})`);
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다' });
    }

    const adminUser = result.rows[0];
    
    // 비밀번호 확인
    const isValidPassword = await bcrypt.compare(password, adminUser.password_hash);
    if (!isValidPassword) {
      console.log(`❌ 관리자 로그인 실패: 잘못된 비밀번호 ${username} (IP ${req.ip})`);
      return res.status(401).json({ error: '아이디 또는 비밀번호가 올바르지 않습니다' });
    }

    // 세션 생성
    req.session.isAdmin = true;
    req.session.loginTime = new Date();
    req.session.adminInfo = {
      admin_id: adminUser.admin_id,
      username: adminUser.username,
      name: adminUser.name,
      role: adminUser.role
    };
    
    // 마지막 로그인 시간 업데이트
    await railwayDB.query(
      'UPDATE admin_users SET last_login_at = NOW(), updated_at = NOW() WHERE admin_id = $1',
      [adminUser.admin_id]
    );
    
    console.log(`🔓 관리자 로그인 성공: ${adminUser.name} (${username}) - IP ${req.ip}`);
    
    res.json({ 
      success: true,
      admin: {
        name: adminUser.name,
        username: adminUser.username,
        role: adminUser.role
      }
    });

  } catch (error) {
    console.error('❌ 관리자 로그인 처리 실패:', error);
    res.status(500).json({ error: '로그인 처리 중 오류가 발생했습니다' });
  }
});

// 관리자 대시보드
app.get('/admin/dashboard', requireAuth, (req, res) => {
  console.log('🎯 대시보드 접근:', req.session.isAdmin);
  res.sendFile(__dirname + '/public/admin-dashboard.html');
});

// 관리자 메인 라우트 (리디렉션용)
app.get('/admin', requireAuth, (req, res) => {
  res.redirect('/admin/dashboard');
});

// 관리자 로그아웃
app.post('/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// 대시보드 통계 API (Railway + Supabase 혼용)
app.get('/api/admin/dashboard-stats', requireAuth, logAdminActivity('VIEW_DASHBOARD'), async (req, res) => {
  try {
    console.log('📊 대시보드 통계 API 호출');
    console.log('🔗 Railway DB 상태:', !!railwayDB);
    
    let submissions = [];
    let pendingAcademies = 0;
    
    if (railwayDB) {
      try {
        // Railway DB에서 제출 현황 조회
        const submissionsResult = await railwayDB.query(`
          SELECT status, submitted_at, academy_name 
          FROM submissions 
          ORDER BY submitted_at DESC 
          LIMIT 10
        `);
        submissions = submissionsResult.rows;
        console.log('📋 제출 내역 조회 성공:', submissions.length);
        
        // Railway DB에서 학원 승인 대기 수 조회
        const academiesResult = await railwayDB.query(`
          SELECT COUNT(*) as pending_academies 
          FROM academies 
          WHERE status = 'pending'
        `);
        pendingAcademies = academiesResult.rows[0]?.pending_academies || 0;
        console.log('🏢 대기 학원 수:', pendingAcademies);
        
      } catch (dbError) {
        console.error('❌ Railway DB 쿼리 실패:', dbError);
        submissions = [];
        pendingAcademies = 0;
      }
    } else {
      console.log('⚠️ Railway DB 연결되지 않음');
    }

    // Supabase에서 전체 번들 수 조회
    let totalBundles = 0;
    try {
      const { count, error: bundleError } = await supabase
        .from('bundles_2025_4')
        .select('*', { count: 'exact', head: true });
      
      if (bundleError) {
        console.error('❌ Supabase 번들 조회 실패:', bundleError);
      } else {
        totalBundles = count || 0;
        console.log('📦 전체 번들 수:', totalBundles);
      }
    } catch (supabaseError) {
      console.error('❌ Supabase 연결 실패:', supabaseError);
    }

    // 통계 계산
    const pendingSubmissions = submissions.filter(s => s.status === 'pending').length;
    const approvedSubmissions = submissions.filter(s => s.status === 'approved').length;
    
    // 최근 활동 생성
    const recentActivity = submissions.slice(0, 5).map(submission => ({
      type: submission.status === 'pending' ? 'submit' : 'approve',
      description: submission.status === 'pending' 
        ? `새로운 시간표 제출` 
        : `시간표 승인 완료`,
      academy: submission.academy_name,
      timestamp: submission.submitted_at
    }));

    console.log('📈 최종 통계:', {
      pendingSubmissions,
      pendingAcademies, 
      approvedSubmissions,
      totalBundles
    });

    res.json({
      pendingSubmissions,
      pendingAcademies,
      approvedSubmissions,
      totalBundles: totalBundles || 0,
      inquiries: 0, // TODO: 문의사항 테이블 생성 후 구현
      recentActivity
    });

  } catch (error) {
    console.error('대시보드 통계 조회 실패:', error);
    res.status(500).json({ error: '통계 데이터 로드 실패' });
  }
});

// ===== 제출 검토 관련 라우트 =====

// 제출 검토 페이지
app.get('/admin/submissions', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/admin-submissions.html');
});

// 제출 목록 API (Railway DB 사용) - 상태별 필터링 지원
app.get('/api/admin/submissions', requireAuth, logAdminActivity('VIEW_SUBMISSIONS'), async (req, res) => {
  try {
    const { status } = req.query; // 상태 필터링 파라미터
    
    console.log('📋 제출 목록 API 호출됨 (Railway DB)');
    console.log('🔗 Railway DB 연결 상태:', !!railwayDB);
    console.log('🔍 필터 상태:', status || '전체');
    
    if (!railwayDB) {
      console.log('❌ Railway DB 연결되지 않음');
      return res.status(503).json({ error: '데이터베이스 서비스 준비 중입니다' });
    }

    // 상태별 쿼리 구성
    let query = `
      SELECT submission_id, academy_name, contact_name, phone, email, 
             verification_url, target_season, notes, csv_data, status, 
             rejection_reason, submitted_at, reviewed_at, reviewed_by
      FROM submissions
    `;
    let queryParams = [];

    if (status) {
      query += ` WHERE status = $1`;
      queryParams.push(status);
    }

    query += ` ORDER BY submitted_at DESC`;

    const result = await railwayDB.query(query, queryParams);
    const submissions = result.rows;
    
    // 상태별 개수 계산
    const countsResult = await railwayDB.query(`
      SELECT status, COUNT(*) as count 
      FROM submissions 
      GROUP BY status
    `);
    
    const counts = {};
    countsResult.rows.forEach(row => {
      counts[row.status] = parseInt(row.count);
    });
    
    console.log(`📊 제출 목록 조회 성공: ${submissions.length}개 (필터: ${status || '전체'})`);
    console.log('📊 상태별 개수:', counts);
    
    res.json({ 
      submissions,
      counts: {
        pending: counts.pending || 0,
        approved: counts.approved || 0,
        rejected: counts.rejected || 0,
        total: Object.values(counts).reduce((sum, count) => sum + count, 0)
      }
    });
  } catch (error) {
    console.error('제출 목록 조회 실패:', error);
    res.status(500).json({ error: '제출 목록 로드 실패: ' + error.message });
  }
});

// 검토 확인 API 제거됨 - 2단계 워크플로우로 변경 (대기 → 승인/거절)

// 승인 확정 (approved_bundles 테이블에 저장 - Supabase 업로드는 별도 단계)
app.post('/api/admin/submissions/:id/approve', requireAuth, logAdminActivity('APPROVE_SUBMISSION'), async (req, res) => {
  try {
    const { id } = req.params;
    const { season } = req.body;
    
    if (!season) {
      return res.status(400).json({ error: '시즌을 선택해주세요' });
    }

    // Railway DB에서 제출 데이터 가져오기
    const result = await railwayDB.query(`
      SELECT * FROM submissions WHERE submission_id = $1
    `, [id]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '제출 데이터를 찾을 수 없습니다' });
    }

    const submission = result.rows[0];
    const csvData = JSON.parse(submission.csv_data);
    const bundles = [];
    const sessions = [];

    // 데이터 변환 (Supabase 형태로 준비)
    for (const bundleData of csvData) {
      const bundleId = generateUUID();
      const schoolCodes = convertSchoolNames(bundleData.target_school);

      bundles.push({
        bundle_id: bundleId,
        teacher_name: bundleData.teacher_name,
        subject: bundleData.subject,
        target_school_codes: schoolCodes,
        school_level: bundleData.school_level,
        target_grade: bundleData.target_grade,
        topic: bundleData.topic,
        academy: bundleData.academy,
        start_date: bundleData.start_date,
        region: bundleData.region,
        published: true,
        status: 'active',
        updated_at: new Date().toISOString()
      });

      // 세션 데이터
      for (const sessionData of bundleData.sessions) {
        sessions.push({
          session_id: generateUUID(),
          bundle_id: bundleId,
          weekday: sessionData.weekday,
          start_time: sessionData.start_time,
          end_time: sessionData.end_time,
          status: 'active'
        });
      }
    }

    // approved_bundles 테이블에 저장 (Supabase 업로드는 나중에)
    await railwayDB.query(`
      INSERT INTO approved_bundles (
        submission_id, target_season, bundle_data, session_data,
        academy_name, instructor_name, contact_name, phone, email, notes,
        approved_by
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `, [
      id, season, JSON.stringify(bundles), JSON.stringify(sessions),
      submission.academy_name, submission.instructor_name, submission.contact_name,
      submission.phone, submission.email, submission.notes, 'admin'
    ]);

    // submissions 테이블 상태를 승인으로 변경
    await railwayDB.query(`
      UPDATE submissions 
      SET status = 'approved', reviewed_at = NOW(), reviewed_by = 'admin', updated_at = NOW()
      WHERE submission_id = $1
    `, [id]);

    console.log(`✅ 시간표 1차 승인 완료: ${submission.academy_name} → ${season} (번들 ${bundles.length}개, 세션 ${sessions.length}개) - approved_bundles 테이블에 저장`);
    
    res.json({ 
      success: true, 
      message: `${season} 시즌 승인 대기열에 ${bundles.length}개 번들이 추가되었습니다.`,
      bundles: bundles.length,
      sessions: sessions.length,
      note: 'Supabase 배포는 /admin/bundles 페이지에서 별도로 진행하세요.'
    });

  } catch (error) {
    console.error('승인 처리 실패:', error);
    res.status(500).json({ error: '승인 처리 실패: ' + error.message });
  }
});

// 거절 (Railway DB 사용)
app.post('/api/admin/submissions/:id/reject', requireAuth, logAdminActivity('REJECT_SUBMISSION'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    await railwayDB.query(`
      UPDATE submissions 
      SET status = 'rejected', rejection_reason = $2, reviewed_at = NOW(), reviewed_by = 'admin', updated_at = NOW()
      WHERE submission_id = $1
    `, [id, reason]);

    console.log(`❌ 시간표 거절: ${id} (사유: ${reason})`);
    res.json({ success: true });
  } catch (error) {
    console.error('거절 처리 실패:', error);
    res.status(500).json({ error: '거절 처리 실패' });
  }
});

// 웹 테이블 시간표 제출 API
app.post('/api/submit-timetable-web', async (req, res) => {
  try {
    console.log('📥 웹 테이블 제출 API 호출됨');
    console.log('📋 요청 본문 크기:', JSON.stringify(req.body).length);
    
    const { academyName, contactName, phone, email, seasonYear, seasonQuarter, verificationUrl, notes, tableData } = req.body;
    
    console.log('🔍 추출된 필드들:', {
      academyName, contactName, phone, email, seasonYear, seasonQuarter, verificationUrl,
      notesLength: notes?.length || 0,
      tableDataLength: tableData?.length || 0
    });
    
    // 첫 번째 행의 start_date 디버깅
    if (tableData && tableData.length > 0) {
      console.log('🔍 첫 번째 행 start_date:', tableData[0].start_date);
      console.log('🔍 첫 번째 행 전체:', tableData[0]);
    }
    
    if (!academyName || !contactName || !email || !seasonYear || !seasonQuarter || !verificationUrl || !tableData) {
      console.log('❌ 필수 정보 누락 체크:', {
        academyName: !!academyName,
        contactName: !!contactName, 
        email: !!email,
        seasonYear: !!seasonYear,
        seasonQuarter: !!seasonQuarter,
        verificationUrl: !!verificationUrl,
        tableData: !!tableData
      });
      return res.status(400).json({ error: '필수 정보가 누락되었습니다' });
    }

    if (!tableData || tableData.length === 0) {
      console.log('❌ 테이블 데이터 없음:', tableData);
      return res.status(400).json({ error: '시간표 데이터가 없습니다' });
    }

    // 행 개수 제한 체크 (악용 방지)
    if (tableData.length > 300) {
      return res.status(400).json({ 
        error: '너무 많은 데이터입니다. 악용 방지를 위해 300개 행까지만 허용됩니다.',
        maxRows: 300,
        currentRows: tableData.length
      });
    }

    console.log('✅ 기본 검증 통과, 데이터 변환 시작');
    
    const submissionId = generateUUID();
    const season = `${seasonYear}.${seasonQuarter}`;
    
    // 테이블 데이터를 CSV 형식으로 변환
    const bundles = tableData.map(row => ({
      teacher_name: row.teacher_name,
      subject: row.subject,
      education_office: row.education_office,
      target_school: row.target_school,
      school_level: row.school_level,
      target_grade: row.target_grade,
      topic: row.topic,
      academy: row.academy,
      start_date: row.start_date,
      region: row.region,
      sessions: row.schedule.map((timeInfo, index) => {
        // timeInfo는 {start_time, end_time} 객체 또는 null
        if (timeInfo && timeInfo.start_time && timeInfo.end_time) {
          return {
            weekday: index,
            start_time: timeInfo.start_time,
            end_time: timeInfo.end_time
          };
        }
        return null;
      }).filter(session => session !== null)
    }));

    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    // Railway DB submissions 테이블에 저장 (phone 필드 추가)
    await railwayDB.query(`
      INSERT INTO submissions (
        submission_id, academy_name, contact_name, phone,
        email, verification_url, target_season, notes, csv_data, status, submitted_at
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
    `, [
      submissionId, academyName, contactName, phone || 'Unknown Phone',
      email, verificationUrl, season, notes, 
      JSON.stringify(bundles), 'pending', new Date()
    ]);

    console.log(`📥 웹 테이블 시간표 제출: ${academyName} (${tableData.length}개 데이터, ID: ${submissionId})`);
    
    res.json({
      success: true,
      submissionId: submissionId,
      message: '시간표가 성공적으로 제출되었습니다. 검토 후 연락드리겠습니다.',
      bundles: bundles.length
    });
    
  } catch (error) {
    console.error('❌ 웹 테이블 제출 실패:', error);
    res.status(500).json({ 
      error: '제출 중 오류가 발생했습니다',
      details: error.message 
    });
  }
});

// ===== 학원/강사 계정 관리 =====

// 학원 회원가입
app.post('/api/academy/register', async (req, res) => {
  try {
    const { academyName, contactName, phone, email, password } = req.body;
    
    if (!academyName || !contactName || !phone || !email || !password) {
      return res.status(400).json({ error: '모든 필수 항목을 입력해주세요' });
    }

    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    // 이메일 중복 체크
    const existingUser = await railwayDB.query(
      'SELECT academy_id FROM academies WHERE email = $1', [email]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: '이미 등록된 이메일입니다' });
    }

    // 비밀번호 해싱
    const hashedPassword = await bcrypt.hash(password, 10);
    
    // 학원 등록 (기본 상태: 승인 대기)
    const result = await railwayDB.query(`
      INSERT INTO academies (academy_name, contact_name, phone, email, password_hash, status)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING academy_id, academy_name, contact_name, email
    `, [academyName, contactName, phone, email, hashedPassword, 'pending']);

    const academy = result.rows[0];
    console.log(`👥 새로운 학원 가입: ${academyName} (${email})`);
    
    res.json({
      success: true,
      message: '회원가입이 완료되었습니다',
      academy: {
        academy_id: academy.academy_id,
        academy_name: academy.academy_name,
        email: academy.email
      }
    });

  } catch (error) {
    console.error('❌ 학원 회원가입 실패:', error);
    res.status(500).json({ error: '회원가입 처리 중 오류가 발생했습니다' });
  }
});

// 학원 로그인
app.post('/api/academy/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    
    if (!email || !password) {
      return res.status(400).json({ error: '이메일과 비밀번호를 입력해주세요' });
    }

    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    // 사용자 조회
    const result = await railwayDB.query(
      'SELECT * FROM academies WHERE email = $1 AND status = $2',
      [email, 'active']
    );
    
    if (result.rows.length === 0) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다' });
    }

    const academy = result.rows[0];
    
    // 비밀번호 확인
    const isValidPassword = await bcrypt.compare(password, academy.password_hash);
    if (!isValidPassword) {
      return res.status(401).json({ error: '이메일 또는 비밀번호가 올바르지 않습니다' });
    }

    // JWT 토큰 생성
    const tokenData = {
      academy_id: academy.academy_id,
      academy_name: academy.academy_name,
      contact_name: academy.contact_name,
      phone: academy.phone,
      email: academy.email
    };
    
    const token = generateToken(tokenData);
    
    console.log(`🔓 학원 로그인: ${academy.academy_name} (${email})`);
    
    res.json({
      success: true,
      token: token,
      academy: tokenData
    });

  } catch (error) {
    console.error('❌ 학원 로그인 실패:', {
      error: error.message,
      stack: error.stack,
      username: req.body.username,
      railwayDBExists: !!railwayDB
    });
    res.status(500).json({ error: '로그인 처리 중 오류가 발생했습니다: ' + error.message });
  }
});

// 학원 제출 내역 조회 (승인된 학원만)
app.get('/api/academy/submissions', requireAcademyAuth, requireApprovedAcademy, async (req, res) => {
  try {
    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    // 해당 학원의 제출 내역만 조회
    const result = await railwayDB.query(`
      SELECT submission_id, academy_name, contact_name, phone, email, notes, status, rejection_reason, submitted_at, reviewed_at
      FROM submissions 
      WHERE email = $1 OR contact_name = $2
      ORDER BY submitted_at DESC
    `, [req.academy.email, req.academy.contact_name]);

    console.log(`📊 학원 제출 내역 조회: ${req.academy.academy_name} (${result.rows.length}개)`);
    
    res.json({
      success: true,
      submissions: result.rows
    });

  } catch (error) {
    console.error('❌ 학원 제출 내역 조회 실패:', error);
    res.status(500).json({ error: '제출 내역 조회 실패' });
  }
});

// 학원 프로필 수정 API
app.put('/api/academy/profile', requireAcademyAuth, async (req, res) => {
  try {
    const { academyName, contactName, phone, email, password } = req.body;
    
    if (!academyName || !contactName || !phone || !email) {
      return res.status(400).json({ error: '모든 필수 항목을 입력해주세요' });
    }

    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    // 이메일 중복 체크 (자신 제외)
    const existingUser = await railwayDB.query(
      'SELECT academy_id FROM academies WHERE email = $1 AND academy_id != $2',
      [email, req.academy.academy_id]
    );
    
    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: '이미 사용 중인 이메일입니다' });
    }

    let updateQuery = `
      UPDATE academies 
      SET academy_name = $1, contact_name = $2, phone = $3, email = $4, updated_at = NOW()
    `;
    let queryParams = [academyName, contactName, phone, email];

    // 비밀번호 변경이 있는 경우
    if (password && password.trim()) {
      const hashedPassword = await bcrypt.hash(password, 10);
      updateQuery += `, password_hash = $5`;
      queryParams.push(hashedPassword);
    }
    
    updateQuery += ` WHERE academy_id = $${queryParams.length + 1} RETURNING academy_id, academy_name, contact_name, phone, email`;
    queryParams.push(req.academy.academy_id);

    const result = await railwayDB.query(updateQuery, queryParams);
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: '학원 정보를 찾을 수 없습니다' });
    }

    const updatedAcademy = result.rows[0];
    
    console.log(`✏️ 학원 정보 수정: ${academyName} (${email})`);
    
    res.json({
      success: true,
      message: '정보가 성공적으로 수정되었습니다',
      academy: {
        academy_id: updatedAcademy.academy_id,
        academy_name: updatedAcademy.academy_name,
        contact_name: updatedAcademy.contact_name,
        phone: updatedAcademy.phone,
        email: updatedAcademy.email
      }
    });

  } catch (error) {
    console.error('❌ 학원 프로필 수정 실패:', error);
    res.status(500).json({ error: '프로필 수정 중 오류가 발생했습니다' });
  }
});

// ===== 관리자 학원 관리 =====

// 학원 관리 페이지
app.get('/admin/academies', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/admin-academies.html');
});

// 승인된 번들 관리 페이지
app.get('/admin/bundles', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/admin-bundles.html');
});

// 학원 목록 조회 API
app.get('/api/admin/academies', requireAuth, logAdminActivity('VIEW_ACADEMIES'), async (req, res) => {
  try {
    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    const result = await railwayDB.query(`
      SELECT academy_id, academy_name, contact_name, phone, email, status, created_at, last_login_at
      FROM academies 
      ORDER BY created_at DESC
    `);

    console.log(`📊 학원 목록 조회: ${result.rows.length}개`);
    res.json({ academies: result.rows });
  } catch (error) {
    console.error('학원 목록 조회 실패:', error);
    res.status(500).json({ error: '학원 목록 로드 실패' });
  }
});

// 학원 승인
app.post('/api/admin/academies/:id/approve', requireAuth, logAdminActivity('APPROVE_ACADEMY'), async (req, res) => {
  try {
    const { id } = req.params;
    
    await railwayDB.query(`
      UPDATE academies 
      SET status = 'active', updated_at = NOW()
      WHERE academy_id = $1
    `, [id]);

    console.log(`✅ 학원 승인: ${id}`);
    res.json({ success: true });
  } catch (error) {
    console.error('학원 승인 실패:', error);
    res.status(500).json({ error: '승인 처리 실패' });
  }
});

// 학원 거절
app.post('/api/admin/academies/:id/reject', requireAuth, logAdminActivity('REJECT_ACADEMY'), async (req, res) => {
  try {
    const { id } = req.params;
    const { reason } = req.body;
    
    await railwayDB.query(`
      UPDATE academies 
      SET status = 'rejected', updated_at = NOW()
      WHERE academy_id = $1
    `, [id]);

    console.log(`❌ 학원 거절: ${id} (사유: ${reason})`);
    res.json({ success: true });
  } catch (error) {
    console.error('학원 거절 실패:', error);
    res.status(500).json({ error: '거절 처리 실패' });
  }
});

// 학원 정지
app.post('/api/admin/academies/:id/suspend', requireAuth, logAdminActivity('SUSPEND_ACADEMY'), async (req, res) => {
  try {
    const { id } = req.params;
    
    await railwayDB.query(`
      UPDATE academies 
      SET status = 'suspended', updated_at = NOW()
      WHERE academy_id = $1
    `, [id]);

    console.log(`⛔ 학원 정지: ${id}`);
    res.json({ success: true });
  } catch (error) {
    console.error('학원 정지 실패:', error);
    res.status(500).json({ error: '정지 처리 실패' });
  }
});

// 학원 정지 해제
app.post('/api/admin/academies/:id/activate', requireAuth, logAdminActivity('ACTIVATE_ACADEMY'), async (req, res) => {
  try {
    const { id } = req.params;
    
    await railwayDB.query(`
      UPDATE academies 
      SET status = 'active', updated_at = NOW()
      WHERE academy_id = $1
    `, [id]);

    console.log(`✅ 학원 정지 해제: ${id}`);
    res.json({ success: true });
  } catch (error) {
    console.error('학원 정지 해제 실패:', error);
    res.status(500).json({ error: '정지 해제 실패' });
  }
});

// ===== 시간표 번들 관리 API =====

// 승인된 번들 목록 조회 API (Railway DB 기반)
app.get('/api/admin/approved-bundles', requireAuth, logAdminActivity('VIEW_APPROVED_BUNDLES'), async (req, res) => {
  try {
    const { season } = req.query;
    
    if (!railwayDB) {
      return res.status(503).json({ error: '서비스 준비 중입니다' });
    }

    let query = `
      SELECT approved_bundle_id, submission_id, target_season, academy_name, 
             instructor_name, contact_name, bundle_data, session_data,
             deployed_to_supabase, approved_at, deployed_at
      FROM approved_bundles
    `;
    let queryParams = [];

    if (season) {
      query += ` WHERE target_season = $1`;
      queryParams.push(season);
    }

    query += ` ORDER BY approved_at DESC`;

    const result = await railwayDB.query(query, queryParams);
    
    // 번들과 세션 개수 계산
    const approvedBundles = result.rows.map(row => {
      const bundleData = JSON.parse(row.bundle_data);
      const sessionData = JSON.parse(row.session_data);
      
      return {
        ...row,
        bundle_count: bundleData.length,
        session_count: sessionData.length,
        bundle_data: bundleData, // 상세 정보도 포함
        session_data: sessionData
      };
    });

    // 시즌별 통계
    const seasonStats = {};
    approvedBundles.forEach(bundle => {
      const season = bundle.target_season;
      if (!seasonStats[season]) {
        seasonStats[season] = {
          total_bundles: 0,
          total_sessions: 0,
          deployed_bundles: 0,
          pending_bundles: 0
        };
      }
      
      seasonStats[season].total_bundles += bundle.bundle_count;
      seasonStats[season].total_sessions += bundle.session_count;
      
      if (bundle.deployed_to_supabase) {
        seasonStats[season].deployed_bundles += bundle.bundle_count;
      } else {
        seasonStats[season].pending_bundles += bundle.bundle_count;
      }
    });

    console.log(`📊 승인된 번들 조회: ${season || '전체'} (${approvedBundles.length}개 제출)`);
    
    res.json({
      approvedBundles,
      seasonStats,
      selectedSeason: season || null,
      totalSubmissions: approvedBundles.length
    });

  } catch (error) {
    console.error('승인된 번들 조회 실패:', error);
    res.status(500).json({ error: '승인된 번들 목록 로드 실패: ' + error.message });
  }
});

// 시즌별 Supabase 배포 API
app.post('/api/admin/deploy-season/:season', requireAuth, logAdminActivity('DEPLOY_SEASON'), async (req, res) => {
  try {
    const { season } = req.params;
    
    if (!season) {
      return res.status(400).json({ error: '시즌을 지정해주세요' });
    }

    // 해당 시즌의 미배포 번들들 조회
    const result = await railwayDB.query(`
      SELECT * FROM approved_bundles 
      WHERE target_season = $1 AND deployed_to_supabase = false
      ORDER BY approved_at DESC
    `, [season]);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: '배포할 승인된 데이터가 없습니다' });
    }

    const allBundles = [];
    const allSessions = [];

    // 모든 승인된 번들 데이터 병합
    for (const approvedBundle of result.rows) {
      const bundleData = JSON.parse(approvedBundle.bundle_data);
      const sessionData = JSON.parse(approvedBundle.session_data);
      
      allBundles.push(...bundleData);
      allSessions.push(...sessionData);
    }

    // Supabase 시즌별 테이블에 배포
    const bundleTableName = `bundles_${season.replace('.', '_')}`;
    const sessionTableName = `sessions_${season.replace('.', '_')}`;

    // 번들 배포
    const { error: bundleError } = await supabase
      .from(bundleTableName)
      .insert(allBundles);

    if (bundleError) throw bundleError;

    // 세션 배포
    const { error: sessionError } = await supabase
      .from(sessionTableName)
      .insert(allSessions);

    if (sessionError) throw sessionError;

    // approved_bundles 테이블에 배포 완료 표시
    await railwayDB.query(`
      UPDATE approved_bundles 
      SET deployed_to_supabase = true, deployed_at = NOW(), updated_at = NOW()
      WHERE target_season = $1 AND deployed_to_supabase = false
    `, [season]);

    console.log(`🚀 ${season} 시즌 Supabase 배포 완료: 번들 ${allBundles.length}개, 세션 ${allSessions.length}개`);
    
    res.json({
      success: true,
      message: `${season} 시즌이 성공적으로 배포되었습니다`,
      deployedBundles: allBundles.length,
      deployedSessions: allSessions.length,
      deployedSubmissions: result.rows.length
    });

  } catch (error) {
    console.error('시즌 배포 실패:', error);
    res.status(500).json({ error: '시즌 배포 실패: ' + error.message });
  }
});

// 시즌별 번들 통계 API
app.get('/api/admin/season-stats', requireAuth, logAdminActivity('VIEW_SEASON_STATS'), async (req, res) => {
  try {
    const { season } = req.query;
    
    if (!season) {
      return res.status(400).json({ error: '시즌을 지정해주세요' });
    }

    const tableName = `bundles_${season.replace('.', '_')}`;
    const sessionTableName = `sessions_${season.replace('.', '_')}`;
    
    // Supabase에서 시즌별 통계 조회
    const [bundlesResult, sessionsResult] = await Promise.all([
      supabase.from(tableName).select('*', { count: 'exact', head: true }),
      supabase.from(sessionTableName).select('*', { count: 'exact', head: true })
    ]);

    // 활성 번들 수 조회
    const activeBundlesResult = await supabase
      .from(tableName)
      .select('*', { count: 'exact', head: true })
      .eq('published', true);

    // 강사 수 조회
    const teachersResult = await supabase
      .from(tableName)
      .select('teacher_name');

    const uniqueTeachers = new Set(teachersResult.data?.map(b => b.teacher_name) || []).size;

    res.json({
      totalBundles: bundlesResult.count || 0,
      activeBundles: activeBundlesResult.count || 0,
      totalSessions: sessionsResult.count || 0,
      totalTeachers: uniqueTeachers,
      season: season
    });

    console.log(`📊 시즌 통계 조회: ${season} (번들: ${bundlesResult.count}, 세션: ${sessionsResult.count})`);

  } catch (error) {
    console.error('시즌 통계 조회 실패:', error);
    res.status(500).json({ error: '시즌 통계 로드 실패' });
  }
});

// 시즌별 번들 목록 API
app.get('/api/admin/bundles', requireAuth, logAdminActivity('VIEW_BUNDLES'), async (req, res) => {
  try {
    const { season, limit = 50, offset = 0 } = req.query;
    
    if (!season) {
      return res.status(400).json({ error: '시즌을 지정해주세요' });
    }

    const tableName = `bundles_${season.replace('.', '_')}`;
    const sessionTableName = `sessions_${season.replace('.', '_')}`;

    // 번들 목록 조회 (세션 수 포함)
    const bundlesResult = await supabase
      .from(tableName)
      .select(`
        bundle_id, teacher_name, subject, target_school_codes, 
        target_grade, topic, academy, region, published,
        sessions:${sessionTableName}!fk_${sessionTableName}_bundle_id(*)
      `)
      .order('updated_at', { ascending: false })
      .range(offset, offset + limit - 1);

    if (bundlesResult.error) {
      throw bundlesResult.error;
    }

    // 세션 수 추가
    const bundles = bundlesResult.data.map(bundle => ({
      ...bundle,
      session_count: bundle.sessions?.length || 0
    }));

    res.json({
      bundles: bundles,
      total: bundles.length,
      season: season
    });

    console.log(`📋 번들 목록 조회: ${season} (${bundles.length}개)`);

  } catch (error) {
    console.error('번들 목록 조회 실패:', error);
    res.status(500).json({ error: '번들 목록 로드 실패' });
  }
});

// ===== 임시 디버깅 API =====

// Railway DB 데이터 확인용 (임시)
app.get('/api/debug/submissions', requireAuth, async (req, res) => {
  try {
    if (!railwayDB) {
      return res.status(503).json({ error: 'Railway DB 연결되지 않음' });
    }

    const result = await railwayDB.query(`
      SELECT submission_id, academy_name, target_season, submitted_at, 
             LENGTH(csv_data) as csv_data_length,
             SUBSTRING(csv_data, 1, 200) as csv_preview
      FROM submissions 
      ORDER BY submitted_at DESC 
      LIMIT 3
    `);

    res.json({
      count: result.rows.length,
      submissions: result.rows
    });

  } catch (error) {
    console.error('디버깅 API 실패:', error);
    res.status(500).json({ error: error.message });
  }
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 서버 시작: http://localhost:${PORT}`);
  console.log(`📊 Supabase URL: ${SUPABASE_URL ? 'Connected' : 'Not connected'}`);
  console.log(`🗃️ Railway DB: ${process.env.DATABASE_URL ? 'Connected' : 'Not connected'}`);
});