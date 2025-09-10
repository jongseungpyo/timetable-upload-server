const express = require('express');
const multer = require('multer');
const csv = require('csv-parser');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
const session = require('express-session');
const bcrypt = require('bcrypt');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

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

// Supabase 클라이언트 설정
const supabase = createClient(SUPABASE_URL, SUPABASE_KEY);

// 보안 미들웨어
app.use(helmet()); // 기본 보안 헤더

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

// 세션 관리
app.use(session({
  secret: process.env.SESSION_SECRET || 'fallback-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production', // HTTPS에서만
    httpOnly: true, // XSS 방지
    maxAge: 24 * 60 * 60 * 1000 // 24시간
  }
}));

// 기본 미들웨어
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// 관리자 인증 미들웨어
function requireAuth(req, res, next) {
  if (!req.session.isAdmin) {
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: '인증이 필요합니다' });
    }
    return res.redirect('/admin/login');
  }
  
  // 세션 만료 체크 (24시간)
  const loginTime = new Date(req.session.loginTime);
  const now = new Date();
  if (now - loginTime > 24 * 60 * 60 * 1000) {
    req.session.destroy();
    if (req.path.startsWith('/api/')) {
      return res.status(401).json({ error: '세션이 만료되었습니다' });
    }
    return res.redirect('/admin/login');
  }
  
  next();
}

// 관리자 활동 로깅 미들웨어
function logAdminActivity(action) {
  return (req, res, next) => {
    const logEntry = {
      timestamp: new Date().toISOString(),
      action: action,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      sessionId: req.session.id
    };
    
    console.log('🔍 Admin Activity:', logEntry);
    
    // DB에 로그 저장 (선택적)
    supabase.from('admin_logs').insert(logEntry).catch(console.error);
    
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

// 메인 페이지 - 시간표 제출 폼으로 리디렉션
app.get('/', (req, res) => {
  res.sendFile(__dirname + '/public/submit.html');
});

// 관리자 직접 업로드 (기존 기능 유지)
app.get('/direct-upload', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/index.html');
});

// 시간표 제출 API
app.post('/api/submit-timetable', upload.single('csvFile'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'CSV 파일이 필요합니다' });
    }

    const submissionId = generateUUID();
    
    // CSV 데이터 파싱
    const csvContent = req.file.buffer.toString('utf-8');
    const rows = csvContent.split('\n').slice(1);
    
    const bundles = [];
    for (const row of rows) {
      if (!row.trim()) continue;
      const columns = row.split(',').map(col => col.replace(/"/g, '').trim());
      if (columns.length < 17) continue;
      
      bundles.push({
        teacher_name: columns[0],
        subject: columns[1], 
        target_school: columns[2],
        school_level: columns[3],
        target_grade: columns[4],
        topic: columns[5],
        academy: columns[6],
        region: columns[8],
        sessions: extractSessions(columns)
      });
    }

    // 제출 데이터 저장 (승인 대기 상태)
    const submission = {
      submission_id: submissionId,
      academy_name: req.body.academyName,
      instructor_name: req.body.instructorName,
      contact_name: req.body.contactName,
      phone: req.body.phone,
      email: req.body.email,
      notes: req.body.notes,
      csv_data: JSON.stringify(bundles),
      status: 'pending',
      submitted_at: new Date().toISOString()
    };
    
    // submissions 테이블에 저장 (실제 DB 반영 전)
    const { error } = await supabase.from('submissions').insert(submission);
    if (error) throw error;

    console.log(`📥 새로운 시간표 제출: ${req.body.academyName} (ID: ${submissionId})`);
    
    res.json({
      success: true,
      submissionId: submissionId,
      message: '시간표가 성공적으로 제출되었습니다. 검토 후 연락드리겠습니다.'
    });
    
  } catch (error) {
    console.error('❌ 시간표 제출 실패:', error);
    res.status(500).json({ 
      error: '제출 중 오류가 발생했습니다',
      details: error.message 
    });
  }
});

// 세션 추출 헬퍼 함수
function extractSessions(columns) {
  const sessions = [];
  const days = [9, 10, 11, 12, 13, 14, 15]; // CSV 컬럼 인덱스
  
  for (let j = 0; j < days.length; j++) {
    const timeSlot = columns[days[j]];
    if (timeSlot && timeSlot.includes('~')) {
      const [startTime, endTime] = timeSlot.split('~').map(t => t.trim());
      sessions.push({
        weekday: j,
        start_time: startTime,
        end_time: endTime
      });
    }
  }
  
  return sessions;
}

// ===== 관리자 라우트 =====

// 관리자 로그인 페이지
app.get('/admin/login', (req, res) => {
  if (req.session.isAdmin) {
    return res.redirect('/admin/dashboard');
  }
  res.sendFile(__dirname + '/public/admin-login.html');
});

// 관리자 로그인 처리  
app.post('/admin/login', adminLimiter, async (req, res) => {
  try {
    const { password } = req.body;
    const adminPassword = process.env.ADMIN_PASSWORD || 'admin123'; // 기본값
    
    if (password === adminPassword) {
      req.session.isAdmin = true;
      req.session.loginTime = new Date();
      
      console.log(`🔓 관리자 로그인: IP ${req.ip}`);
      
      res.json({ success: true });
    } else {
      console.log(`❌ 관리자 로그인 실패: IP ${req.ip}`);
      res.status(401).json({ error: '비밀번호가 틀렸습니다' });
    }
  } catch (error) {
    res.status(500).json({ error: '로그인 처리 중 오류 발생' });
  }
});

// 관리자 대시보드
app.get('/admin/dashboard', requireAuth, (req, res) => {
  res.sendFile(__dirname + '/public/admin-dashboard.html');
});

// 관리자 로그아웃
app.post('/admin/logout', (req, res) => {
  req.session.destroy();
  res.json({ success: true });
});

// 대시보드 통계 API
app.get('/api/admin/dashboard-stats', requireAuth, logAdminActivity('VIEW_DASHBOARD'), async (req, res) => {
  try {
    // 제출 현황 조회
    const { data: submissions, error: submissionError } = await supabase
      .from('submissions')
      .select('status, submitted_at, academy_name')
      .order('submitted_at', { ascending: false })
      .limit(10);

    if (submissionError) throw submissionError;

    // 전체 번들 수 조회
    const { count: totalBundles, error: bundleError } = await supabase
      .from('bundles_2025_4')
      .select('*', { count: 'exact', head: true });

    if (bundleError) throw bundleError;

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

    res.json({
      pendingSubmissions,
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

// 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 서버 시작: http://localhost:${PORT}`);
  console.log(`📊 Supabase URL: ${process.env.SUPABASE_URL}`);
});