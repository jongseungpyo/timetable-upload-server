const express = require('express');
const multer = require('multer');
const csv = require('csv-parser');
const { createClient } = require('@supabase/supabase-js');
const cors = require('cors');
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

// 미들웨어
app.use(cors());
app.use(express.json());
app.use(express.static('public'));

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

// 기본 라우트
app.get('/', (req, res) => {
  res.send(`
    <h1>시간표 데이터 업로드 서버</h1>
    <p>CSV 파일을 업로드하여 Supabase에 데이터를 추가할 수 있습니다.</p>
    <form action="/api/upload-csv" method="post" enctype="multipart/form-data">
      <input type="file" name="csvFile" accept=".csv" required>
      <label>
        <input type="checkbox" name="clearExisting" value="true"> 기존 데이터 삭제 후 업로드
      </label>
      <button type="submit">업로드</button>
    </form>
  `);
});

// 서버 시작
app.listen(PORT, () => {
  console.log(`🚀 서버 시작: http://localhost:${PORT}`);
  console.log(`📊 Supabase URL: ${process.env.SUPABASE_URL}`);
});