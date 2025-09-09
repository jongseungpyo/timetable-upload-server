# 시간표 데이터 업로드 서버

학원에서 제출한 CSV 데이터를 처리하여 Supabase에 업로드하는 서버입니다.

## 🚀 기능

- **CSV 파일 업로드**: 웹 인터페이스를 통한 파일 업로드
- **자동 변환**: 학교명 → NEIS 학교코드 자동 변환
- **Bulk Insert**: 대량 데이터 효율적 처리
- **데이터 검증**: 필수 필드 체크 및 오류 처리

## 📊 CSV 형식

```csv
강사명,과목,대상 학교,초중고,대상 학년,주제,출강 학원,개강 일자,지역,일요일,월요일,화요일,수요일,목요일,금요일,토요일,시즌
표종승,물리,세화고,고등학교,2,내신 대비반,처음과 끝 학원,,반포,,,,,,9:00 ~ 12:00,,2025.4
```

## 🔧 로컬 개발

```bash
npm install
npm run dev
```

## 🌐 Railway 배포

1. Railway 계정 생성
2. GitHub 레포지토리 연결  
3. 환경변수 설정
4. 자동 배포

## 📝 환경변수

```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your_anon_key
SUPABASE_SERVICE_ROLE_KEY=your_service_role_key
PORT=3000
ADMIN_SECRET=your_admin_password
```

## 🎯 API 엔드포인트

- `GET /` - 업로드 인터페이스
- `POST /api/upload-csv` - CSV 업로드 처리