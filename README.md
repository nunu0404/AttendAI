# AttendAI

모바일 QR·WebAuthn 기반 출석 관리 시스템입니다. 대시보드에서 세션을 생성하고, 핸드폰으로 QR을 스캔해 생체 인증을 거친 뒤 자동으로 출석을 기록합니다. Gmail 연동으로 공결 메일을 불러와 CSV에 반영할 수 있습니다.

## 주요 기능
- **실시간 QR 보드**: 세션 시작 시 15초 주기로 갱신되는 QR 코드 발급.
- **WebAuthn 출석**: 기기 등록 및 생체 인증 완료 후 자동 출석 처리.
- **Gmail 공결 수집**: Gemini 기반 필터링으로 공결·병결 메일만 CSV에 반영.
- **대시보드 관리**  
  - 의심 출석 분석 
  - 임의 출석/공결 입력 및 삭제  
  - 세션/전체 출석·공결 CSV 다운로드  
  - 공결 목록 페이지네이션
- **네트워크 제한(옵션)**: `CHECKIN_ALLOWED_SUBNETS` 환경변수로 허용 IP 대역 지정.

## 실행 방법

### 1. 환경 설정
```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 2. 환경 변수
필요에 따라 아래 항목을 `.env`나 PowerShell에 설정합니다.
```
# QR 베이스 URL 강제 (예: ngrok HTTPS 주소)
CHECKIN_BASE_URL=https://your-domain.ngrok-free.dev

# 허용 네트워크 (쉼표로 구분된 CIDR 또는 단일 IP)
CHECKIN_ALLOWED_SUBNETS=192.168.137.0/24,10.0.0.5

# Gmail/Gemini 설정
GEMINI_API_KEY=...
GEMINI_MODEL=models/gemini-2.0-flash
```

### 3. 서버 실행
```bash
.venv\Scripts\activate
uvicorn backend.app:app --reload --host 0.0.0.0 --port 8000
```

브라우저에서 `http://localhost:8000/dashboard`로 접속하면 대시보드를 확인할 수 있습니다. QR 보드는 `/qrboard?session_id=...`, 체크인 페이지는 `/checkin?t=...`으로 열립니다.

## Gmail 공결 수집
대시보드의 “Gmail 불러오기” 버튼을 누르면 최근 메일을 읽어 공결·병결 메일만 저장합니다. Gemini가 없으면 휴리스틱으로 동작합니다.

## 폴더 구조
```
backend/
  app.py             # FastAPI 메인 앱
  gmail_ingest.py    # Gmail 공결 수집 스크립트
  static/, exports/
frontend/
  static/            # JS/CSS
  *.html             # 대시보드·체크인 페이지
```

## 기여
PR 환영합니다. 주요 변경 사항은 `backend/app.py`와 `frontend/static/dashboard.js`에서 관리됩니다.
