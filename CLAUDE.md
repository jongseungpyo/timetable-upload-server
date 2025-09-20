# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Code Collaboration Rules

### Main Principle
- **Only modify code after explicit user approval**
- **Never modify anything before user confirmation**

### Process
1. User makes request →
2. If unclear or incomplete, always ask questions and present options →
3. Only when user says "confirmed" or "proceed as planned" →
4. Then modify only the approved parts

### Prohibited Actions
- No logic changes without user confirmation
- No unnecessary code/file creation without user confirmation
- No automatic refactoring or optimization in intermediate steps
- **No environment variable hardcoding - always use .env files**
- **No mock data or fake implementations**
- **No 'any' type usage**
- **No direct DOM manipulation**
- **No console.log statements in production code**

### Core Keywords to Remember
> "Execute after user approval"
> "Don't modify user instructions arbitrarily"
> "Ask questions and get confirmation for all intermediate steps"

## Project Overview

This is a Korean timetable upload server for academies (private institutes) that processes CSV data submissions and manages them through approval workflows. The system handles timetable data from instructors, converts school names to NEIS codes, and deploys approved data to Supabase.

## Architecture

**Database Architecture:**
- **Railway PostgreSQL**: Primary database for submissions, admin users, academies, and approved bundles
- **Supabase**: Final production database for deployed timetable data, with season-specific tables (e.g., `bundles_2025_4`, `sessions_2025_4`)

**Core Workflow:**
1. Academy registration → Admin approval → Active status
2. Timetable submission via web interface → Review queue (Railway DB)
3. Admin approval → `approved_bundles` table → Supabase deployment

**Authentication Systems:**
- **Admin users**: Session-based authentication with bcrypt passwords in `admin_users` table
- **Academy users**: JWT token-based authentication stored in `academies` table

## Development Commands

```bash
# Install dependencies
npm install

# Development (auto-reload server)
npm run dev

# Build CSS (development with watch)
npm run build-css

# Build CSS (production minified)
npm run build-css-prod

# Production start
npm start
```

## Key Components

**School Mapping System (Updated):**
- `public/school_mappings/`: Education office-specific mapping files (17 files, 1.8MB total)
- Format: `B10_서울.json`, `R10_경북.json`, etc.
- Functions: `convertSchoolNamesWithEducationOffice()`, `loadEducationOfficeMapping()`
- Supports original school names + abbreviations (e.g., "세화고등학교", "세화고")
- Client-side lazy loading with caching for real-time validation

**CSV Processing System:**
- **RFC 4180 Compliant Parser**: State machine-based with encoding detection (UTF-8 BOM, EUC-KR)
- **Strict Header Validation**: 17 columns enforced, Monday-first weekday order
- **Real-time School Validation**: Live error highlighting for typos and invalid school names
- **Multiple School Support**: "서울고, 상문고" format with individual validation
- **Union Class Exception**: "연합반" always valid regardless of education office

**Weekday System (Monday=0):**
- Unified across frontend, backend, and admin interfaces
- 0=Monday, 1=Tuesday, ..., 6=Sunday throughout the system
- Admin interfaces updated to display Monday-first order

**Data Flow:**
- CSV/Web submissions → RFC 4180 parsing → Real-time validation → `submissions` table (pending)
- Admin review → Server conversion with education office mappings → `approved_bundles` table
- Individual bundle deployment → Supabase `bundles_YYYY_Q` and `sessions_YYYY_Q` tables

**Admin Interface Routes:**
- `/admin/dashboard` - Main dashboard with unified accordion sidebar
- `/admin/submissions` - Review submissions with real-time conversion preview
- `/admin/bundles` - Individual bundle management (deploy/delete) with season clearing
- `/admin/academies` - Academy registration approval
- `/admin/current_bundles` - Deployed bundle statistics and monitoring

**Unified Admin Navigation:**
- Accordion structure: 대시보드, 제출검토(미검토/승인/거절), 학원가입승인, 번들관리(승인된번들/번들현황)
- Consistent sidebar across all admin pages with smooth animations
- Mobile-responsive design considerations

## Environment Variables

Required variables (see `.env.example`):
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`: Supabase connection
- `DATABASE_URL`: Railway PostgreSQL connection
- `ADMIN_SECRET`, `SESSION_SECRET`, `JWT_SECRET`: Security keys

## Important Files

- `server.js`: Main Express server with all routes and database logic
- `public/school_mappings/`: Education office-specific mapping files (B10_서울.json, etc.)
- `public/index.html`: Main submission interface with RFC 4180 CSV parser
- `public/admin-*.html`: Admin interface pages with unified accordion navigation
- `src/styles.css`: TailwindCSS source file

## Recent Major Updates

**School Mapping System Overhaul:**
- Migrated from centralized `school_mapping_complete.json` to education office-specific files
- Implemented regex-based school abbreviation generation with priority rules
- Added support for multiple school names ("서울고, 상문고") and union classes ("연합반")

**CSV Processing Enhancement:**
- Implemented RFC 4180 compliant parser with proper encoding detection
- Added strict header validation (17 columns, Monday-first order)
- Real-time school name validation with education office mapping
- Debounced preview updates and visual error feedback

**Weekday System Unification:**
- Changed from Sunday=0 to Monday=0 throughout entire system
- Updated frontend input, backend storage, admin displays, and session formatting
- Requires Supabase data migration for existing seasons

**Admin Interface Improvements:**
- Unified accordion navigation across all admin pages
- Individual bundle management (deploy/delete buttons per bundle)
- Supabase season clearing functionality for data migration
- Session display format standardization (월09:00-12:00 format)

## Development Notes

**Database Initialization:**
- Railway PostgreSQL tables are auto-created on server startup via `initializeRailwayDB()`
- Default admin account: `admin/admin123` (created automatically)
- Test academy account: `test@timebuilder.com/test123`

**Security Features:**
- Helmet.js with CSP configuration allowing inline scripts for HTML interfaces
- Rate limiting on API endpoints and admin login
- Input validation and row limits (300 rows max) for abuse prevention

## Testing

No formal test framework is configured. Manual testing is done through the web interfaces.

**Test Accounts:**
- Admin: `admin/admin123`
- Academy: `test@timebuilder.com/test123` (requires admin approval)

## Data Migration Notes

**Weekday System Migration:**
Due to the weekday system change (Sunday=0 → Monday=0), existing Supabase data requires migration:

1. **Clear Legacy Data**: Use "Supabase 시즌 초기화" in `/admin/bundles`
2. **Clean Problem Data**: Delete bundles with TEMP codes using individual delete buttons
3. **Redeploy Clean Data**: Use individual deploy buttons for properly converted bundles
4. **Verify Results**: Check `/admin/current_bundles` for accumulated deployments

**APIs for Data Management:**
- `POST /api/admin/clear-season/:season` - Clear entire season from Supabase
- `POST /api/admin/deploy-bundle/:bundleId` - Deploy individual bundle
- `DELETE /api/admin/approved-bundles/:bundleId` - Remove problematic bundle

**Mapping File Structure:**
```
public/school_mappings/
├── B10_서울.json (172KB)
├── J10_경기.json (298KB) 
├── R10_경북.json (113KB)
└── ... (17 files total)
```

Each file contains:
```json
{
  "school_to_code": {
    "세화고등학교": "B10_7010197",
    "세화고": "B10_7010197"
  },
  "code_to_school": {
    "B10_7010197": "세화고등학교"
  }
}
```