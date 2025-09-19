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

**School Mapping System:**
- `school_mapping_complete.json`: Contains NEIS school code mappings
- Functions: `convertSchoolNamesWithEducationOffice()`, `findSchoolCodeByOffice()`
- Supports education office-based lookup for accurate school code conversion

**Data Flow:**
- CSV/Web submissions → `submissions` table (pending status)
- Admin approval → `approved_bundles` table (with season info)
- Season deployment → Supabase `bundles_YYYY_Q` and `sessions_YYYY_Q` tables

**Admin Interface Routes:**
- `/admin/dashboard` - Main admin dashboard with statistics
- `/admin/submissions` - Review pending submissions
- `/admin/bundles` - Manage approved bundles and deploy to Supabase
- `/admin/academies` - Manage academy registrations

## Environment Variables

Required variables (see `.env.example`):
- `SUPABASE_URL`, `SUPABASE_SERVICE_ROLE_KEY`: Supabase connection
- `DATABASE_URL`: Railway PostgreSQL connection
- `ADMIN_SECRET`, `SESSION_SECRET`, `JWT_SECRET`: Security keys

## Important Files

- `server.js`: Main Express server with all routes and database logic
- `school_mapping_complete.json`: School name to NEIS code mappings
- `public/`: Static HTML files for admin and public interfaces
- `src/styles.css`: TailwindCSS source file

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