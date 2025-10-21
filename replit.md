# Étude LINE

## Overview
Étude LINE is an educational web application built with FastAPI, designed for professors to share content (courses, exercises, solutions) with students. The platform features content organized hierarchically by university, field, level, semester, subject, and chapter. It includes a complete authentication system, robust content management, and is available as an installable Progressive Web App (PWA). The project aims to facilitate seamless educational content dissemination and access, enabling students to register and access all content freely.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, featuring a modern, responsive design with CSS Grid and Flexbox and a gradient color scheme. Key interfaces include dashboards for Professors, Students, and Admins, offering consistent branding, interactive content views, color-coded level cards, and icon-based actions. Admin panels feature consistent button-based forms, animated transitions, real-time search, and detailed student information display. All admin dashboard lists and individual user details are collapsible by default for a clean interface. University statistics are presented in compact, color-coded cards. The homepage includes a redesigned student registration flow with animations. The application is fully responsive for mobile, tablet, and PC, with specific optimizations for forms, notification centers, and dashboards, ensuring touch-friendly elements and readable typography across devices. Scroll position and active tabs are preserved across form submissions in professor and admin dashboards to maintain user context. Semester headers in the professor dashboard are visually distinct with consistent violet/purple styling. The desktop interface features professional full-width optimization with responsive breakpoints at 1400px, 1600px, 1920px, and 2560px (4K), utilizing 95-98% of screen width with progressive scaling of padding, fonts, and element sizes for optimal use of ultra-wide displays.

### Technical Implementations
- **Authentication & Authorization**: `bcrypt` for password hashing, `itsdangerous` for secure cookie-based session management, and role-based access control.
- **Hierarchical Access Control**: Students can only view chapters from their current level and all lower levels within their filière, enforced by SQL-level filtering. Professors have full access within their assigned subject.
- **User & Content Management**: Separate models for professors and students, with content hierarchically organized.
- **University-Based Administration**: Administrators are assigned to specific universities, restricting access to institutional data, with a main administrator having global access.
- **Data Filtering**: Professors can only create content within their assigned university, and dashboards dynamically filter data based on user roles and affiliations.
- **Complete Cascade Deletion**: A comprehensive system with specialized helper functions ensures transaction-safe, permanent removal of all associated data when an entity (chapter, subject, professor, student, filière, UFR, university, secondary administrator) is deleted, including uploaded files, comments, and notifications.
- **Search Functionality**: Pure frontend, real-time, case-insensitive search across admin and professor dashboards for various entities, including real-time chapter search for students/professors and live filtering of dropdown options in admin creation forms.
- **Performance Optimization**: Comprehensive performance optimizations including database-based migration detection (checking admin count instead of local files to ensure Render compatibility), image optimization (PNG to WebP with lazy loading), database indexes on all foreign key columns (`universite_id`, `ufr_id`, `filiere_id`, `matiere_id`, `created_by`) with composite index on notifications table (`destinataire_id`, `lue`), eager loading with `joinedload()` to eliminate N+1 queries in professor dashboard, SQL aggregations for admin statistics instead of Python loops, improved error logging for session management, and notification polling reduced from 3 seconds to 30 seconds (10x reduction in API calls) for student and professor dashboards.
- **Progressive Web App (PWA)**: Full PWA implementation with a web app manifest, service worker for intelligent caching with route-specific strategies (static assets use cache-first, API routes use network-only to prevent stale data, dashboards use network-only with offline fallback to ensure real-time updates), offline fallback page, PWA/iOS meta tags, and a custom, persistent installation banner. Cache version v10 with automatic cleanup of old caches.
- **Interactive Comment System**: Real-time commenting with a `Commentaire` database model, RESTful API endpoints, permission-based deletion (author-only), visual differentiation for user roles, XSS protection, and reply functionality. Unified JSON-based API communication and enhanced error handling are implemented.
- **Admin Auto-Provisioning**: Automatic creation of a default main administrator at startup.
- **Administrator Edit Capability**: Main administrator can modify usernames and passwords for professors and secondary administrators, with duplicate username validation and automatic update of associated chapters for professors.
- **Notification System**: Real-time notification system with a `Notification` database model, RESTful API, auto-notifications for new content, a UI notification center with unread counters, read/unread states, and individual/bulk deletion. Native push notifications with custom sound and vibration are implemented via the Service Worker API, including PWA badge API integration for unread counts on the app icon.
- **University-Specific Feature Control System**: Each university has independent control over key features through the `ParametreUniversite` model. Administrators can independently enable/disable downloads and academic progression features for their specific university. The system includes automatic migration of legacy global parameters to per-university settings, ensuring backward compatibility. Features controlled per university: (1) Download buttons visibility across all dashboards - when disabled, download buttons are hidden for students and professors of that university while maintaining view/read functionality. (2) Academic progression system activation - controls whether students of that university can access the passage feature. API endpoints (`/api/parametres/telechargements`, `/api/parametres/passage-classe`) automatically filter by the user's university and accept `universite_id` as a string parameter for main administrator cross-university management. The admin dashboard displays "⚙️ Contrôles des fonctionnalités" with university name, providing real-time toggle controls. Main administrators see a university selector dropdown to manage any university's settings. Settings are persisted in the database with automatic provisioning for new universities. The student dashboard uses a DOM mutation observer to apply download settings to dynamically loaded content. Main administrators can manage settings for any university, while regular administrators are restricted to their assigned university.
- **Academic Progression Hierarchy System**: Comprehensive system for managing student advancement between academic levels and programs. Administrators define advancement paths (`PassageHierarchy` model) specifying valid transitions (e.g., L1 MPCI → L2 PC/SID/MPI). The admin interface includes a "Passage dans la même filière" checkbox that simplifies creation of same-filière progression rules (e.g., L1 MPCI → L2 MPCI) by automatically synchronizing departure and arrival filières, with client-side validation ensuring the arrival level is higher than departure level. Same-filière passages are visually differentiated in the list view with a blue "MÊME FILIÈRE" badge and compact display format. Students can choose their next level through a dedicated interface with a mandatory "Redoublant" (repeat year) option always available. The system tracks all progression history (`StudentPassage` model), updates student records with new level/filière, and sends automatic notifications. Features include admin dashboard with hierarchy management, real-time statistics (total passages, by type), student choice validation with confirmation dialogs, and permanent tracking of all decisions. The `statut_passage` column in the `Etudiant` model tracks current status (en_attente/validé/redoublant). Each university can independently enable/disable the passage feature via `ParametreUniversite` model.

### System Design Choices
- **Monolithic Architecture**: FastAPI handles all backend logic, database interactions, and API endpoints.
- **Session Management**: Cookie-based sessions with `itsdangerous` for secure tokens and automatic role detection.
- **Route Protection**: Dependency injection for automated authentication and authorization.
- **Production Deployment**: Optimized for Render deployment with dynamic port configuration (PORT environment variable), automatic production/development mode detection (RENDER environment variable), disabled reload in production, and Gunicorn with Uvicorn workers for better stability. See `GUIDE_DEPLOIEMENT_RENDER.md` for complete deployment instructions.

## External Dependencies

### Core Framework Dependencies
- **FastAPI**: Asynchronous web framework.
- **Uvicorn**: ASGI server.
- **Jinja2**: Server-side template engine.
- **Pydantic**: Data validation and settings.

### Security Dependencies
- **passlib**: Password hashing library.
- **bcrypt**: Bcrypt algorithm.
- **itsdangerous**: Cryptographic signing for session cookies.

### Database Dependencies
- **PostgreSQL**: Persistent relational database provided by Replit for development, and Render PostgreSQL (paid) for production deployment.
- **SQLAlchemy**: ORM for database operations.
- **psycopg2-binary**: PostgreSQL adapter for Python.
- **alembic**: Database migration tool.
- **Data Persistence**: 
  - **Development (Replit)**: All data stored in Replit PostgreSQL database and local `uploads/` directory.
  - **Production (Render)**: Application data stored in Render PostgreSQL (external database). Uploaded files (videos, PDFs, documents) require Render Disk configuration to persist across deployments (see `RENDER_DISK_SETUP.md`).

### Utility Dependencies
- **python-multipart**: For handling form data and file uploads.

### Environment Configuration
- **SECRET_KEY**: Essential environment variable for session security.

### File System Dependencies
- **Upload Storage**: 
  - **Development**: Local `uploads/` directory for course materials.
  - **Production (Render)**: Requires Render Disk mounted at `/opt/render/project/src/uploads` to prevent file loss on redeploys. Configuration guide: `GUIDE_DEPLOIEMENT_RENDER.md`.

### Deployment Configuration
- **render.yaml**: Blueprint configuration file for automatic Render deployment setup with web service, PostgreSQL database, and persistent disk for uploads.
- **Production Start Command**: `gunicorn main:app --workers 4 --worker-class uvicorn.workers.UvicornWorker --bind 0.0.0.0:$PORT --timeout 120`
- **Build Command**: `pip install -r requirements.txt`
- **Required Environment Variables**: DATABASE_URL, SECRET_KEY, SESSION_SECRET, PYTHON_VERSION (3.11.2)