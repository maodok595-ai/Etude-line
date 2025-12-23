# Étude LINE

## Overview
Étude LINE is an educational web application built with FastAPI, designed for professors to share content (courses, exercises, solutions) with students. The platform features content organized hierarchically by university, field, level, semester, subject, and chapter. It includes a complete authentication system, robust content management, and is available as an installable Progressive Web App (PWA). The project aims to facilitate seamless educational content dissemination and access, enabling students to register and access all content freely.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, featuring a modern, responsive design with CSS Grid and Flexbox and a gradient color scheme. Key interfaces include dashboards for Professors, Students, and Admins, offering consistent branding, interactive content views, color-coded level cards, and icon-based actions. Admin panels feature consistent button-based forms, animated transitions, real-time search, and detailed student information display. All admin dashboard lists and individual user details are collapsible by default for a clean interface. University statistics are presented in compact, color-coded cards. The homepage includes a redesigned student registration flow with animations. The application is fully responsive for mobile, tablet, and PC, with specific optimizations for forms, notification centers, and dashboards, ensuring touch-friendly elements and readable typography across devices. Scroll position and active tabs are preserved across form submissions in professor and admin dashboards to maintain user context. Semester headers in the professor dashboard are visually distinct with consistent violet/purple styling. The desktop interface features professional full-width optimization with responsive breakpoints at 1400px, 1600px, 1920px, and 2560px (4K), utilizing 95-98% of screen width with progressive scaling of padding, fonts, and element sizes for optimal use of ultra-wide displays. All collapsible sections (e.g., student lists, statistical cards) are closed by default on page load for a cleaner interface. Unwanted automatic scrolling has been eliminated across the application, especially after form submissions or button clicks, to prevent loss of user context. Toast notifications are used for success/error messages, appearing in a fixed position without forcing page scrolls. Images and videos are displayed respecting their original aspect ratio, with responsive adjustments for different screen sizes. The file reader offers a continuous scroll mode for PDFs on mobile for a more natural reading experience. A dedicated secondary administrator theme uses a full violet color scheme with glassmorphism effects for clear role distinction.

### Technical Implementations
- **Authentication & Authorization**: `bcrypt` for password hashing, `itsdangerous` for secure cookie-based session management, and role-based access control.
- **Hierarchical Access Control**: Students can only view chapters from their current level and all lower levels within their filière, enforced by SQL-level filtering. Professors have full access within their assigned subject.
- **User & Content Management**: Separate models for professors and students, with content hierarchically organized.
- **University-Based Administration**: Administrators are assigned to specific universities, restricting access to institutional data, with a main administrator having global access.
- **Data Filtering**: Professors can only create content within their assigned university, and dashboards dynamically filter data based on user roles and affiliations.
- **Complete Cascade Deletion**: A comprehensive system with specialized helper functions ensures transaction-safe, permanent removal of all associated data when an entity (chapter, subject, professor, student, filière, UFR, university, secondary administrator) is deleted, including uploaded files, comments, and notifications.
- **Search Functionality**: Pure frontend, real-time, case-insensitive search across admin and professor dashboards for various entities, including real-time chapter search for students/professors and live filtering of dropdown options in admin creation forms.
- **Performance Optimization**: Comprehensive performance optimizations including:
  - **Database**: Database-based migration detection, database indexes on all foreign key columns, composite index on notifications table. Query optimization eliminates N+1 queries in admin dashboard (54+ queries reduced to ~3-5) and uses eager loading for professors. SQL aggregations are used for admin statistics.
  - **Network Optimization**: GZip compression middleware (70-80% payload size reduction). Cache-Control headers: 1-hour caching for static files, no-cache for dynamic content.
  - **Frontend**: Image optimization (PNG to WebP with lazy loading), notification polling reduced from 3 seconds to 30 seconds.
  - **JavaScript Scope**: All interactive functions exposed to global scope via `window` object to fix `onclick` handler accessibility issues.
- **Progressive Web App (PWA)**: Full PWA implementation with a web app manifest, service worker for intelligent caching (cache-first for static, network-only for API, network-only with offline fallback for dashboards), offline fallback page, PWA/iOS meta tags, and a custom, persistent installation banner. Cache version v10 with automatic cleanup. iOS icon issues corrected by using `apple-touch-icon` and proper sizing. Simplified iOS PWA installation guide to focus only on Safari instructions.
- **Interactive Comment System**: Real-time commenting with a `Commentaire` database model, RESTful API endpoints, permission-based deletion (author-only), visual differentiation for user roles, XSS protection, and reply functionality. Unified JSON-based API communication and enhanced error handling.
- **Admin Auto-Provisioning**: Automatic creation of a default main administrator at startup.
- **Administrator Edit Capability**: Main administrator can modify usernames and passwords for professors and secondary administrators, with duplicate username validation and automatic update of associated chapters for professors.
- **Notification System**: Real-time notification system with a `Notification` database model, RESTful API, auto-notifications for new content, a UI notification center with unread counters, read/unread states, and individual/bulk deletion. Native push notifications with custom sound and vibration are implemented via the Service Worker API, including PWA badge API integration for unread counts on the app icon.
- **University-Specific Feature Control System**: Each university has independent control over key features (e.g., download buttons visibility, academic progression activation) through the `ParametreUniversite` model. Administrators can toggle these features via the admin dashboard, with main administrators having cross-university management capabilities.
- **Academic Progression Hierarchy System**: Comprehensive system for managing student advancement between academic levels and programs, defined by administrators using `PassageHierarchy` model. Includes admin interface for hierarchy management, real-time statistics, student choice validation with confirmation dialogs, and permanent tracking of progression history (`StudentPassage` model).
- **Rich Scientific Content Editor**: Integration of Quill.js WYSIWYG editor with MathJax for LaTeX equations, native tables, and Chart.js for interactive graphs, allowing professors to create rich pedagogical content without technical knowledge. This utilizes CDN libraries for Quill.js, MathJax, and Chart.js, with custom buttons for equation and chart insertion. Content is stored as HTML and rendered safely.
- **File Reader Improvements**: Files now open within the integrated reader (not new tabs), `window.history.back()` ensures correct navigation. Security has been enhanced against Path Traversal and Stored XSS vulnerabilities using path normalization, `is_relative_to()` checks, and DOM API for secure element creation.
- **Scheduled Online Courses with Jitsi**: Complete system for professors to schedule live online courses using Jitsi video conferencing:
  - **ScheduledCourse Model**: Database table storing course scheduling details (filière, niveau, semestre, matière, date, heure, durée, Jitsi link, notification flags).
  - **Automatic Jitsi Link Generation**: Links are generated with format `https://meet.jit.si/etudeline-{niveau}-{filiere}-{semestre}-{matiere}-{date}-{heure}`.
  - **REST API Endpoints**: 
    - `POST /courses/schedule` - Schedule a new course
    - `GET /courses/upcoming` - Get all upcoming courses (filtered by student's filière/niveau)
    - `GET /courses/prof/{prof_id}` - Get courses by professor
    - `GET /courses/my` - Get current professor's courses
    - `PUT /courses/{course_id}` - Update a course
    - `DELETE /courses/{course_id}` - Delete a course
  - **Automatic Notification System**: Background tasks send notifications to eligible students at 24h, 1h, and course start time. Uses `threading.Timer` with daemon threads.
  - **Startup Rescheduling**: On server restart, pending notifications are automatically rescheduled from the database.
  - **UI Page**: `/courses/view` displays scheduled courses with role-aware interface (professors can create, all users can view and join).

### System Design Choices
- **Monolithic Architecture**: FastAPI handles all backend logic, database interactions, and API endpoints.
- **Session Management**: Cookie-based sessions with `itsdangerous` for secure tokens and automatic role detection.
- **Route Protection**: Dependency injection for automated authentication and authorization.
- **Production Deployment**: Optimized for Render deployment with dynamic port configuration, automatic production/development mode detection, disabled reload in production, and Gunicorn with Uvicorn workers for better stability.

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
- **PostgreSQL**: Persistent relational database (Replit for development, Render PostgreSQL for production).
- **SQLAlchemy**: ORM for database operations.
- **psycopg2-binary**: PostgreSQL adapter for Python.
- **alembic**: Database migration tool.
- **Data Persistence**: Local `uploads/` directory for development, Render Disk for production (for uploaded files). University logos are stored directly in PostgreSQL as binary data.

### Utility Dependencies
- **python-multipart**: For handling form data and file uploads.
- **Pillow**: For image manipulation (e.g., resizing PWA icons).

### Environment Configuration
- **SECRET_KEY**: Essential environment variable for session security.
- **DATABASE_URL**: PostgreSQL connection URL.
- **ADMIN_USERNAME**: Main administrator username.
- **ADMIN_PASSWORD**: Main administrator password.
- **SESSION_SECRET**: Secret key for session signing.
- **PYTHON_VERSION**: Specifies Python version (e.g., 3.11.2).
- **ENVIRONMENT**: Optional, detects automatically.

### File System Dependencies
- **Upload Storage**: Local `uploads/` directory for course materials in development. In production, requires Render Disk mounted at `/opt/render/project/src/uploads` for persistence across redeploys.

### Deployment Configuration
- **render.yaml**: Blueprint for automatic Render deployment setup.
- **Production Start Command**: `uvicorn main:app --host 0.0.0.0 --port $PORT`.
- **Build Command**: `pip install -r requirements.txt`.