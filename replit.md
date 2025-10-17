# Étude LINE

## Overview

Étude LINE is an educational web application built with FastAPI, designed to facilitate content sharing between professors and students. Professors can publish educational content (courses, exercises, solutions) organized hierarchically by university, field, level, semester, subject, and chapter. Students can register and access all content freely. The platform includes a complete authentication system, content management capabilities, and is available as a Progressive Web App (PWA) installable on mobile and desktop devices.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, offering a modern, responsive design using CSS Grid and Flexbox with a gradient color scheme. Key interfaces include:
- **index.html**: Landing page with role selection.
- **login.html**: Unified authentication.
- **dashboard_prof.html**: Professor's content management interface with hierarchical accordion views for chapters, color-coded level cards (L1=green, L2=blue, L3=purple, M1=orange, M2=red), and icon-based actions. Displays university logo and "BIENVENUE A L'[UNIVERSITÉ NAME]" welcome message.
- **dashboard_etudiant.html**: Student's content consumption interface with an interactive accordion for hierarchical content navigation. Displays university logo and "BIENVENUE A L'[UNIVERSITÉ NAME]" welcome message.
- **Admin Dashboards**: Modernized admin panels with consistent button-based forms, hidden by default, animated transitions, and real-time search functionality across all entity lists. Secondary admins see university logo and welcome message for their assigned university.
- **Homepage UX**: Redesigned student registration with initial welcome view, "S'inscrire" button, and smooth fade-in/fade-out animations.
- **University Branding**: All dashboards (admin, professor, student) display university branding with consistent styling:
  - Welcome message "BIENVENUE A L'[UNIVERSITÉ]" in uppercase Poppins font at the top
  - University logo centered at 150px (desktop) / 120px (mobile) with rounded corners and shadow
  - User information box below the logo with role-specific details (administrator/professor/student info)
- **Responsive Design (Oct 17, 2025)**: Fully optimized for mobile, tablet, and PC with adaptive layouts:
  - Horizontal scrollable tabs with custom scrollbar on mobile (<768px) ensuring all sections (Matières, etc.) remain accessible
  - Adaptive grid layouts: 1 column (mobile <768px), 2 columns (tablet 768px), full grid (desktop >768px)
  - Touch-optimized buttons and spacing for mobile devices (<480px)
  - Unified media queries without duplication for consistent responsive behavior

### Technical Implementations
- **Authentication & Authorization**: Utilizes bcrypt for password hashing and `itsdangerous` for secure, cookie-based session management. Supports dual registration (professors/students) and unified login with role detection.
- **User & Content Management**: Separate models for professors and students with role-based access control. Content is organized hierarchically.
- **University-Based Administration**: Administrators can be assigned to specific universities, restricting their access and management capabilities to data within that institution. A main administrator has global access. Secondary admins see filtered statistics and university-specific branding.
- **Data Filtering**: Professors can only create content within their assigned university. All dashboard views (professor and admin) dynamically filter data based on user roles and university affiliations.
- **Cascade Deletion**: Implemented manual cascade deletion for universities, UFRs, and filières to ensure all related entities (students, professors, chapters, subjects) are removed correctly.
- **Search Functionality**: Pure frontend, real-time, case-insensitive search filtering is implemented across all admin and professor dashboards for entities like admins, professors, students, universities, UFRs, filières, and matières.
- **Performance Optimization (Oct 2025)**: Implemented migration sentinel system using `.migration_done` file to prevent redundant database migrations at startup. Reduces homepage response time by 58% (0.48s → 0.20s) and database query time by 47% (2.98s → 1.57s). Migration can be forced via `MIGRATE_ON_START=true` environment variable.
- **Progressive Web App (PWA) (Oct 17, 2025)**: Full PWA implementation enabling installation on mobile/desktop devices. Features include:
  - Web App Manifest (`/static/manifest.json`) with complete metadata, branded icons (192px, 512px), and shortcuts
  - Service Worker (`/static/sw.js`) with intelligent caching strategies: cache-first for static assets, network-first for dynamic pages, network-only for API calls
  - Offline fallback page (`/static/offline.html`) with auto-refresh capabilities
  - PWA meta tags and iOS-specific tags across all templates
  - Installable from browser with "Add to Home Screen" functionality
  - Works offline with cached content when no internet connection available
- **Interactive Comment System (Oct 17, 2025)**: Real-time commenting and discussion feature for enhanced interaction between professors and students:
  - Database model `Commentaire` with author tracking, timestamps, and cascade deletion on chapter removal
  - RESTful API endpoints: GET /api/commentaires/{chapitre_id}, POST /api/commentaires, DELETE /api/commentaires/{id}
  - Permission-based deletion: users can delete their own comments, admins can delete any comment
  - Visual differentiation: professors (blue) and students (green) with clean name-only display
  - Real-time interface with async JavaScript functions for loading, posting, and deleting comments
  - XSS protection through HTML escaping and secure form submission
  - Available in both student and professor dashboards for bidirectional communication
  - Comments section appears below chapter content (courses, exercises, solutions) for contextual discussions
  - **Reply functionality**: Click "↩️ Répondre" to auto-fill "@AuthorName" in comment field with scroll-to-form. Uses data-attributes to avoid JavaScript escaping issues with special characters in names.
  - **Collapsible section (Oct 17, 2025)**: Comments section closed by default with toggle arrow (▸/▼) for cleaner interface
  - **Collapsible content sections (Oct 17, 2025)**: Cours, Exercices, Solutions sections are collapsible with clickable arrows (▸/▼), all closed by default for cleaner interface in both dashboards
- **Admin Auto-Provisioning (Oct 17, 2025)**: Automatic main admin creation at every startup to prevent credential loss when switching databases:
  - Function `create_default_admin_if_needed()` runs after table creation, independent of migration state
  - Ensures admin "kamaodo65/admin123" always exists, even when `.migration_done` prevents full migration
  - Idempotent design: checks for existing admin before creation, safe for repeated calls
  - Works with both DATABASE_URL and EXTERNAL_DATABASE_URL configurations
  - Logs "✅ Administrateur principal déjà présent" when admin exists, "✅ Administrateur principal créé" when created
- **Notification System (Oct 17, 2025)**: Real-time notification system to keep students informed of new content:
  - Database model `Notification` with type, message, recipient tracking, read status, and timestamps
  - RESTful API endpoints: GET /api/notifications, GET /api/notifications/count, PUT /api/notifications/lire-toutes, PUT /api/notifications/{id}/lire
  - Auto-notification creation when professors publish new chapters, sent to all students in relevant filière/niveau
  - UI notification center with bell icon, unread counter badge, and dropdown popup with notification list
  - Graceful error handling: notification failures don't block chapter creation
  - Visual indicators: emoji icons (📚 for new chapters), timestamp display, read/unread states
  - Click-to-mark-read functionality with real-time badge updates
  - "Tout marquer comme lu" batch action for clearing all notifications at once
  - Optimized button sizes in student dashboard (matière buttons: padding 0.6rem, font-size 1rem for cleaner interface)

### System Design Choices
- **Monolithic Architecture**: Built on FastAPI, handling all backend logic, database interactions, and API endpoints.
- **Session Management**: Cookie-based sessions with automatic role detection and `itsdangerous` for secure, tamper-proof tokens.
- **Route Protection**: Dependency injection (`current_user`) for automatic authentication and authorization checks.

## External Dependencies

### Core Framework Dependencies
- **FastAPI**: Asynchronous web framework.
- **Uvicorn**: ASGI server.
- **Jinja2**: Server-side template engine.
- **Pydantic**: Data validation and settings.

### Security Dependencies
- **passlib**: Password hashing library (v1.7.4).
- **bcrypt**: Bcrypt algorithm (v4.1.3, compatible with passlib).
- **itsdangerous**: Cryptographic signing for session cookies.

### Database Dependencies
- **PostgreSQL**: External relational database (configured via `EXTERNAL_DATABASE_URL`).
- **SQLAlchemy**: ORM for database operations (v2.0.43).
- **psycopg2-binary**: PostgreSQL adapter for Python (v2.9.10).
- **alembic**: Database migration tool (v1.16.5).

### Utility Dependencies
- **python-multipart**: For handling form data and file uploads.

### Environment Configuration
- **SECRET_KEY**: Essential environment variable for session security.

### File System Dependencies
- **Upload Storage**: Local `uploads/` directory for course materials.