# Étude LINE

## Overview
Étude LINE is an educational web application built with FastAPI, enabling professors to share content (courses, exercises, solutions) with students. Content is hierarchically organized by university, field, level, semester, subject, and chapter. Students can register and access all content freely. The platform features a complete authentication system, robust content management, and is available as an installable Progressive Web App (PWA) for mobile and desktop. The project aims to facilitate seamless educational content dissemination and access.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, featuring a modern, responsive design with CSS Grid and Flexbox and a gradient color scheme. Key interfaces include:
- **Dashboards (Professor, Student, Admin)**: Consistent university branding (logo, welcome message), interactive accordion views for content, color-coded level cards (L1-M2), and icon-based actions. Admin panels have consistent button-based forms, animated transitions, and real-time search.
- **Homepage UX**: Redesigned student registration with initial welcome view, "S'inscrire" button, and smooth fade-in/fade-out animations.
- **Responsive Design**: Fully optimized for mobile, tablet, and PC across various breakpoints (480px to 1600px+). This includes stacked navigation, compact typography, optimized spacing, touch-friendly buttons, and hover effects on larger screens, with specific enhancements for all dashboards and the homepage.
- **Professor Chapter Creation Form - Mobile Pro (Oct 17, 2025)**: The chapter creation form features a professional mobile-first design with stable CSS classes (form-header, section-cours, section-exercices, section-solutions, form-warning, form-note) ensuring robust responsive behavior at 600px and 480px breakpoints. Header elements stack vertically, buttons span full width for touch accessibility, and colored sections (cours/exercices/solutions) have optimized padding and typography for small screens.
- **Mobile Notification Center - PWA Optimized (Oct 17, 2025)**: The notification popup is fully optimized for mobile and PWA environments with fixed positioning spanning the entire viewport (top/left/right: 0, width: 100%, max-height: 100vh) at the 600px breakpoint, eliminating previous absolute positioning issues. Typography scales appropriately (0.85rem messages, 0.7rem timestamps at 600px; 0.8rem/0.65rem at 480px), action buttons are touch-friendly (36x36px at 600px, 34x34px at 480px), and the notification list respects screen boundaries with calc(100vh - 70px) max-height. These responsive styles are applied to both student and professor dashboards, ensuring consistent UX across all user roles on mobile devices.
- **Scroll Position Preservation (Oct 17, 2025)**: Form submissions for chapter creation and administrator management now preserve the user's scroll position using sessionStorage. When a form is submitted via AJAX, the current scroll position is saved before page reload and automatically restored after reload, preventing the page from jumping to the top. This enhancement applies to both professor and admin dashboards, maintaining user context and improving workflow efficiency.
- **Active Tab Preservation (Oct 17, 2025)**: Admin dashboard now preserves the active tab (Administrateurs, Professeurs, Universités, UFR, Filières, Matières) across page reloads. When creating universities, UFRs, filières, or matières, the system saves the current tab in sessionStorage and automatically restores it after form submission, eliminating the need to manually navigate back to the desired section.
- **Color-Coded Semesters (Oct 17, 2025)**: Professor dashboard now features visually distinct semester headers with consistent violet/purple styling (#764ba2 on light purple background #f3e5f5). Each semester header includes a 4px left border for improved visual hierarchy and quick identification.

### Technical Implementations
- **Authentication & Authorization**: `bcrypt` for password hashing, `itsdangerous` for secure cookie-based session management, and role-based access control for professors and students.
- **Hierarchical Access Control (Oct 17, 2025)**: Students can only view chapters from their current level and all lower levels within their filière:
  - L1 students: see L1 only
  - L2 students: see L1, L2
  - L3 students: see L1, L2, L3
  - M1 students: see L1, L2, L3, M1
  - M2 students: see all levels (L1, L2, L3, M1, M2)
  - Implementation via `get_allowed_levels()` function with SQL-level filtering using `.in_(allowed_levels)`
  - Professors retain full access to all levels within their assigned subject
- **User & Content Management**: Separate models for professors and students. Content is hierarchically organized.
- **University-Based Administration**: Administrators are assigned to specific universities, restricting their access to institutional data. A main administrator has global access.
- **Data Filtering**: Professors can only create content within their assigned university. Dashboards dynamically filter data based on user roles and university affiliations.
- **Cascade Deletion**: Manual cascade deletion ensures related entities are removed correctly for universities, UFRs, and filières.
- **Search Functionality**: Pure frontend, real-time, case-insensitive search across all admin and professor dashboards for various entities. A real-time chapter search is implemented for student and professor dashboards, featuring automatic parent container expansion and visual feedback.
- **Performance Optimization**: Database migration sentinel (`.migration_done`) to prevent redundant migrations at startup, significantly reducing response times. Image optimization converts large PNGs to WebP with lazy loading.
- **Progressive Web App (PWA)**: Full PWA implementation with a web app manifest, service worker for intelligent caching (cache-first for static, network-first for dynamic), offline fallback page, and PWA/iOS meta tags, enabling installation and offline functionality.
- **Interactive Comment System (Oct 18, 2025)**: Real-time commenting feature with a `Commentaire` database model, RESTful API endpoints, permission-based deletion, visual differentiation for professors/students, XSS protection, and a reply functionality. Sections for comments, courses, exercises, and solutions are collapsible. Both professor and student dashboards now use unified JSON-based API communication for comment submission, ensuring consistent behavior across all user roles. Enhanced error handling detects and reports textarea accessibility issues.
- **Admin Auto-Provisioning**: Automatic creation of a default main administrator at every startup to ensure access regardless of database state.
- **Notification System (Oct 17, 2025)**: Real-time notification system with a `Notification` database model, RESTful API endpoints, and auto-notifications for new chapters and comments. Features a UI notification center with a bell icon, unread counter, read/unread states, and individual/bulk deletion. Native push notifications with custom sound and vibration are implemented via the Service Worker API, offering system-level alerts and click-to-focus functionality. Audio notifications are browser-compliant (play only when page is visible via `!document.hidden`, volume set to 0.7) with 10-second polling interval for faster detection.

### System Design Choices
- **Monolithic Architecture**: Built on FastAPI, handling all backend logic, database interactions, and API endpoints.
- **Session Management**: Cookie-based sessions with `itsdangerous` for secure, tamper-proof tokens and automatic role detection.
- **Route Protection**: Dependency injection (`current_user`) for automated authentication and authorization checks.

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
- **PostgreSQL**: External relational database.
- **SQLAlchemy**: ORM for database operations.
- **psycopg2-binary**: PostgreSQL adapter for Python.
- **alembic**: Database migration tool.

### Utility Dependencies
- **python-multipart**: For handling form data and file uploads.

### Environment Configuration
- **SECRET_KEY**: Essential environment variable for session security.

### File System Dependencies
- **Upload Storage**: Local `uploads/` directory for course materials.