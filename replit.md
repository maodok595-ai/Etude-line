# Étude LINE

## Overview
Étude LINE is an educational web application built with FastAPI, enabling professors to share content (courses, exercises, solutions) with students. Content is hierarchically organized by university, field, level, semester, subject, and chapter. Students can register and access all content freely. The platform features a complete authentication system, robust content management, and is available as an installable Progressive Web App (PWA) for mobile and desktop. The project aims to facilitate seamless educational content dissemination and access.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, featuring a modern, responsive design with CSS Grid and Flexbox and a gradient color scheme. Key interfaces include:
- **Dashboards (Professor, Student, Admin)**: Consistent university branding (logo, welcome message), interactive accordion views for content, color-coded level cards (L1-M2), and icon-based actions. Admin panels have consistent button-based forms, animated transitions, and real-time search. **Student Information Display (Oct 18, 2025)**: Admin dashboard displays comprehensive student information including full name, username, academic level (color-coded badge), registration date and time, university name, UFR name, and filière name, providing complete visibility of student profiles. **Collapsible List Sections (Oct 18, 2025)**: All admin dashboard lists (Administrateurs, Professeurs, Étudiants, Universités, UFR, Filières, Matières) feature clickable toggle arrows (▼/►) for expanding/collapsing entire sections, with all sections starting closed (►) by default on page load. **Individual User Collapse (Oct 18, 2025)**: Each professor and student card includes a personal toggle arrow next to their name, allowing administrators to expand/collapse individual user details (username, specialization, university info, action buttons) independently, with all user details starting collapsed (►) by default for a clean, organized interface.
- **Homepage UX**: Redesigned student registration with initial welcome view, "S'inscrire" button, and smooth fade-in/fade-out animations.
- **Responsive Design**: Fully optimized for mobile, tablet, and PC across various breakpoints (480px to 1600px+). This includes stacked navigation, compact typography, optimized spacing, touch-friendly buttons, and hover effects on larger screens, with specific enhancements for all dashboards and the homepage.
- **Professor Chapter Creation Form - Mobile Pro (Oct 17, 2025)**: The chapter creation form features a professional mobile-first design with stable CSS classes (form-header, section-cours, section-exercices, section-solutions, form-warning, form-note) ensuring robust responsive behavior at 600px and 480px breakpoints. Header elements stack vertically, buttons span full width for touch accessibility, and colored sections (cours/exercices/solutions) have optimized padding and typography for small screens.
- **Mobile Notification Center - PWA Optimized (Oct 17, 2025)**: The notification popup is fully optimized for mobile and PWA environments with fixed positioning spanning the entire viewport (top/left/right: 0, width: 100%, max-height: 100vh) at the 600px breakpoint, eliminating previous absolute positioning issues. Typography scales appropriately (0.85rem messages, 0.7rem timestamps at 600px; 0.8rem/0.65rem at 480px), action buttons are touch-friendly (36x36px at 600px, 34x34px at 480px), and the notification list respects screen boundaries with calc(100vh - 70px) max-height. These responsive styles are applied to both student and professor dashboards, ensuring consistent UX across all user roles on mobile devices.
- **Scroll Position Preservation (Oct 17, 2025)**: Form submissions for chapter creation and administrator management now preserve the user's scroll position using sessionStorage. When a form is submitted via AJAX, the current scroll position is saved before page reload and automatically restored after reload, preventing the page from jumping to the top. This enhancement applies to both professor and admin dashboards, maintaining user context and improving workflow efficiency.
- **Active Tab Preservation (Oct 18, 2025)**: Admin dashboard now preserves the active tab (Administrateurs, Professeurs, Universités, UFR, Filières, Matières) across page reloads. All admin creation forms (administrators, professors, universities, UFRs, filières, matières) automatically save the current tab in sessionStorage before submission and restore it after page reload, eliminating the need to manually navigate back to the desired section. The system intercepts all `/admin/` form submissions to ensure seamless workflow continuity.
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
- **Complete Cascade Deletion (Oct 18, 2025)**: Comprehensive deletion system with 7 specialized helper functions ensuring total data removal. When deleting any entity, all associated data is permanently removed in a transaction-safe manner:
  - **Chapitre deletion**: Removes uploaded files (cours, exercices, solutions), all comments, and notifications
  - **Matière deletion**: Removes all chapters, uploaded files, comments, and notifications
  - **Professeur deletion**: Removes all created chapters, uploaded files, comments (authored), and notifications
  - **Étudiant deletion**: Removes all comments (authored) and notifications
  - **Filière deletion**: Removes all matières, chapters, uploaded files, comments, notifications, assigned professors, and enrolled students
  - **UFR deletion**: Removes all filières and their entire content hierarchically
  - **Université deletion**: Removes all UFRs and their entire content (with protection against deleting universities with assigned secondary administrators)
  - **Administrateur deletion**: Protected against deletion of main admin (maodoka65)
  - Implementation uses transaction-based approach with automatic rollback on errors, filesystem cleanup for uploaded files, and detailed logging of deletion statistics for each operation
- **Search Functionality**: Pure frontend, real-time, case-insensitive search across all admin and professor dashboards for various entities. A real-time chapter search is implemented for student and professor dashboards, featuring automatic parent container expansion and visual feedback. **Form Select Filtering (Oct 18, 2025)**: All admin creation forms (UFR, Filière, Matière, Professeur, Administrateur secondaire) now include live search bars above dropdown menus, enabling instant filtering of parent entities as users type. The `filterSelectOptions()` function hides non-matching options in real-time and automatically resets selection if the chosen option becomes hidden. This feature works seamlessly with cascading selects (university → UFR → filière → matière) in the professor creation form, maintaining filtering capability even after options are dynamically populated.
- **Performance Optimization**: Database migration sentinel (`.migration_done`) to prevent redundant migrations at startup, significantly reducing response times. Image optimization converts large PNGs to WebP with lazy loading.
- **Progressive Web App (PWA)**: Full PWA implementation with a web app manifest, service worker for intelligent caching (cache-first for static, network-first for dynamic), offline fallback page, and PWA/iOS meta tags, enabling installation and offline functionality. **Custom Install Banner (Oct 18, 2025)**: Persistent installation banner that intercepts the browser's native `beforeinstallprompt` event, displaying a custom UI with gradient styling at the bottom of the page. The banner remains visible indefinitely until the user installs the app or manually closes it (stored in sessionStorage for the current session only), ensuring maximum visibility and installation conversion.
- **Interactive Comment System (Oct 18, 2025)**: Real-time commenting feature with a `Commentaire` database model, RESTful API endpoints, permission-based deletion with author-only visibility, visual differentiation for professors/students, XSS protection, and a reply functionality. Sections for comments, courses, exercises, and solutions are collapsible. Both professor and student dashboards now use unified JSON-based API communication for comment submission, ensuring consistent behavior across all user roles. Enhanced error handling detects and reports textarea accessibility issues. The reply feature uses a robust DOM traversal method that finds the textarea within the same comment section, working reliably across different dashboard structures. **Security Enhancement**: Delete button only appears for comment authors (verified by comparing `auteur_id` and `auteur_type` with current user credentials), preventing unauthorized deletion attempts.
- **Admin Auto-Provisioning**: Automatic creation of a default main administrator at every startup to ensure access regardless of database state.
- **Administrator Edit Capability (Oct 18, 2025)**: Main administrator can modify usernames and passwords for professors and secondary administrators. Edit endpoints `/admin/edit-admin` and `/admin/edit-prof` accept optional `new_username` and `new_password` fields with duplicate username validation across all user types. When a professor's username is updated, all associated chapters (`created_by` field) are automatically updated to maintain data consistency. Password changes are securely hashed using bcrypt before storage.
- **Notification System (Oct 18, 2025)**: Real-time notification system with a `Notification` database model, RESTful API endpoints, and auto-notifications for new chapters and comments. Features a UI notification center with a bell icon, unread counter, read/unread states, and individual/bulk deletion. Native push notifications with custom sound and vibration are implemented via the Service Worker API, offering system-level alerts that work even when the app is in the background. Notifications appear at the top of the phone/computer with system sounds and vibration patterns (200ms-100ms-200ms-100ms-200ms). The Service Worker handles message passing between background notifications and active pages to play custom notification sounds (volume 0.9) when tabs are open. Audio playback uses browser-compliant auto-play policies with 3-second polling interval for optimal responsiveness. Backend logging tracks notification creation for both chapter publications and comment interactions. **PWA Badge API Integration (Oct 18, 2025)**: The installed PWA icon displays a numerical badge showing the count of unread notifications using the Badging API (`navigator.setAppBadge()`). The badge updates automatically when new notifications arrive or when notifications are read/deleted, working even when the application is closed. The Service Worker receives messages from the client pages to update the badge count, providing native app-like behavior with real-time visual indicators on the home screen icon.

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