# Étude LINE

## Overview
Étude LINE is an educational web application built with FastAPI, designed for professors to share content (courses, exercises, solutions) with students. The platform features content organized hierarchically by university, field, level, semester, subject, and chapter. It includes a complete authentication system, robust content management, and is available as an installable Progressive Web App (PWA). The project aims to facilitate seamless educational content dissemination and access, enabling students to register and access all content freely.

## User Preferences
Preferred communication style: Simple, everyday language.

## System Architecture

### UI/UX Decisions
The application uses a server-side rendered architecture with Jinja2 templates, featuring a modern, responsive design with CSS Grid and Flexbox and a gradient color scheme. Key interfaces include dashboards for Professors, Students, and Admins, offering consistent branding, interactive content views, color-coded level cards, and icon-based actions. Admin panels feature consistent button-based forms, animated transitions, real-time search, and detailed student information display. All admin dashboard lists and individual user details are collapsible by default for a clean interface. University statistics are presented in compact, color-coded cards. The homepage includes a redesigned student registration flow with animations. The application is fully responsive for mobile, tablet, and PC, with specific optimizations for forms, notification centers, and dashboards, ensuring touch-friendly elements and readable typography across devices. Scroll position and active tabs are preserved across form submissions in professor and admin dashboards to maintain user context. Semester headers in the professor dashboard are visually distinct with consistent violet/purple styling.

### Technical Implementations
- **Authentication & Authorization**: `bcrypt` for password hashing, `itsdangerous` for secure cookie-based session management, and role-based access control.
- **Hierarchical Access Control**: Students can only view chapters from their current level and all lower levels within their filière, enforced by SQL-level filtering. Professors have full access within their assigned subject.
- **User & Content Management**: Separate models for professors and students, with content hierarchically organized.
- **University-Based Administration**: Administrators are assigned to specific universities, restricting access to institutional data, with a main administrator having global access.
- **Data Filtering**: Professors can only create content within their assigned university, and dashboards dynamically filter data based on user roles and affiliations.
- **Complete Cascade Deletion**: A comprehensive system with specialized helper functions ensures transaction-safe, permanent removal of all associated data when an entity (chapter, subject, professor, student, filière, UFR, university, secondary administrator) is deleted, including uploaded files, comments, and notifications.
- **Search Functionality**: Pure frontend, real-time, case-insensitive search across admin and professor dashboards for various entities, including real-time chapter search for students/professors and live filtering of dropdown options in admin creation forms.
- **Performance Optimization**: Database migration sentinel prevents redundant migrations. Image optimization converts large PNGs to WebP with lazy loading.
- **Progressive Web App (PWA)**: Full PWA implementation with a web app manifest, service worker for intelligent caching, offline fallback page, PWA/iOS meta tags, and a custom, persistent installation banner.
- **Interactive Comment System**: Real-time commenting with a `Commentaire` database model, RESTful API endpoints, permission-based deletion (author-only), visual differentiation for user roles, XSS protection, and reply functionality. Unified JSON-based API communication and enhanced error handling are implemented.
- **Admin Auto-Provisioning**: Automatic creation of a default main administrator at startup.
- **Administrator Edit Capability**: Main administrator can modify usernames and passwords for professors and secondary administrators, with duplicate username validation and automatic update of associated chapters for professors.
- **Notification System**: Real-time notification system with a `Notification` database model, RESTful API, auto-notifications for new content, a UI notification center with unread counters, read/unread states, and individual/bulk deletion. Native push notifications with custom sound and vibration are implemented via the Service Worker API, including PWA badge API integration for unread counts on the app icon.

### System Design Choices
- **Monolithic Architecture**: FastAPI handles all backend logic, database interactions, and API endpoints.
- **Session Management**: Cookie-based sessions with `itsdangerous` for secure tokens and automatic role detection.
- **Route Protection**: Dependency injection for automated authentication and authorization.

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
- **PostgreSQL**: Relational database.
- **SQLAlchemy**: ORM for database operations.
- **psycopg2-binary**: PostgreSQL adapter for Python.
- **alembic**: Database migration tool.

### Utility Dependencies
- **python-multipart**: For handling form data and file uploads.

### Environment Configuration
- **SECRET_KEY**: Essential environment variable for session security.

### File System Dependencies
- **Upload Storage**: Local `uploads/` directory for course materials.