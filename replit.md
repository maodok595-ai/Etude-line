# Étude LINE

## Overview

Étude LINE is an educational web application built with FastAPI that serves two distinct user roles: professors and students. The platform allows professors to publish educational content (courses, exercises, solutions) organized by university, field of study, level, semester, subject, and chapter. Students can access this content through a subscription-based payment system integrated with Wave payment services.

The application features a complete authentication system, content management capabilities, and payment processing functionality. It's designed as a simple but comprehensive educational platform that bridges the gap between professors creating content and students accessing structured learning materials.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Frontend Architecture
The application uses a server-side rendered architecture with Jinja2 templates and FastAPI's built-in HTML response system. The frontend consists of four main templates:
- **index.html**: Landing page with role selection and registration options
- **login.html**: Authentication interface for both user types
- **dashboard_prof.html**: Professor interface for content management and publishing
- **dashboard_etudiant.html**: Student interface for content consumption and subscription management

The UI follows a modern, responsive design with CSS Grid and Flexbox, using a gradient color scheme for visual appeal.

### Backend Architecture
Built on FastAPI with a monolithic architecture pattern, the system handles:
- **Authentication & Authorization**: Uses bcrypt for password hashing and itsdangerous for secure session management via signed cookies
- **User Management**: Separate data models for professors (UserProf) and students (UserEtudiant) with role-based access control
- **Content Management**: ContentItem model supporting hierarchical organization of educational materials
- **Payment Processing**: Integration with Wave payment system including webhook handling
- **Session Management**: Cookie-based sessions with automatic role detection and route protection

### Data Storage Solution
The application uses a file-based JSON storage system with file locking for data persistence:
- **Data Structure**: Single JSON file (data.json) with separate collections for users, content, payments, and subscriptions
- **Concurrency Control**: File locking (fcntl) ensures data integrity during concurrent operations
- **Data Models**: Pydantic models provide validation and type safety for all data operations
- **Backup Strategy**: Simple file-based approach suitable for development and small-scale deployment

### Authentication & Authorization
- **Dual Registration System**: Separate registration flows for professors and students with different required fields
- **Unified Login**: Single login endpoint that automatically detects user role based on stored data
- **Session Security**: URLSafeTimedSerializer creates tamper-proof session tokens
- **Route Protection**: Dependency injection system (current_user) provides automatic authentication checks

## External Dependencies

### Core Framework Dependencies
- **FastAPI**: Web framework providing async capabilities, automatic OpenAPI documentation, and built-in validation
- **Uvicorn**: ASGI server for running the FastAPI application
- **Jinja2**: Template engine for server-side HTML rendering
- **Pydantic**: Data validation and settings management using Python type annotations

### Security Dependencies
- **passlib[bcrypt]**: Password hashing library with bcrypt algorithm support
- **itsdangerous**: Cryptographic signing for secure session cookies and tokens

### Utility Dependencies
- **python-multipart**: Form data parsing for file uploads and form submissions

### Payment Integration
- **Wave Payment System**: External payment provider for handling student subscriptions
  - Webhook endpoint for payment confirmation
  - QR code integration for mobile payments
  - FCFA currency support (default 990 FCFA per semester)

### Environment Configuration
The application relies on environment variables for configuration:
- **SECRET_KEY**: Critical for session security and token signing
- **PRICE_FCFA**: Configurable subscription price (default: 990)
- **WAVE_WEBHOOK_SECRET**: Security token for payment webhook verification
- **WAVE_QR_IMAGE_PATH**: Path to payment QR code image for display

### File System Dependencies
- **Local File Storage**: JSON-based persistence with file locking
- **Template Assets**: Static template files and placeholder images
- **Upload Handling**: Support for content file uploads through multipart forms