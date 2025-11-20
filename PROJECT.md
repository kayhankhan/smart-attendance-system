# Smart Attendance Portal - Project Documentation

## Project Overview

A production-ready Flask web application for educational institutions that uses QR code scanning and GPS location verification to mark attendance. The system enforces a 100-meter radius check to prevent proxy attendance, features multi-role access control, and includes custom CAPTCHA verification.

## Key Features

### For Students (Undergraduate/Postgraduate)
- Scan QR codes using mobile camera for attendance
- Real-time location verification (must be within 100 meters)
- Mobile camera and GPS permission requests for iOS/Android
- Daily and weekly attendance dashboards
- Automated email reports sent to student and family

### For Employees (Faculty/Staff)
- View their own sessions and attendance records
- Access attendance rosters for their classes
- Export attendance data to CSV

### For Administrators
- Exclusive admin portal at `/auth/admin`
- Complete user management with email-based access control
- Create and manage subjects and sessions
- Subject creation with course codes and credits
- Session scheduling with GPS locations using interactive maps
- Generate secure QR codes for each session
- System-wide statistics dashboard
- Manual job triggering for testing
- Comprehensive audit logging
- View and clear audit logs with password verification

## Technical Stack

- **Backend**: Flask 3.0, Python 3.11, SQLAlchemy
- **Database**: PostgreSQL (with psycopg2-binary driver) or SQLite for development
- **Frontend**: Jinja2, TailwindCSS, html5-qrcode, Leaflet.js
- **Email**: Flask-Mail with SMTP support
- **Scheduling**: APScheduler for background jobs
- **Security**: 
  - CSRF protection via Flask-WTF
  - HMAC QR tokens with expiry
  - Werkzeug password hashing
  - Custom CAPTCHA system
  - Flask-Limiter for DDoS protection
  - Environment variable enforcement for production secrets

## Quick Start

### 1. Configure Environment Variables

**Required for Production:**
```
SECRET_KEY=your-strong-random-secret-key-here
DATABASE_URL=postgresql://user:password@host:port/database
```

**Optional Configuration:**
```
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@yourdomain.com
```

### 2. Initialize Database

```bash
python init_db.py
```

This creates the database schema and seeds the default admin user.

### 3. Default Admin Credentials

**Admin Portal**: `/auth/admin`
- Email: admin@neduet.edu.pk
- Password: admin123

**IMPORTANT**: Change the password immediately on first login!

### 4. User Roles

The system supports four role types:
- **admin**: Full system access, exclusive rights to create subjects/sessions/users
- **employee**: Faculty and staff members (view-only for sessions)
- **undergraduate**: Undergraduate students
- **postgraduate**: Postgraduate students

## Architecture

### Database Models
- **User**: Multi-role users (admin, employee, undergraduate, postgraduate) with email-based authentication
- **Subject**: Academic subjects with course codes and credits
- **Session**: Class sessions with GPS coordinates and secure QR tokens
- **Attendance**: Records with verification status and distance tracking
- **FamilyEmail**: Family contacts for weekly reports (students only)
- **AuditLog**: Security and activity tracking

### Security Features
- HMAC-signed QR codes (30-minute expiry)
- Server-side GPS distance verification
- Duplicate attendance prevention via unique constraints
- CSRF protection on all forms
- Werkzeug password hashing
- IP address logging for audit trails
- **DDoS Protection**: Flask-Limiter with rate limiting
  - Login: 10 attempts per minute
  - Admin login: 10 attempts per minute
  - Forgot password: 5 attempts per hour
  - Reset password: 10 attempts per hour
  - Global: 200 requests per day, 50 per hour
- **Custom CAPTCHA**: Image-based verification on login forms
- **Forgot Password**: Secure password reset with email verification and 1-hour token expiry
- **Admin Password Verification**: Required to clear audit logs

### Automated Jobs
- Weekly email reports (every Monday 07:00)
- Attendance summary calculations
- Configurable via APScheduler

## Project Structure

```
├── app.py                    # Main Flask application with scheduler
├── models.py                 # SQLAlchemy database models
├── auth.py                   # Authentication and authorization
├── utils.py                  # QR generation, GPS distance, utilities
├── mailer.py                 # Email sending functionality
├── captcha.py                # Custom CAPTCHA generation
├── init_db.py                # Database initialization script
├── seed_data.py              # Demo data seeding script
├── requirements.txt          # Python dependencies
├── views/
│   ├── student.py            # Student routes and QR scanning
│   ├── teacher.py            # Teacher routes and session management
│   └── admin.py              # Admin routes and system management
├── templates/                # Jinja2 HTML templates
│   ├── auth/                 # Login, password reset
│   ├── student/              # Student dashboards
│   ├── teacher/              # Teacher dashboards
│   ├── admin/                # Admin dashboards
│   └── email/                # Email templates
├── static/
│   ├── css/                  # Custom stylesheets
│   ├── js/                   # JavaScript files
│   ├── images/               # Logo and images
│   └── qr_codes/             # Generated QR code images
└── tests/
    └── test_core.py          # Automated tests
```

## Testing

Run automated tests:
```bash
pytest tests/test_core.py -v
```

Tests cover distance calculation, location verification, QR token validation, password hashing, duplicate prevention, and login flows.

## Deployment Notes

For production deployment:
1. Use PostgreSQL instead of SQLite
2. Generate strong SECRET_KEY (32+ random characters)
3. Configure production SMTP service
4. Enable HTTPS (required for camera and GPS)
5. Remove or change demo account passwords
6. Set up database backups
7. Consider additional rate limiting for API endpoints
8. Set FLASK_ENV=production

## Development

To run in development mode:
```bash
python app.py
```

The app will start on `http://0.0.0.0:5000`

## Support

For detailed usage instructions, troubleshooting, and customization options, see README.md.

## License

This project is for educational purposes. Modify and use as needed.

---

**Last Updated**: 2025-11-15
**Status**: Production Ready
