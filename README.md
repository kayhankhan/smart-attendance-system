# Smart Attendance System with QR Code & Location Tracking

A production-ready Flask web application that uses QR code scanning and GPS location verification to mark student attendance. The system enforces a 100-meter radius check to prevent proxy attendance and automatically sends weekly attendance reports via email.

## Features

### Core Functionality
- **Multi-Role Authentication**: Separate dashboards for Students, Teachers, and Admins
- **QR Code Attendance**: Secure HMAC-signed QR codes for each session
- **GPS Location Verification**: 100-meter radius enforcement using geopy
- **Real-time Camera Scanning**: HTML5 QR code scanner with mobile support
- **Duplicate Prevention**: Database constraints prevent double check-ins
- **Daily & Weekly Reports**: Student dashboards with attendance statistics
- **Automated Email Reports**: Weekly reports sent to students and families every Monday at 07:00
- **Multi-Session Support**: Multiple classes per day with unique QR codes
- **Audit Logging**: Complete activity tracking for security

### User Roles

#### Students
- Scan QR codes using camera or file upload
- View daily attendance status
- View weekly attendance summary
- Receive automated email reports

#### Teachers
- Create subjects and schedule sessions
- Set session locations using interactive map
- Display QR codes for students to scan
- View real-time attendance rosters
- Export attendance data to CSV

#### Administrators
- Manage users and family emails
- View system-wide statistics
- Trigger scheduled jobs manually
- Access comprehensive audit logs

## Technology Stack

- **Backend**: Flask 3.0, Python 3.11
- **Database**: SQLite with SQLAlchemy ORM
- **Frontend**: Jinja2 templates, TailwindCSS
- **QR Scanning**: html5-qrcode library
- **Maps**: Leaflet.js with OpenStreetMap
- **Email**: Flask-Mail with SMTP
- **Scheduling**: APScheduler for background jobs
- **Security**: CSRF protection, password hashing, HMAC QR tokens

## Quick Start Guide

### 1. Set Environment Variables

Set the following environment variables in your deployment environment:

```
SECRET_KEY=your-secret-key-here-change-this-in-production
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASSWORD=your-app-password
MAIL_DEFAULT_SENDER=noreply@yourdomain.com
```

**Important Notes:**
- Generate a strong `SECRET_KEY` for production (at least 32 random characters)
- For Gmail, you need to use an [App Password](https://support.google.com/accounts/answer/185833)
- Without SMTP credentials, the app will work but emails won't send

### 2. Initialize the Database

Run the seed script to create demo accounts and test data:

```bash
python seed_data.py
```

This creates:
- 1 Admin account
- 2 Teacher accounts  
- 10 Student accounts
- 4 Subjects
- 6 Sessions (past, today, upcoming)

**Note:** If you need to reset the database and re-seed:

```bash
# Option 1: Delete database file and re-seed
rm attendance.db
python seed_data.py

# Option 2: Force re-seed (use in Python)
python -c "from seed_data import seed_database; seed_database(force=True)"
```

### 3. Run the Application

Execute:

```bash
python app.py
```

The app will start on `http://0.0.0.0:5000`

### 4. Login with Demo Accounts

**Admin (via /auth/admin):**
- Email: `admin@neduet.edu.pk`
- Password: `admin123` (change on first login)

**Employee (Faculty):**
- Email: `employee@school.test`
- Password: `Test1234!`

**Student:**
- Email: `student1@school.test` (student2, student3, etc.)
- Password: `Test1234!`

## How to Use

### For Teachers

1. **Login** with teacher credentials
2. **Create a Subject** from the dashboard
3. **Create a Session**:
   - Select subject, date/time
   - Click on map to set location (students must be within 100m)
   - Add optional notes
4. **Display QR Code** during class for students to scan
5. **View Attendance** in real-time
6. **Export to CSV** for record-keeping

### For Students

1. **Login** with student credentials
2. **Go to "Scan QR"** page
3. **Allow camera and location permissions** when prompted
4. **Point camera at QR code** displayed by teacher
5. System automatically:
   - Gets your GPS coordinates
   - Verifies you're within 100m of class
   - Marks attendance if valid
6. **View Dashboard** to see today's attendance
7. **Check Weekly Reports** for summary

### For Admins

1. **Login** with admin credentials
2. **Manage Users** - view all students, teachers
3. **Add Family Emails** for students (for weekly reports)
4. **Trigger Jobs** manually for testing
5. **View Audit Logs** for security monitoring

## Testing

### Run Automated Tests

```bash
pytest tests/test_core.py -v
```

Tests cover:
- Distance calculation accuracy
- Location verification logic
- QR token generation and validation
- Password hashing
- Duplicate attendance prevention
- Login flow

### Manual Testing Workflow

1. **Create a session** as teacher (use current time)
2. **Note the session location** coordinates
3. **Open student account** in another browser/incognito
4. **Try scanning QR** - should fail if not at location
5. **Mock GPS** (browser dev tools) to match session location
6. **Scan again** - should succeed
7. **Verify** attendance appears in teacher's roster

## Email Configuration

### Gmail Setup

1. Enable 2-Factor Authentication on your Google account
2. Generate an [App Password](https://support.google.com/accounts/answer/185833)
3. Use App Password as `SMTP_PASSWORD` environment variable

### Other SMTP Providers

Update these secrets accordingly:

- **SendGrid**: SMTP_HOST=smtp.sendgrid.net, SMTP_PORT=587
- **Mailgun**: SMTP_HOST=smtp.mailgun.org, SMTP_PORT=587
- **AWS SES**: SMTP_HOST=email-smtp.{region}.amazonaws.com

### Test Email Configuration

As admin:
1. Go to Dashboard
2. Enter your email in "Test Email Configuration"
3. Click "Send Test"
4. Check inbox (and spam folder)

## Weekly Reports Schedule

Reports are automatically sent **every Monday at 07:00** to:
- Student's email
- All family emails registered for that student

Reports include:
- Weekly attendance percentage
- List of attended/missed sessions
- Recommendations based on performance

To trigger manually (testing):
1. Login as admin
2. Go to Dashboard
3. Click "Trigger Now" under Weekly Reports

## Security Features

- **Password Hashing**: Werkzeug security with strong hashing
- **CSRF Protection**: Flask-WTF tokens on all forms
- **HMAC QR Tokens**: Cryptographically signed, time-limited
- **Role-Based Access**: Route protection by user role
- **Audit Logging**: All critical actions logged with IP address
- **Location Verification**: Server-side distance calculation
- **Unique Constraints**: Prevent duplicate attendance

## Database Schema

### Tables

- **users**: Students, teachers, admins with authentication
- **family_emails**: Family contact information for reports
- **subjects**: Academic subjects taught
- **sessions**: Individual class sessions with location
- **attendance**: Attendance records with verification status
- **audit_logs**: System activity tracking

### Key Relationships

- User (teacher) → Subjects (one-to-many)
- Subject → Sessions (one-to-many)
- Session → Attendance (one-to-many)
- User (student) → Attendance (one-to-many)
- User (student) → FamilyEmails (one-to-many)

## File Structure

```
.
├── app.py                    # Main Flask application
├── models.py                 # Database models
├── auth.py                   # Authentication helpers
├── utils.py                  # Utility functions (QR, GPS, etc.)
├── mailer.py                 # Email functionality
├── seed_data.py             # Database seeding script
├── requirements.txt         # Python dependencies
├── views/
│   ├── student.py           # Student routes
│   ├── teacher.py           # Teacher routes
│   └── admin.py             # Admin routes
├── templates/
│   ├── base.html            # Base template
│   ├── auth/                # Login, register
│   ├── student/             # Student dashboards, scan
│   ├── teacher/             # Teacher dashboards, sessions
│   ├── admin/               # Admin dashboards
│   └── email/               # Email templates
├── static/
│   └── qr_codes/            # Generated QR codes
└── tests/
    └── test_core.py         # Automated tests
```

## Troubleshooting

### QR Scanner Not Working

- Ensure HTTPS or localhost (camera requires secure context)
- Check browser permissions for camera
- Try file upload fallback option

### Location Permission Denied

- Enable location in browser settings
- For testing, use browser dev tools to mock GPS
- Teacher can manually verify if needed

### Attendance Rejected

- **"Too far from location"**: Student must be within 100m
  - Check coordinates shown to student
  - Verify session location on teacher's map
- **"Token expired"**: QR codes valid for 30 minutes
  - Teacher should refresh session page
- **"Already marked"**: Can't check in twice
  - View dashboard to confirm attendance

### Emails Not Sending

- Verify SMTP credentials in environment variables
- Check spam folder
- Use admin test email feature to diagnose
- Review application logs for errors

### Database Issues

To reset database (⚠️ destroys all data):

```bash
rm attendance.db
python seed_data.py
```

## Production Deployment

### Before Going Live

1. **Change SECRET_KEY**: Generate cryptographically secure key
2. **Use PostgreSQL**: Replace SQLite with production database
3. **Configure Real SMTP**: Use reliable email service
4. **Update Locations**: Change default coordinates in seed_data.py
5. **Remove Demo Accounts**: Delete or change demo passwords
6. **Enable HTTPS**: Required for camera and GPS
7. **Rate Limiting**: Add IP-based rate limiting
8. **Backup Strategy**: Regular database backups

### Environment Variables for Production

```
SECRET_KEY=<strong-random-key>
DATABASE_URL=postgresql://user:pass@host/db
SMTP_HOST=<your-smtp-server>
SMTP_PORT=587
SMTP_USER=<your-smtp-username>
SMTP_PASSWORD=<your-smtp-password>
MAIL_DEFAULT_SENDER=noreply@yourdomain.com
```

## Support & Customization

### Customization Options

- **Distance Threshold**: Change `max_distance_meters=100` in code
- **Report Schedule**: Modify cron expression in app.py
- **Email Templates**: Edit templates/email/ files
- **UI Theme**: Customize TailwindCSS classes
- **Session Duration**: Adjust QR token expiry time

### Common Modifications

**Change 100m radius to 200m:**
```python
# In views/student.py, line ~75
verify_location(..., max_distance_meters=200)
```

**Change report schedule to Friday:**
```python
# In app.py, scheduler config
day_of_week='fri'
```

## License

This project is for educational purposes. Modify and use as needed.

## Credits

Built with Flask, SQLAlchemy, html5-qrcode, Leaflet, and TailwindCSS.

---

**Need Help?** Check logs, review code comments, or consult Flask documentation.

**Security Notice**: Demo passwords should be changed immediately in production environments.
# smart-attendance-system
