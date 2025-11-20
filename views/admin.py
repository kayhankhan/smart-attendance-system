from flask import Blueprint, render_template, request, jsonify, flash, redirect, url_for
from auth import login_required, role_required, get_current_user, log_audit
from models import db, User, Subject, Session, Attendance, AuditLog, FamilyEmail
from mailer import send_weekly_report, send_test_email
from datetime import datetime
import pytz

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')


@admin_bp.route('/dashboard')
@role_required('admin')
def dashboard():
    """Admin dashboard"""
    user = get_current_user()
    assert user is not None

    # Get statistics
    total_users = User.query.count()
    total_students = User.query.filter(
        User.role.in_(['undergraduate', 'postgraduate'])).count()
    total_employees = User.query.filter_by(role='employee').count()
    total_admins = User.query.filter_by(role='admin').count()
    total_subjects = Subject.query.filter_by(is_active=True).count()
    total_sessions = Session.query.filter_by(is_active=True).count()
    total_attendance = Attendance.query.filter_by(
        verification_status='VERIFIED').count()

    # Recent audit logs
    recent_logs = AuditLog.query.order_by(
        AuditLog.timestamp.desc()).limit(20).all()

    return render_template('admin/dashboard.html',
                           user=user,
                           total_users=total_users,
                           total_students=total_students,
                           total_employees=total_employees,
                           total_admins=total_admins,
                           total_subjects=total_subjects,
                           total_sessions=total_sessions,
                           total_attendance=total_attendance,
                           recent_logs=recent_logs)


@admin_bp.route('/users')
@role_required('admin')
def list_users():
    """List all users with filtering and sorting"""
    user = get_current_user()
    assert user is not None

    # Get filter parameters
    role_filter = request.args.get('role', 'all')
    department_filter = request.args.get('department', 'all')
    year_filter = request.args.get('year', 'all')
    sort_by = request.args.get('sort', 'created_at')

    # Base query
    query = User.query

    # Apply filters
    if role_filter != 'all':
        query = query.filter_by(role=role_filter)
    if department_filter != 'all':
        query = query.filter_by(department=department_filter)
    if year_filter != 'all':
        query = query.filter_by(year=int(year_filter))

    # Apply sorting
    if sort_by == 'name':
        query = query.order_by(User.full_name)
    elif sort_by == 'email':
        query = query.order_by(User.email)
    elif sort_by == 'department':
        query = query.order_by(User.department.desc())
    elif sort_by == 'year':
        query = query.order_by(User.year.desc())
    else:
        query = query.order_by(User.created_at.desc())

    users = query.all()

    # Get unique departments and years for filters
    departments = db.session.query(User.department).distinct().filter(
        User.department.isnot(None)).all()
    departments = [d[0] for d in departments]
    years = db.session.query(User.year).distinct().filter(
        User.year.isnot(None)).all()
    years = sorted([y[0] for y in years if y[0]])

    return render_template('admin/list_users.html',
                           user=user,
                           users=users,
                           departments=departments,
                           years=years,
                           current_role=role_filter,
                           current_dept=department_filter,
                           current_year=year_filter,
                           current_sort=sort_by)


@admin_bp.route('/users/<int:user_id>')
@role_required('admin')
def view_user(user_id):
    """View user details"""
    admin_user = get_current_user()
    assert admin_user is not None
    target_user = User.query.get_or_404(user_id)

    # Get family emails if student
    family_emails = []
    if target_user.is_student():
        family_emails = FamilyEmail.query.filter_by(student_id=user_id).all()

    # Get attendance summary if student
    attendance_summary = None
    if target_user.is_student():
        from utils import get_weekly_attendance_summary
        attendance_summary = get_weekly_attendance_summary(user_id)

    return render_template('admin/view_user.html',
                           user=admin_user,
                           target_user=target_user,
                           family_emails=family_emails,
                           attendance_summary=attendance_summary)


@admin_bp.route('/users/<int:user_id>/family_emails/add', methods=['POST'])
@role_required('admin')
def add_family_email(user_id):
    """Add family email"""
    admin_user = get_current_user()
    assert admin_user is not None
    target_user = User.query.get_or_404(user_id)

    if not target_user.is_student():
        flash('Can only add family emails for students', 'danger')
        return redirect(url_for('admin.view_user', user_id=user_id))

    try:
        email = request.form.get('email')
        relationship = request.form.get('relationship')

        if not email:
            flash('Email is required', 'danger')
            return redirect(url_for('admin.view_user', user_id=user_id))

        family_email = FamilyEmail(student_id=user_id,  # type: ignore
                                   email=email,
                                   relationship=relationship)

        db.session.add(family_email)
        db.session.commit()

        log_audit(user_id=admin_user.id,
                  action='FAMILY_EMAIL_ADDED',
                  entity_type='User',
                  entity_id=user_id,
                  details=f'Added family email: {email}',
                  ip_address=request.remote_addr)

        flash(f'Family email added successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error adding family email: {str(e)}', 'danger')

    return redirect(url_for('admin.view_user', user_id=user_id))


@admin_bp.route('/users/<int:user_id>/family_emails/<int:email_id>/delete',
                methods=['POST'])
@role_required('admin')
def delete_family_email(user_id, email_id):
    """Delete family email"""
    admin_user = get_current_user()
    assert admin_user is not None
    family_email = FamilyEmail.query.get_or_404(email_id)

    if family_email.student_id != user_id:
        flash('Invalid family email', 'danger')
        return redirect(url_for('admin.view_user', user_id=user_id))

    try:
        email_address = family_email.email
        db.session.delete(family_email)
        db.session.commit()

        log_audit(user_id=admin_user.id,
                  action='FAMILY_EMAIL_DELETED',
                  entity_type='User',
                  entity_id=user_id,
                  details=f'Deleted family email: {email_address}',
                  ip_address=request.remote_addr)

        flash('Family email deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting family email: {str(e)}', 'danger')

    return redirect(url_for('admin.view_user', user_id=user_id))


@admin_bp.route('/jobs/trigger', methods=['POST'])
@role_required('admin')
def trigger_job():
    """Manually trigger scheduled jobs"""
    admin_user = get_current_user()
    assert admin_user is not None
    job_type = request.form.get('job_type')

    try:
        if job_type == 'weekly_reports':
            # Send weekly reports to all students
            students = User.query.filter(
                User.role.in_(['undergraduate', 'postgraduate']),
                User.is_active == True).all()
            success_count = 0
            error_count = 0

            for student in students:
                success, message = send_weekly_report(student.id)
                if success:
                    success_count += 1
                else:
                    error_count += 1

            log_audit(
                user_id=admin_user.id,
                action='WEEKLY_REPORTS_TRIGGERED',
                details=
                f'Sent to {success_count} students, {error_count} errors',
                ip_address=request.remote_addr)

            flash(
                f'Weekly reports sent to {success_count} students ({error_count} errors)',
                'success')

        elif job_type == 'test_email':
            test_recipient = request.form.get('test_email')
            if not test_recipient:
                flash('Please provide a test email address', 'warning')
                return redirect(url_for('admin.dashboard'))

            success, message = send_test_email(test_recipient)
            if success:
                flash(f'Test email sent to {test_recipient}', 'success')
            else:
                flash(f'Error sending test email: {message}', 'danger')

            log_audit(user_id=admin_user.id,
                      action='TEST_EMAIL_SENT',
                      details=f'Test email to {test_recipient}: {message}',
                      ip_address=request.remote_addr)

        else:
            flash('Invalid job type', 'danger')

    except Exception as e:
        flash(f'Error triggering job: {str(e)}', 'danger')

    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/audit_logs')
@role_required('admin')
def audit_logs():
    """View audit logs"""
    user = get_current_user()
    assert user is not None

    page = request.args.get('page', 1, type=int)
    per_page = 50

    logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).paginate(
        page=page, per_page=per_page, error_out=False)

    return render_template('admin/audit_logs.html', user=user, logs=logs)


@admin_bp.route('/audit_logs/clear', methods=['POST'])
@role_required('admin')
def clear_audit_logs():
    """Clear all audit logs after admin password verification"""
    admin_user = get_current_user()
    assert admin_user is not None

    # Get and verify admin password
    admin_password = request.form.get('admin_password')

    if not admin_password:
        flash('Admin password is required to clear audit logs.', 'danger')
        return redirect(url_for('admin.audit_logs'))

    # Verify admin password
    if not admin_user.check_password(admin_password):
        flash('Incorrect admin password. Audit logs were not cleared.',
              'danger')
        log_audit(
            user_id=admin_user.id,
            action='AUDIT_LOG_CLEAR_FAILED',
            details='Failed attempt to clear audit logs - incorrect password',
            ip_address=request.remote_addr)
        return redirect(url_for('admin.audit_logs'))

    try:
        # Count logs before deletion
        log_count = AuditLog.query.count()

        # Delete all audit logs
        AuditLog.query.delete()
        db.session.commit()

        # Log this action (new audit log after clearing)
        log_audit(
            user_id=admin_user.id,
            action='AUDIT_LOG_CLEARED',
            details=
            f'Admin {admin_user.email} cleared {log_count} audit log entries',
            ip_address=request.remote_addr)

        flash(f'Successfully cleared {log_count} audit log entries.',
              'success')

    except Exception as e:
        db.session.rollback()
        flash(f'Error clearing audit logs: {str(e)}', 'danger')
        log_audit(user_id=admin_user.id,
                  action='AUDIT_LOG_CLEAR_ERROR',
                  details=f'Error clearing audit logs: {str(e)}',
                  ip_address=request.remote_addr)

    return redirect(url_for('admin.audit_logs'))


@admin_bp.route('/users/create', methods=['GET', 'POST'])
@role_required('admin')
def create_user():
    """Create a new user"""
    admin_user = get_current_user()
    assert admin_user is not None

    if request.method == 'POST':
        try:
            email = request.form.get('email')
            full_name = request.form.get('full_name')
            role = request.form.get('role')
            password = request.form.get('password')
            student_id = request.form.get('student_id')
            department = request.form.get('department')
            year = request.form.get('year')
            phone = request.form.get('phone')

            # Validation
            if not all([email, full_name, role, password]):
                flash('Email, full name, role, and password are required',
                      'danger')
                return redirect(url_for('admin.create_user'))

            # Check if email already exists
            if User.query.filter_by(email=email).first():
                flash('Email already exists', 'danger')
                return redirect(url_for('admin.create_user'))

            # Create user
            new_user = User(email=email,  # type: ignore
                            full_name=full_name,
                            role=role,
                            student_id=student_id if student_id else None,
                            department=department if department else None,
                            year=int(year) if year else None,
                            phone=phone if phone else None,
                            created_by_admin_id=admin_user.id,
                            force_password_reset=True,
                            is_active=True)
            new_user.set_password(password)

            db.session.add(new_user)
            db.session.commit()

            log_audit(user_id=admin_user.id,
                      action='USER_CREATED',
                      entity_type='User',
                      entity_id=new_user.id,
                      details=f'Created user: {email} with role {role}',
                      ip_address=request.remote_addr)

            flash(
                f'User {full_name} created successfully! They must change password on first login.',
                'success')
            return redirect(url_for('admin.list_users'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating user: {str(e)}', 'danger')

    return render_template('admin/create_user.html', user=admin_user)


@admin_bp.route('/users/<int:user_id>/edit', methods=['GET', 'POST'])
@role_required('admin')
def edit_user(user_id):
    """Edit user details"""
    admin_user = get_current_user()
    assert admin_user is not None
    target_user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        try:
            target_user.full_name = request.form.get('full_name')
            target_user.email = request.form.get('email')
            target_user.role = request.form.get('role')
            target_user.student_id = request.form.get('student_id') or None
            target_user.department = request.form.get('department') or None
            year_str = request.form.get('year')
            target_user.year = int(year_str) if year_str else None
            target_user.phone = request.form.get('phone') or None
            target_user.is_active = request.form.get('is_active') == 'true'

            # Check if password reset is requested
            if request.form.get('reset_password'):
                new_password = request.form.get('new_password')
                if new_password:
                    target_user.set_password(new_password)
                    target_user.force_password_reset = True
                    target_user.last_password_change_at = datetime.now(
                        pytz.UTC)

            db.session.commit()

            log_audit(user_id=admin_user.id,
                      action='USER_UPDATED',
                      entity_type='User',
                      entity_id=target_user.id,
                      details=f'Updated user: {target_user.email}',
                      ip_address=request.remote_addr)

            flash(f'User {target_user.full_name} updated successfully!',
                  'success')
            return redirect(url_for('admin.view_user', user_id=user_id))

        except Exception as e:
            db.session.rollback()
            flash(f'Error updating user: {str(e)}', 'danger')

    return render_template('admin/edit_user.html',
                           user=admin_user,
                           target_user=target_user)


@admin_bp.route('/users/<int:user_id>/delete', methods=['POST'])
@role_required('admin')
def delete_user(user_id):
    """Delete a user"""
    admin_user = get_current_user()
    assert admin_user is not None
    target_user = User.query.get_or_404(user_id)

    # Prevent self-deletion
    if target_user.id == admin_user.id:
        flash('Cannot delete your own account', 'danger')
        return redirect(url_for('admin.list_users'))

    # Get admin password for confirmation
    admin_password = request.form.get('admin_password')
    if not admin_password or not admin_user.check_password(admin_password):
        flash('Invalid admin password', 'danger')
        return redirect(url_for('admin.view_user', user_id=user_id))

    try:
        user_email = target_user.email
        db.session.delete(target_user)
        db.session.commit()

        log_audit(user_id=admin_user.id,
                  action='USER_DELETED',
                  details=f'Deleted user: {user_email}',
                  ip_address=request.remote_addr)

        flash(f'User {user_email} deleted successfully', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f'Error deleting user: {str(e)}', 'danger')

    return redirect(url_for('admin.list_users'))


@admin_bp.route('/subjects/create', methods=['GET', 'POST'])
@role_required('admin')
def create_subject():
    """Admin creates a new subject for teachers"""
    admin_user = get_current_user()
    assert admin_user is not None

    if request.method == 'POST':
        try:
            name = request.form.get('name')
            code = request.form.get('code')
            description = request.form.get('description')
            teacher_id = request.form.get('teacher_id')

            if not all([name, code, teacher_id]):
                flash('Subject name, code, and teacher are required', 'danger')
                return redirect(url_for('admin.create_subject'))

            # Check if code already exists
            if Subject.query.filter_by(code=code).first():
                flash('Subject code already exists', 'danger')
                return redirect(url_for('admin.create_subject'))

            subject = Subject(name=name,  # type: ignore
                              code=code,
                              description=description,
                              teacher_id=teacher_id)

            db.session.add(subject)
            db.session.commit()

            log_audit(user_id=admin_user.id,
                      action='SUBJECT_CREATED',
                      entity_type='Subject',
                      entity_id=subject.id,
                      details=f'Admin created subject: {code} - {name}',
                      ip_address=request.remote_addr)

            flash(f'Subject "{name}" created successfully!', 'success')
            return redirect(url_for('admin.dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating subject: {str(e)}', 'danger')

    # Get all teachers/employees
    teachers = User.query.filter_by(role='employee', is_active=True).all()
    return render_template('admin/create_subject.html',
                           user=admin_user,
                           teachers=teachers)


@admin_bp.route('/sessions/create', methods=['GET', 'POST'])
@role_required('admin')
def create_session():
    """Admin creates a new session for teachers"""
    admin_user = get_current_user()
    assert admin_user is not None

    if request.method == 'POST':
        try:
            from utils import generate_qr_token, save_qr_code
            import os

            subject_id = request.form.get('subject_id')
            teacher_id = request.form.get('teacher_id')
            location_lat = float(request.form.get('location_lat', 0))
            location_lng = float(request.form.get('location_lng', 0))
            location_name = request.form.get('location_name')
            start_time_str = request.form.get('start_time')
            end_time_str = request.form.get('end_time')
            notes = request.form.get('notes')

            if not all([subject_id, teacher_id, start_time_str, end_time_str]):
                flash('All required fields must be filled', 'danger')
                return redirect(url_for('admin.create_session'))

            # Parse datetime
            start_time = datetime.strptime(start_time_str or '', '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time_str or '', '%Y-%m-%dT%H:%M')

            # Make timezone-aware
            start_time = pytz.UTC.localize(start_time)
            end_time = pytz.UTC.localize(end_time)

            if end_time <= start_time:
                flash('End time must be after start time', 'danger')
                return redirect(url_for('admin.create_session'))

            # Create session
            session_obj = Session(subject_id=subject_id,  # type: ignore
                                  teacher_id=teacher_id,
                                  location_lat=location_lat,
                                  location_lng=location_lng,
                                  location_name=location_name,
                                  start_time=start_time,
                                  end_time=end_time,
                                  notes=notes,
                                  qr_token='temporary')

            db.session.add(session_obj)
            db.session.flush()

            # Generate actual QR token
            qr_token = generate_qr_token(session_obj.id,
                                         start_time.isoformat())
            session_obj.qr_token = qr_token

            # Save QR code image
            qr_filename = f'session_{session_obj.id}.png'
            qr_filepath = os.path.join('static', 'qr_codes', qr_filename)
            save_qr_code(qr_token, session_obj.id, qr_filepath)

            db.session.commit()

            log_audit(
                user_id=admin_user.id,
                action='SESSION_CREATED',
                entity_type='Session',
                entity_id=session_obj.id,
                details=f'Admin created session for subject ID {subject_id}',
                ip_address=request.remote_addr)

            flash('Session created successfully!', 'success')
            return redirect(url_for('admin.dashboard'))

        except Exception as e:
            db.session.rollback()
            flash(f'Error creating session: {str(e)}', 'danger')

    # Get subjects and teachers
    subjects = Subject.query.filter_by(is_active=True).all()
    teachers = User.query.filter_by(role='employee', is_active=True).all()
    return render_template('admin/create_session.html',
                           user=admin_user,
                           subjects=subjects,
                           teachers=teachers)
