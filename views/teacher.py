from flask import Blueprint, render_template, request, jsonify, session, flash, redirect, url_for, send_file
from auth import login_required, role_required, get_current_user, log_audit
from models import db, Subject, Session, Attendance, User
from utils import generate_qr_token, save_qr_code, calculate_attendance_duration
from datetime import datetime
import pytz
import os
import csv
from io import StringIO, BytesIO

teacher_bp = Blueprint('teacher', __name__, url_prefix='/teacher')

@teacher_bp.route('/dashboard')
@role_required('employee')
def dashboard():
    """Teacher dashboard"""
    user = get_current_user()
    assert user is not None
    
    # Get teacher's subjects
    subjects = Subject.query.filter_by(teacher_id=user.id, is_active=True).all()
    
    # Get upcoming sessions
    now = datetime.now(pytz.UTC)
    upcoming_sessions = Session.query.filter(
        Session.teacher_id == user.id,
        Session.start_time > now,
        Session.is_active == True
    ).order_by(Session.start_time).limit(10).all()
    
    # Get today's sessions
    today_start = now.replace(hour=0, minute=0, second=0, microsecond=0)
    today_end = now.replace(hour=23, minute=59, second=59, microsecond=999999)
    
    today_sessions = Session.query.filter(
        Session.teacher_id == user.id,
        Session.start_time >= today_start,
        Session.start_time <= today_end,
        Session.is_active == True
    ).order_by(Session.start_time).all()
    
    return render_template('teacher/dashboard.html',
                         user=user,
                         subjects=subjects,
                         upcoming_sessions=upcoming_sessions,
                         today_sessions=today_sessions)

@teacher_bp.route('/sessions/<int:session_id>')
@role_required('employee')
def view_session(session_id):
    """View session details and QR code"""
    user = get_current_user()
    assert user is not None
    session_obj = Session.query.get_or_404(session_id)
    
    if session_obj.teacher_id != user.id:
        flash('You do not have permission to view this session', 'danger')
        return redirect(url_for('teacher.dashboard'))
    
    # Check if QR code file exists, regenerate if missing
    qr_filename = f'session_{session_obj.id}.png'
    qr_filepath = os.path.join('static', 'qr_codes', qr_filename)
    
    if not os.path.exists(qr_filepath):
        try:
            # Regenerate QR code if missing
            qr_token = session_obj.qr_token
            if not qr_token or qr_token == 'temporary':
                qr_token = generate_qr_token(session_obj.id, session_obj.start_time.isoformat())
                session_obj.qr_token = qr_token
                db.session.commit()
            
            save_qr_code(qr_token, session_obj.id, qr_filepath)
        except Exception as e:
            flash(f'Warning: Could not generate QR code. Error: {str(e)}', 'warning')
    
    # Get attendance records
    attendance_records = Attendance.query.filter_by(session_id=session_id).all()
    
    # Count verified attendance
    verified_count = sum(1 for a in attendance_records if a.verification_status == 'VERIFIED')
    
    return render_template('teacher/view_session.html',
                         user=user,
                         session=session_obj,
                         attendance_records=attendance_records,
                         verified_count=verified_count)

@teacher_bp.route('/sessions/<int:session_id>/attendance')
@role_required('employee')
def session_attendance(session_id):
    """View attendance for a session"""
    user = get_current_user()
    assert user is not None
    session_obj = Session.query.get_or_404(session_id)
    
    if session_obj.teacher_id != user.id:
        flash('You do not have permission to view this session', 'danger')
        return redirect(url_for('teacher.dashboard'))
    
    attendance_records = Attendance.query.filter_by(session_id=session_id).order_by(Attendance.timestamp).all()
    
    return render_template('teacher/session_attendance.html',
                         user=user,
                         session=session_obj,
                         attendance_records=attendance_records)

@teacher_bp.route('/sessions/<int:session_id>/export_csv')
@role_required('employee')
def export_csv(session_id):
    """Export attendance to CSV"""
    user = get_current_user()
    assert user is not None
    session_obj = Session.query.get_or_404(session_id)
    
    if session_obj.teacher_id != user.id:
        flash('You do not have permission to export this session', 'danger')
        return redirect(url_for('teacher.dashboard'))
    
    attendance_records = Attendance.query.filter_by(session_id=session_id).order_by(Attendance.timestamp).all()
    
    # Create CSV in memory
    output = StringIO()
    writer = csv.writer(output)
    
    # Write header
    writer.writerow(['Student Name', 'Student ID', 'Email', 'Status', 'Distance (m)', 'Timestamp', 'IP Address'])
    
    # Write data
    for record in attendance_records:
        writer.writerow([
            record.student.full_name,
            record.student.student_id,
            record.student.email,
            record.verification_status,
            f'{record.distance_meters:.1f}',
            record.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            record.ip_address
        ])
    
    # Convert to bytes
    output.seek(0)
    csv_bytes = BytesIO(output.getvalue().encode('utf-8'))
    
    filename = f'attendance_session_{session_id}_{datetime.now().strftime("%Y%m%d")}.csv'
    
    log_audit(
        user_id=user.id,
        action='CSV_EXPORTED',
        entity_type='Session',
        entity_id=session_id,
        details=f'Exported attendance CSV for session {session_id}',
        ip_address=request.remote_addr
    )
    
    return send_file(
        csv_bytes,
        mimetype='text/csv',
        as_attachment=True,
        download_name=filename
    )

@teacher_bp.route('/sessions/create', methods=['GET', 'POST'])
@role_required('employee')
def create_session():
    """Employee creates a new session for their subjects"""
    user = get_current_user()
    assert user is not None
    
    if request.method == 'POST':
        try:
            subject_id = request.form.get('subject_id')
            location_lat = float(request.form.get('location_lat', 0))
            location_lng = float(request.form.get('location_lng', 0))
            location_name = request.form.get('location_name')
            start_time_str = request.form.get('start_time')
            end_time_str = request.form.get('end_time')
            notes = request.form.get('notes')
            is_compensation = request.form.get('is_compensation') == 'on'
            compensates_session_id = request.form.get('compensates_session_id')
            
            if not all([subject_id, start_time_str, end_time_str]):
                flash('All required fields must be filled', 'danger')
                return redirect(url_for('teacher.create_session'))
            
            # Verify teacher owns this subject
            subject = Subject.query.get(subject_id)
            if not subject or subject.teacher_id != user.id:
                flash('You can only create sessions for your own subjects', 'danger')
                return redirect(url_for('teacher.create_session'))
            
            # Parse datetime
            start_time = datetime.strptime(start_time_str or '', '%Y-%m-%dT%H:%M')
            end_time = datetime.strptime(end_time_str or '', '%Y-%m-%dT%H:%M')
            
            # Make timezone-aware
            start_time = pytz.UTC.localize(start_time)
            end_time = pytz.UTC.localize(end_time)
            
            if end_time <= start_time:
                flash('End time must be after start time', 'danger')
                return redirect(url_for('teacher.create_session'))
            
            # Create session
            session_obj = Session(  # type: ignore
                subject_id=subject_id,
                teacher_id=user.id,
                location_lat=location_lat,
                location_lng=location_lng,
                location_name=location_name,
                start_time=start_time,
                end_time=end_time,
                notes=notes,
                is_compensation=is_compensation,
                compensates_session_id=int(compensates_session_id) if compensates_session_id else None,
                qr_token='temporary'
            )
            
            db.session.add(session_obj)
            db.session.flush()
            
            # Generate actual QR token
            qr_token = generate_qr_token(session_obj.id, start_time.isoformat())
            session_obj.qr_token = qr_token
            
            # Save QR code image
            qr_filename = f'session_{session_obj.id}.png'
            qr_filepath = os.path.join('static', 'qr_codes', qr_filename)
            save_qr_code(qr_token, session_obj.id, qr_filepath)
            
            db.session.commit()
            
            log_audit(
                user_id=user.id,
                action='SESSION_CREATED',
                entity_type='Session',
                entity_id=session_obj.id,
                details=f'Teacher created session for {subject.name}' + (' (Compensation)' if is_compensation else ''),
                ip_address=request.remote_addr
            )
            
            flash(f'Session created successfully! Session ID: {session_obj.id}', 'success')
            return redirect(url_for('teacher.view_session', session_id=session_obj.id))
            
        except ValueError as e:
            flash(f'Invalid input: {str(e)}', 'danger')
            return redirect(url_for('teacher.create_session'))
        except Exception as e:
            db.session.rollback()
            flash(f'Error creating session: {str(e)}', 'danger')
            return redirect(url_for('teacher.create_session'))
    
    # GET request - show form
    subjects = Subject.query.filter_by(teacher_id=user.id, is_active=True).all()
    
    # Get past sessions that could be compensated
    past_sessions = Session.query.filter(
        Session.teacher_id == user.id,
        Session.end_time < datetime.now(pytz.UTC),
        Session.is_active == True
    ).order_by(Session.start_time.desc()).limit(20).all()
    
    return render_template('teacher/create_session.html', 
                         user=user, 
                         subjects=subjects,
                         past_sessions=past_sessions)

@teacher_bp.route('/sessions/<int:session_id>/calculate_duration', methods=['POST'])
@role_required('employee')
def calculate_duration(session_id):
    """Calculate attendance duration for a completed session"""
    user = get_current_user()
    assert user is not None
    session_obj = Session.query.get_or_404(session_id)
    
    if session_obj.teacher_id != user.id:
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
    
    success, message, count = calculate_attendance_duration(session_id)
    
    if success:
        log_audit(
            user_id=user.id,
            action='DURATION_CALCULATED',
            entity_type='Session',
            entity_id=session_id,
            details=f'Calculated duration for {count} attendance records',
            ip_address=request.remote_addr
        )
        return jsonify({'success': True, 'message': message, 'updated_count': count})
    else:
        return jsonify({'success': False, 'message': message}), 400

@teacher_bp.route('/sessions/<int:session_id>/refresh_qr')
@role_required('employee')
def refresh_qr(session_id):
    """Regenerate QR code with new timestamp"""
    user = get_current_user()
    assert user is not None
    session_obj = Session.query.get_or_404(session_id)
    
    if session_obj.teacher_id != user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    try:
        current_time = datetime.now(pytz.UTC).isoformat()
        qr_token = generate_qr_token(session_obj.id, current_time)
        session_obj.qr_token = qr_token
        
        qr_filename = f'session_{session_obj.id}.png'
        qr_filepath = os.path.join('static', 'qr_codes', qr_filename)
        save_qr_code(qr_token, session_obj.id, qr_filepath)
        
        db.session.commit()
        
        return jsonify({
            'success': True,
            'qr_url': url_for('static', filename=f'qr_codes/{qr_filename}'),
            'timestamp': current_time
        })
    
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': str(e)}), 500
