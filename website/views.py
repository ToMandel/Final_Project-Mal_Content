from flask import Blueprint, json, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_required, current_user
from .models import User, Report, Rule, RuleType, ReportType
import re

views = Blueprint('views', __name__)

# Dashboard route
@views.route('/dashboard', methods=['GET'])
@login_required
def dashboard():
    return render_template('dashboard.html', user=current_user)

# RULES
@views.route('/rules', methods=['GET'])
@login_required
def show_rules():
    rules = Rule.objects(user_id=current_user.id)
    return render_template("./Rules/rules.html", user=current_user, rules=rules)

@views.route('/create-rule', methods=['GET', 'POST'])
@login_required
def create_rule():
    if request.method == 'POST':
        rule = request.form.get('rule')
        data_type = request.form.get('data_type')

        if not rule or len(rule.strip()) < 1:
            flash('Rule is too short!', category='error')
        elif not data_type or data_type not in [RuleType.KEYWORD, RuleType.CONTEXTUAL, RuleType.PHRASE]:
            flash('Invalid rule type!', category='error')
        else:
            try:
                new_rule = Rule(data=rule, data_type=data_type, user_id=current_user.id)
                new_rule.save()
                flash('Rule added!', category='success')
            except Exception as e:
                flash('An error occurred while adding the rule.', category='error')
            return redirect(url_for('views.show_rules'))

    return render_template("./Rules/create_rule.html", user=current_user, RuleType=RuleType)

@views.route('/update-rule/<rule_id>', methods=['GET', 'POST'])
@login_required
def update_rule(rule_id):
    rule = Rule.objects(id=rule_id, user_id=current_user.id).first()
    if not rule:
        flash('Rule not found!', category='error')
        return redirect(url_for('views.show_rules'))

    if request.method == 'POST':
        new_data = request.form.get('rule')
        new_data_type = request.form.get('data_type')

        if not new_data or len(new_data.strip()) < 1:
            flash('Rule is too short!', category='error')
        elif not new_data_type or new_data_type not in [RuleType.KEYWORD, RuleType.CONTEXTUAL, RuleType.PHRASE]:
            flash('Invalid rule type!', category='error')
        else:
            try:
                # Update the rule
                rule.update(data=new_data, data_type=new_data_type)
                
                # Re-evaluate all reports
                reports = Report.objects(user_id=current_user.id)
                for report in reports:
                    new_report_type = ml_model_predict(report.data)
                    report.update(report_type=new_report_type)
                
                flash('Rule and reports updated!', category='success')
            except Exception as e:
                flash('An error occurred while updating the rule and reports.', category='error')
            return redirect(url_for('views.show_rules'))

    return render_template("./Rules/update_rule.html", user=current_user, rule=rule)

@views.route('/delete-rule', methods=['POST'])
@login_required
def delete_rule():
    try:
        data = json.loads(request.data)
        rule = Rule.objects(id=data.get('ruleId')).first()
        if rule and rule.user_id.id == current_user.id:
            rule.delete()

            # Re-evaluate all reports
            reports = Report.objects(user_id=current_user.id)
            for report in reports:
                new_report_type = ml_model_predict(report.data)
                report.update(report_type=new_report_type)

            flash('Rule deleted', category='success')
            return jsonify({'success': True})
        else:
            flash('Rule not found or unauthorized!', category='error')
            return jsonify({'success': False})
    except Exception as e:
        flash('An error occurred while deleting the rule.', category='error')
        return jsonify({'success': False, 'error': str(e)})


# REPORTS
@views.route('/', methods=['GET'])
@login_required
def show_reports():
    reports = Report.objects(user_id=current_user.id)
    return render_template("./Reports/reports.html", user=current_user, reports=reports)

@views.route('/create-report', methods=['GET', 'POST'])
@login_required
def create_report():
    if request.method == 'POST':
        report_data = request.form.get('report')

        if not report_data or len(report_data.strip()) < 1:
            flash('Report is too short!', 'error')
            return jsonify({'toxic': False}), 400

        report_type = ml_model_predict(report_data)
        try:
            new_report = Report(
                data=report_data, 
                report_type=report_type,  
                user_id=current_user.id
            )
            new_report.save()
            return jsonify({'toxic': report_type == ReportType.TOXIC}), 200

        except Exception as e:
            flash('An error occurred while adding the report.', 'error')
            return jsonify({'toxic': False}), 500

    return render_template("./Reports/create_report.html", user=current_user)

@views.route('/update-report/<report_id>', methods=['GET', 'POST'])
@login_required
def update_report(report_id):
    report = Report.objects(id=report_id, user_id=current_user.id).first()
    if not report:
        flash('Report not found!', category='error')
        return redirect(url_for('views.show_reports'))

    if request.method == 'POST':
        new_data = request.form.get('report')
        if not new_data or len(new_data.strip()) < 1:
            flash('Report is too short!', category='error')
        else:
            try:
                # Re-evaluate the report based on updated rules
                new_report_type = ml_model_predict(new_data)
                
                # Update the report with the new data and report type
                report.update(data=new_data, report_type=new_report_type)
                flash('Report updated and re-evaluated!', category='success')
            except Exception as e:
                flash('An error occurred while updating the report.', category='error')
            return redirect(url_for('views.show_reports'))
    
    return render_template("./Reports/update_report.html", user=current_user, report=report)


@views.route('/delete-report', methods=['POST', 'DELETE'])
@login_required
def delete_report():
    data = json.loads(request.data)
    report = Report.objects(id=data.get('reportId')).first()
    if report and report.user_id.id == current_user.id:
        report.delete()
        flash('Report deleted!', category='success')
        return jsonify({'success': True})

    flash('Failed to delete report!', category='error')
    return jsonify({'success': False})

# Text processing functions
CHARS_TO_REMOVE = '!"#$%&()*+,-./:;<=>?@[\\]^_`{|}~\t\n“”’\'∞θ÷α•à−β∅³π‘₹´°£€\×™√²—'
trans_table = str.maketrans('', '', CHARS_TO_REMOVE)

def clean_text(text):
    text = text.lower()
    text = re.sub(r"what's", "what is ", text)
    text = re.sub(r"\'s", " ", text)
    text = re.sub(r"\'ve", " have ", text)
    text = re.sub(r"can't", " cannot ", text)
    text = re.sub(r"n't", " not ", text)
    text = re.sub(r"i'm", "i am ", text)
    text = re.sub(r"\'re", " are ", text)
    text = re.sub(r"\'d", " would ", text)
    text = re.sub(r"\'ll", " will ", text)
    text = re.sub(r"\'scuse", " excuse ", text)
    text = re.sub(r'\s+', ' ', text)
    text = text.translate(trans_table)
    text = text.strip()
    return text

def apply_rules(report_data):
    keyword_rules = Rule.objects(data_type=RuleType.KEYWORD)
    phrase_rules = Rule.objects(data_type=RuleType.PHRASE)
    contextual_rules = Rule.objects(data_type=RuleType.CONTEXTUAL)

    for rule in keyword_rules:
        if rule.data.lower() in report_data.lower():
            return True

    for rule in phrase_rules:
        if rule.data.lower() in report_data.lower():
            return True

    for rule in contextual_rules:
        if rule.data.lower() in report_data.lower():
            return True

    return False

def ml_model_predict(report_data):
    if apply_rules(report_data):
        return ReportType.TOXIC

    model = current_app.config['ML_MODEL']
    tfidf_vectorizer = current_app.config['TFIDF_VECTORIZER']

    cleaned_text = clean_text(report_data)
    transformed_data = tfidf_vectorizer.transform([cleaned_text])
    prediction = model.predict(transformed_data)

    return ReportType.TOXIC if prediction > 0.5 else ReportType.NON_TOXIC
