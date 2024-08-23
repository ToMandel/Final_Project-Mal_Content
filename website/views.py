from flask import Blueprint, redirect, render_template, request, flash, jsonify, url_for
from flask_login import login_required, current_user
from .models import Report, Rule, RuleType, ReportType
from bson import ObjectId
import json

views = Blueprint('views', __name__)

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
                new_rule.save()  # Save the rule using MongoEngine
                flash('Rule added!', category='success')
            except Exception as e:
                flash('An error occurred while adding the rule.', category='error')
            return redirect(url_for('views.show_rules'))  # Redirect to avoid form resubmission

    return render_template("./Rules/create_rule.html", user=current_user, RuleType=RuleType)


@views.route('/update-rule/<rule_id>', methods=['GET', 'POST', 'PUT'])
@login_required
def update_rule(rule_id):
    rule = Rule.objects(id=ObjectId(rule_id), user_id=current_user.id).first()
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
                rule.update(data=new_data, data_type=new_data_type)
                flash('Rule updated!', category='success')
            except Exception as e:
                flash('An error occurred while updating the rule.', category='error')
            return redirect(url_for('views.show_rules'))

    return render_template("./Rules/update_rule.html", user=current_user, rule=rule)


@views.route('/delete-rule', methods=['POST'])
@login_required
def delete_rule():
    data = json.loads(request.data)
    rule = Rule.objects(id=ObjectId(data.get('ruleId'))).first()
    if rule and rule.user_id.id == current_user.id:
        rule.delete()  # Delete the rule from the rules collection
        flash('Rule deleted!', category='success')
        return jsonify({'success': True})

    flash('Failed to delete rule!', category='error')
    return jsonify({'success': False})


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
            flash('Report is too short!', category='error')
        else:
            # Call the ML model to predict if the report is toxic or non-toxic
            report_type = ml_model_predict(report_data)  # Replace with your ML model function

            try:
                new_report = Report(
                    data=report_data, 
                    report_type=report_type,  # Set by the ML model
                    user_id=current_user.id
                )
                new_report.save()  # Save the report using MongoEngine
                flash('Report added!', category='success')
            except Exception as e:
                flash('An error occurred while adding the report.', category='error')
            return redirect(url_for('views.show_reports'))  # Redirect to avoid form resubmission

    return render_template("./Reports/create_report.html", user=current_user)

@views.route('/update-report/<report_id>', methods=['GET','POST', 'PUT'])
@login_required
def update_report(report_id):
    report = Report.objects(id=ObjectId(report_id), user_id=current_user.id).first()
    if not report:
        flash('Report not found!', category='error')
        return redirect(url_for('views.show_reports'))

    if request.method == 'POST':
        new_data = request.form.get('report')
        if not new_data or len(new_data.strip()) < 1:
            flash('Report is too short!', category='error')
        else:
            try:
                report.update(data=new_data)
                flash('Report updated!', category='success')
            except Exception as e:
                flash('An error occurred while updating the report.', category='error')
            return redirect(url_for('views.show_reports'))
    
    return render_template("./Reports/update_report.html", user=current_user, report=report)

@views.route('/delete-report', methods=['POST'])
@login_required
def delete_report():
    data = json.loads(request.data)
    report = Report.objects(id=ObjectId(data.get('reportId'))).first()
    if report and report.user_id.id == current_user.id:
        report.delete()  # Delete the report from the reports collection
        flash('Report deleted!', category='success')
        return jsonify({'success': True})

    flash('Failed to delete report!', category='error')
    return jsonify({'success': False})

# Placeholder function for ML model prediction
def ml_model_predict(report_data):
    # Implement your ML model logic here to return 'toxic' or 'non-toxic'
    # Example:
    # return 'toxic' if model.predict(report_data) == 1 else 'non-toxic'
    return ReportType.TOXIC
