from flask import Blueprint, render_template, request, flash, redirect, url_for, jsonify, current_app
from flask_login import login_user, login_required, logout_user, current_user
from .models import User, Report, Rule, RuleType, ReportType
import re  # Import the regular expressions module

# Other imports and your Flask routes/functions follow here...


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

from flask import current_app

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
    
    # Preserve more of the original text structure by not replacing all non-word characters
    # text = re.sub(r'\W', ' ', text)  # Comment out or remove this line if you find it alters important words

    text = re.sub(r'\s+', ' ', text)
    text = text.translate(trans_table)
    text = text.strip()
    
    return text


from flask import current_app
from .models import Rule, RuleType

def apply_rules(report_data):
    # Retrieve all rules from the database
    keyword_rules = Rule.objects(data_type=RuleType.KEYWORD)
    phrase_rules = Rule.objects(data_type=RuleType.PHRASE)
    contextual_rules = Rule.objects(data_type=RuleType.CONTEXTUAL)
    
    # Check if any keyword rules match the report data
    for rule in keyword_rules:
        if rule.data.lower() in report_data.lower():
            return True  # Found a match, classify as toxic

    # Check if any phrase rules match the report data
    for rule in phrase_rules:
        if rule.data.lower() in report_data.lower():
            return True  # Found a match, classify as toxic

    # Check if any contextual rules match the report data
    for rule in contextual_rules:
        # Implement more complex logic here if needed for contextual matching
        if rule.data.lower() in report_data.lower():
            return True  # Found a match, classify as toxic

    return False  # No rules matched

def ml_model_predict(report_data):
    # Apply rules first
    if apply_rules(report_data):
        return ReportType.TOXIC

    # If no rules matched, proceed with model prediction
    model = current_app.config['ML_MODEL']
    tfidf_vectorizer = current_app.config['TFIDF_VECTORIZER']

    # Clean the input text
    cleaned_text = clean_text(report_data)

    # Transform the input text using the TF-IDF vectorizer
    transformed_data = tfidf_vectorizer.transform([cleaned_text])

    # Predict using the loaded model
    prediction = model.predict(transformed_data)

    # Assuming the model returns a probability, and you classify as 'toxic' if above a threshold
    return ReportType.TOXIC if prediction > 0.5 else ReportType.NON_TOXIC
