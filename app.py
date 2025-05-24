from flask import Flask, render_template, request, redirect, url_for, send_from_directory, flash
import os
from werkzeug.utils import secure_filename
from redaction import RedactionTool

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['REDACTED_FOLDER'] = 'redacted'
app.config['ALLOWED_EXTENSIONS'] = {'pdf', 'png', 'jpg', 'jpeg'}
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
app.secret_key = 'your-secret-key-here'  # Change this in production

# Ensure folders exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['REDACTED_FOLDER'], exist_ok=True)

tool = RedactionTool()

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        # Check if files were uploaded
        if 'files' not in request.files:
            flash('No files selected')
            return redirect(request.url)
        
        files = request.files.getlist('files')
        redaction_types = request.form.getlist('redaction_types')
        
        if not redaction_types:
            redaction_types = ['all_text']  # Default to redacting all text
        
        processed_files = []
        
        for file in files:
            if file and file.filename and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                input_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                output_path = os.path.join(app.config['REDACTED_FOLDER'], filename)
                
                try:
                    file.save(input_path)
                    
                    if filename.lower().endswith(('.jpg', '.jpeg', '.png')):
                        tool.redact_image(input_path, output_path, methods=redaction_types)
                    elif filename.lower().endswith('.pdf'):
                        tool.redact_pdf(input_path, output_path, methods=redaction_types)
                    
                    processed_files.append(filename)
                    
                    # Clean up uploaded file
                    os.remove(input_path)
                    
                except Exception as e:
                    flash(f'Error processing {filename}: {str(e)}')
        
        if processed_files:
            flash(f'Successfully processed {len(processed_files)} file(s)')
            return redirect(url_for('results'))
        else:
            flash('No files were processed successfully')
    
    return render_template('index.html')

@app.route('/results')
def results():
    try:
        redacted_files = os.listdir(app.config['REDACTED_FOLDER'])
        redacted_files = [f for f in redacted_files if allowed_file(f)]
    except FileNotFoundError:
        redacted_files = []
    
    return render_template('results.html', files=redacted_files)

@app.route('/download/<filename>')
def download(filename):
    return send_from_directory(app.config['REDACTED_FOLDER'], filename, as_attachment=True)

@app.route('/clear')
def clear_files():
    """Clear all redacted files"""
    try:
        for filename in os.listdir(app.config['REDACTED_FOLDER']):
            file_path = os.path.join(app.config['REDACTED_FOLDER'], filename)
            os.remove(file_path)
        flash('All files cleared successfully')
    except Exception as e:
        flash(f'Error clearing files: {str(e)}')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)