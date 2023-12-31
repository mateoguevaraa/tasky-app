# Tasky - Developer Task Management App
#### Video Demo:  <https://www.youtube.com/watch?v=Nwd9f8ZIUaU&t=2s>
#### Description:

Welcome to Tasky, a powerful task management application designed specifically for developers!

The app.py file contains all the validation logic and the server-side. The databases were very challenging to make, because I have to find the best relationship possible between users, projects and tasks. 
Finally they ended up being like this:

```python
# Tables
class User(UserMixin, db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(30), unique=True, nullable=False)
    verified = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    projects = db.relationship('Project', backref='users', lazy=True)

class Project(db.Model):

    __tablename__ = 'projects'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200))
    tasks = db.relationship('Task', backref='projects', cascade='all, delete-orphan')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Task(db.Model):

    __tablename__ = 'tasks'

    id = db.Column(db.Integer, primary_key=True)
    description = db.Column(db.String(150), nullable=False)
    completed = db.Column(db.Boolean, default=False)
    project_id = db.Column(db.Integer, db.ForeignKey('projects.id'), nullable=False)
```
They worked really well for me.


Inside the templates folder are all of the html files. The index2.html contains the homepage template, then the other templates have very explicit names indicating their function. Talking about design, it was the most difficult and challenging part for me. The home page was redesign the last day because I did not like it. Then the card display for the projects was difficult to get, because i wanted them to be like in a computer or IDE kind of box. Bootstrap cards save me, with them I was able to make them responsive and to look good.

Meanwhile in the static folder you can find the images used in the web app, as well as the favicon. The icon and the images were made in Canvas.

In the Instance folder there is the database which I will not upload for security reasons as well as the flask secret key and the recaptcha key.

Finally the delete and edit functions were pretty tricky too, because I had to ensure that the projects and tasks were deleted from the database as well as edited in the case the user want to edit them.
Here is the edit-task function which was the most difficult:
```python
def edit_task(task_id):
    if request.method == 'POST':
        task = Task.query.get(task_id)
        project_id = task.project_id
        project_name = Project.query.filter_by(id=project_id).first().name

        new_description = request.form.get('task-edit')

        if not new_description or new_description.isspace():
            return redirect(url_for("project_dashboard", project_id=project_id, project_name=project_name))
        
        if len(new_description) > 150:
            flash('Task must be less than 150 characters.', 'input_error')
            return redirect(url_for('edit_task', task_id = task_id))      
        
        try:
            new_description = new_description.capitalize()
        except:
            pass

        task.description = new_description

        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash('An error occured while editing the task. Try Again', 'error')
            return redirect(url_for('edit_task', project_id=project_id, project_name=project_name))

        try:
            db.session.commit()
        except:
            db.session.rollback()
            flash('An error occured while adding the tasks.', 'error')
            return redirect(url_for('add_task', project_id=project_id, project_name=project_name))
        
        return redirect(url_for("project_dashboard", project_id=project_id, project_name=project_name))

    else:
        task_info = Task.query.filter_by(id=task_id).first()
        current_task_description = task_info.description
        project_id = task_info.project_id
        project_name = Project.query.filter_by(id=project_id).first().name

        return render_template('edit-task.html', task_id=task_id, current_task_description=current_task_description, project_name=project_name, project_id=project_id)
```

#### Features

- Efficient Task Tracking: Organize and track your project tasks effortlessly.
- Intuitive Interface: User-friendly design for seamless navigation.
- Cross-Platform Compatibility: Access Tasky on any device, anywhere.
- Task Completion: Mark tasks as complete and streamline your workflow.
- Developer-Focused: Tailored functionalities for developers' unique needs.

#### Usage

Tasky simplifies task management for developers, offering a user-friendly interface and powerful features. Start by signing up, log in and create your first project. Add tasks, mark them as complete, and organize your workflow effortlessly.

#### Technologies Used

HTML, CSS, JavaScript for the frontend
Python Flask for the backend
SQLite database for data storage
Bootstrap for design

##### Contributing
Contributions are welcome! Feel free to fork this repository, make changes, and submit a pull request.