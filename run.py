from app import create_app

app = create_app()

with app.app_context():
    # Initialize the database within the application context
    from app.db import init_db
    init_db()

if __name__ == "__main__":
    app.run(debug=True,host='0.0.0.0')
