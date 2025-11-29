from server.app import app

if __name__ == '__main__':
    print("Starting Flask server on http://127.0.0.1:5000")
    print("Ensure you have run 'python client/keygen.py' at least once.")
    app.run(debug=True, port=5000)
