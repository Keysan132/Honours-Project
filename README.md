When downloaded delete the venv file, after it is deleted within the terminal you will need to do the following:

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
pip install -r requirements.txt
.venv\Scripts\activate
streamlit run app.py

then the application should open in a localhost website
