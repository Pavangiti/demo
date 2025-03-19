import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import bcrypt
import os
from statsmodels.tsa.arima.model import ARIMA
from pmdarima import auto_arima  # Auto ARIMA for dynamic model selection

# ----------------- PAGE CONFIGURATION -----------------
st.set_page_config(page_title="Predictive Healthcare Analytics", layout="wide")

# ----------------- DATABASE & FILE PATH SETUP -----------------
DB_FILE = "vaccination_data.db"
USER_DB = "users.db"
DATASET_PATH = "finald.xlsx"

def create_connection(db_path):
    return sqlite3.connect(db_path, check_same_thread=False)

def setup_user_database():
    conn = create_connection(USER_DB)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT UNIQUE,
                        password TEXT
                      )''')
    conn.commit()
    conn.close()

def setup_vaccination_database():
    conn = create_connection(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS vaccination_data (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        STATE TEXT,
                        CITY TEXT,
                        AGE_GROUP TEXT,
                        GENDER TEXT,
                        ETHNICITY TEXT,
                        VACCINATED BOOLEAN,
                        Year INTEGER,
                        DESCRIPTION TEXT
                      )''')
    conn.commit()
    conn.close()

def is_data_present():
    conn = create_connection(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM vaccination_data")
    count = cursor.fetchone()[0]
    conn.close()
    return count > 0

def load_data_into_db():
    if not is_data_present():
        if os.path.exists(DATASET_PATH):
            df = pd.read_excel(DATASET_PATH)
            conn = create_connection(DB_FILE)
            df.to_sql("vaccination_data", conn, if_exists="replace", index=False)
            conn.close()
            st.success("✅ Data loaded into the database successfully!")
        else:
            st.error("❌ Error: File not found at the specified path!")
            st.stop()

setup_user_database()
setup_vaccination_database()
load_data_into_db()

# ----------------- USER AUTHENTICATION SYSTEM -----------------
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def authenticate_user(username, password):
    conn = create_connection(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    stored_password = cursor.fetchone()
    conn.close()
    return stored_password and bcrypt.checkpw(password.encode(), stored_password[0].encode())

def user_exists(username):
    conn = create_connection(USER_DB)
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
    conn.close()
    return user

def add_user(username, password):
    conn = create_connection(USER_DB)
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hash_password(password)))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        return False

def login_page():
    st.title("🔑 Secure Login")
    username = st.text_input("👤 Username")
    password = st.text_input("🔑 Password", type="password")
    if st.button("Login"):
        if authenticate_user(username, password):
            st.session_state["authenticated"] = True
            st.session_state["username"] = username
            st.rerun()
        else:
            st.error("❌ Invalid credentials. Try again.")
    if st.button("Sign Up"):
        st.session_state["signup"] = True
        st.rerun()

def signup_page():
    st.title("📝 Create Account")
    username = st.text_input("👤 Choose Username")
    password = st.text_input("🔑 Choose Password", type="password")
    confirm_password = st.text_input("🔑 Confirm Password", type="password")
    if st.button("Sign Up"):
        if password != confirm_password:
            st.error("❌ Passwords do not match.")
        elif user_exists(username):
            st.error("❌ Username already exists.")
        else:
            if add_user(username, password):
                st.success("✅ Account created successfully!")
                st.session_state["signup"] = False
                st.rerun()
    if st.button("Go to Login"):
        st.session_state["signup"] = False
        st.rerun()

if "authenticated" not in st.session_state:
    st.session_state["authenticated"] = False
if "signup" not in st.session_state:
    st.session_state["signup"] = False

if not st.session_state["authenticated"]:
    if st.session_state["signup"]:
        signup_page()
    else:
        login_page()
    st.stop()

st.title("📊 Predictive Healthcare Analytics")
if st.sidebar.button("Logout"):
    st.session_state["authenticated"] = False
    st.rerun()

conn = create_connection(DB_FILE)
df = pd.read_sql("SELECT * FROM vaccination_data", conn)
conn.close()

st.write("### 🔍 Raw Data Preview")
st.dataframe(df.head())

st.sidebar.header("🔍 Filter Data")
state = st.sidebar.selectbox("📍 Select State", df["STATE"].dropna().unique())
city = st.sidebar.selectbox("🏙 Select City", df[df["STATE"] == state]["CITY"].dropna().unique())
vaccine = st.sidebar.multiselect("💉 Select Vaccine Type", df["DESCRIPTION"].dropna().unique())

filtered_df = df[(df["STATE"] == state) & (df["CITY"] == city) & (df["DESCRIPTION"].isin(vaccine))]
st.dataframe(filtered_df)

st.plotly_chart(px.pie(filtered_df, names="ETHNICITY", title="Ethnicity Distribution"))
st.plotly_chart(px.pie(filtered_df, names="GENDER", title="Gender Distribution"))
st.plotly_chart(px.bar(filtered_df, x="AGE_GROUP", color="VACCINATED", title="Vaccination by Age Group"))
