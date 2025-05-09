
# VILS Selection Project

## 🛠️ Backend Setup

### 1. Create and Set Up a Virtual Environment

```bash
# Navigate to the backend directory
cd app

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Windows:
venv\Scripts\activate

# On macOS/Linux:
source venv/bin/activate
```
# start the fast api server
uvicorn main:app --reload --host 0.0.0.0 --port 8000


### 2. Install Dependencies

```bash
pip install -r requirements.txt
```

### 3. Generate JWT Secret Key and PKCE Pairs

```bash
# Generate JWT secret key
python generate_jwt_secret.py

# Generate PKCE pairs for OAuth providers
python generate_pkce_pair.py
```

---

## ⚛️ Frontend Setup (React Application)

### Prerequisites

- Node.js (version 14 or higher)
- npm

### Installation Steps

```bash
# Navigate to the frontend directory
cd frontend

# Install dependencies
npm install

# Start the development server
npm start
```


Your application should now be running with:

Backend API at http://localhost:8000
Frontend at http://localhost:3000