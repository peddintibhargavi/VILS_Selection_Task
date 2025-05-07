import React from 'react';
const BACKEND_URL = "http://localhost:8000"; // Replace with your backend URL

export default function LoginButtons() {
  return (
    <div className="login-container">
      <h2>Sign in with</h2>
      <div className="oauth-buttons">
        <a href={`${BACKEND_URL}/auth/google/login`} className="oauth-button google">
          <div className="icon">
            
          </div>
          <span>Continue with Google</span>
        </a>
        
        <a href={`${BACKEND_URL}/auth/github/login`} className="oauth-button github">
          <div className="icon">
            
          </div>
          <span>Continue with GitHub</span>
        </a>
        
        <a href={`${BACKEND_URL}/auth/microsoft/login`} className="oauth-button microsoft">
          <div className="icon">
           
          </div>
          <span>Continue with Microsoft</span>
        </a>
        
        <a href={`${BACKEND_URL}/auth/facebook/login`} className="oauth-button facebook">
          <div className="icon">
            
          </div>
          <span>Continue with Facebook</span>
        </a>
      </div>
    </div>
  );
}