import React, { useEffect, useState } from 'react';
import LoginButtons from './components/LoginButtons';
import Profile from './components/Profile';

function App() {
  const [token, setToken] = useState(null);

  useEffect(() => {
    // If redirected from OAuth, get token from query
    const params = new URLSearchParams(window.location.search);
    const t = params.get("token");
    if (t) {
      setToken(t);
      localStorage.setItem("auth_token", t);
      window.history.replaceState({}, document.title, "/");
    } else {
      const saved = localStorage.getItem("auth_token");
      if (saved) setToken(saved);
    }
  }, []);

  return (
    <div style={{ padding: "20px" }}>
      <h1>OAuth2 Login Demo</h1>
      {!token && <LoginButtons />}
      <Profile token={token} />
    </div>
  );
}

export default App;