import React, { useEffect, useState } from 'react';

const BACKEND_URL = "http://localhost:8000";

export default function Profile({ token }) {
  const [user, setUser] = useState(null);
  const [methods, setMethods] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  useEffect(() => {
    async function fetchProfile() {
      try {
        setLoading(true);
        const res = await fetch(`${BACKEND_URL}/auth/me`, {
          headers: { Authorization: `Bearer ${token}` }
        });

        if (!res.ok) {
          throw new Error(`Failed to fetch profile: ${res.statusText}`);
        }

        const data = await res.json();
        setUser(data);
      } catch (err) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    async function fetchMethods() {
      try {
        const res = await fetch(`${BACKEND_URL}/auth/methods`, {
          headers: { Authorization: `Bearer ${token}` }
        });

        if (!res.ok) {
          throw new Error(`Failed to fetch methods: ${res.statusText}`);
        }

        const data = await res.json();
        setMethods(data.providers || []);
      } catch (err) {
        setError(err.message);
      }
    }

    if (token) {
      fetchProfile();
      fetchMethods();
    }
  }, [token]);

  const handleLogout = () => {
    localStorage.removeItem("auth_token");
    window.location.reload(); // Or call a prop function to update state
  };

  if (!token) return <p>Not logged in.</p>;
  if (loading) return <p>Loading...</p>;
  if (error) return <p>Error: {error}</p>;

  return (
    <div className="profile-container">
      <div className="profile-header">
        {user?.profile_picture && (
          <img 
            src={user.profile_picture} 
            alt={`${user.username}'s profile`} 
            className="profile-picture"
          />
        )}
        <h2>Welcome, {user?.full_name || user?.username}</h2>
        <button onClick={handleLogout} className="logout-button" style={{ marginTop: "10px" }}>
          Logout
        </button>
      </div>

      <div className="profile-details">
        <p><strong>Email:</strong> {user?.email}</p>
        {user?.first_name && <p><strong>First Name:</strong> {user.first_name}</p>}
        {user?.last_name && <p><strong>Last Name:</strong> {user.last_name}</p>}
        {user?.full_name && <p><strong>Full Name:</strong> {user.full_name}</p>}
      </div>

      <div className="linked-providers">
        <h3>Linked Providers:</h3>
        {methods.length > 0 ? (
          <ul className="providers-list">
            {methods.map((provider, idx) => (
              <li key={idx} className={`provider-item ${provider.provider}`}>
                <span className="provider-name">{provider.provider} - {provider.provider_user_id}</span>
                <li className="connected-date">
                  {provider.connected_at ? 
                    `Connected on ${new Date(provider.connected_at).toLocaleDateString()}` : 
                    'Connection date unknown'}
                </li>
              </li>
            ))}
          </ul>
        ) : (
          <p>No providers linked.</p>
        )}
      </div>
    </div>
  );
}
