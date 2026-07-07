import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import axios from 'axios';

const AuthContext = createContext(null);
export const useAuth = () => useContext(AuthContext);

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

// Configure axios once
axios.defaults.withCredentials = true;

export function AuthProvider({ children }) {
  // null = checking; user object = authed; false = anonymous (guest)
  const [user, setUser] = useState(null);
  const [error, setError] = useState('');

  const check = useCallback(async () => {
    try {
      const { data } = await axios.get(`${BACKEND_URL}/api/auth/me`, { withCredentials: true });
      setUser(data);
    } catch (e) {
      setUser(false);
    }
  }, []);

  useEffect(() => { check(); }, [check]);

  const login = async (email, password) => {
    setError('');
    try {
      const { data } = await axios.post(
        `${BACKEND_URL}/api/auth/login`,
        { email, password },
        { withCredentials: true }
      );
      setUser(data.user);
      return { ok: true };
    } catch (e) {
      const msg = formatErr(e.response?.data?.detail) || e.message;
      setError(msg);
      return { ok: false, error: msg };
    }
  };

  const register = async (email, password, name) => {
    setError('');
    try {
      const { data } = await axios.post(
        `${BACKEND_URL}/api/auth/register`,
        { email, password, name },
        { withCredentials: true }
      );
      setUser(data.user);
      return { ok: true };
    } catch (e) {
      const msg = formatErr(e.response?.data?.detail) || e.message;
      setError(msg);
      return { ok: false, error: msg };
    }
  };

  const logout = async () => {
    try {
      await axios.post(`${BACKEND_URL}/api/auth/logout`, {}, { withCredentials: true });
    } catch (e) {
      // Non-fatal: server-side session may already be invalid; frontend still clears state
    }
    setUser(false);
  };

  const ctxValue = useMemo(
    () => ({ user, login, register, logout, check, error, setError }),
    [user, error, check],
  );

  return (
    <AuthContext.Provider value={ctxValue}>
      {children}
    </AuthContext.Provider>
  );
}

function formatErr(detail) {
  if (detail == null) return '';
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((e) => e?.msg || JSON.stringify(e)).join(' ');
  if (detail?.msg) return detail.msg;
  return String(detail);
}
