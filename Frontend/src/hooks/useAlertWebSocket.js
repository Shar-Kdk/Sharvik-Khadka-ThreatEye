import { useEffect, useRef, useCallback, useState } from 'react';

const WS_BASE = (import.meta.env.VITE_API_URL || 'http://localhost:8000')
  .replace(/\/$/, '')
  .replace(/^http/, 'ws'); // http → ws, https → wss

const RECONNECT_DELAY_MS = 3000; // Retry connection every 3 seconds on disconnect
const MAX_RECONNECT_ATTEMPTS = 20;

/**
 * React hook for real-time alert streaming via WebSocket.
 *
 * Usage:
 *   const { isConnected, connectionStatus } = useAlertWebSocket(token, onNewAlert);
 *
 * @param {string} token - JWT access token for authentication
 * @param {function} onNewAlert - Callback called with the alert object when a new alert arrives
 * @returns {{ isConnected: boolean, connectionStatus: string }}
 */
export default function useAlertWebSocket(token, onNewAlert, onClear) {
  const wsRef = useRef(null);
  const reconnectTimerRef = useRef(null);
  const reconnectAttemptsRef = useRef(0);
  const onNewAlertRef = useRef(onNewAlert);
  const onClearRef = useRef(onClear);
  const [isConnected, setIsConnected] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState('disconnected');

  // Keep callback refs fresh
  useEffect(() => {
    onNewAlertRef.current = onNewAlert;
    onClearRef.current = onClear;
  }, [onNewAlert, onClear]);

  const connect = useCallback(() => {
    if (!token) return;

    // Close any existing connection
    if (wsRef.current) {
      wsRef.current.close();
      wsRef.current = null;
    }

    const url = `${WS_BASE}/ws/alerts/?token=${token}`;
    setConnectionStatus('connecting');
    console.log('[WebSocket] Connecting to', url.replace(token, '***'));

    const ws = new WebSocket(url);
    wsRef.current = ws;

    ws.onopen = () => {
      console.log('[WebSocket] Connected ✓');
      setIsConnected(true);
      setConnectionStatus('connected');
      reconnectAttemptsRef.current = 0; // Reset retry counter on success
    };

    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (data.type === 'new_alert' && data.alert) {
          console.log('[WebSocket] New alert received:', data.alert.id, data.alert.message);
          onNewAlertRef.current?.(data.alert);
        } else if (data.type === 'clear_alerts') {
          console.log('[WebSocket] Alerts cleared signal received');
          onClearRef.current?.();
        }
      } catch (err) {
        console.error('[WebSocket] Failed to parse message:', err);
      }
    };

    ws.onclose = (event) => {
      console.log('[WebSocket] Disconnected (code:', event.code, ')');
      setIsConnected(false);
      wsRef.current = null;

      // Don't reconnect if intentionally closed or auth failed
      if (event.code === 4001 || event.code === 4003) {
        setConnectionStatus('auth_failed');
        console.error('[WebSocket] Authentication failed — will not reconnect');
        return;
      }

      // Auto-reconnect with limit
      if (reconnectAttemptsRef.current < MAX_RECONNECT_ATTEMPTS) {
        setConnectionStatus('reconnecting');
        reconnectAttemptsRef.current += 1;
        console.log(
          `[WebSocket] Reconnecting in ${RECONNECT_DELAY_MS}ms (attempt ${reconnectAttemptsRef.current}/${MAX_RECONNECT_ATTEMPTS})`
        );
        reconnectTimerRef.current = setTimeout(connect, RECONNECT_DELAY_MS);
      } else {
        setConnectionStatus('failed');
        console.error('[WebSocket] Max reconnection attempts reached');
      }
    };

    ws.onerror = (err) => {
      console.error('[WebSocket] Error:', err);
      // onclose will fire after this, which handles reconnection
    };
  }, [token]);

  // Connect on mount, reconnect when token changes
  useEffect(() => {
    connect();

    return () => {
      // Cleanup: close socket and clear timers
      if (reconnectTimerRef.current) {
        clearTimeout(reconnectTimerRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [connect]);

  return { isConnected, connectionStatus };
}
