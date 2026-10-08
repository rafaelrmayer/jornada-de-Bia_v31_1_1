/* Jornada de Bia v31.1 - SecurityService
 * Client-side protection only: this is not a substitute for server authentication.
 */
(() => {
  const PIN_KEY = 'guardianPinHash';
  const LEGACY_PIN_KEY = 'guardianPin';
  const SESSION_KEY = 'jornadaGuardianUnlocked';
  const ATTEMPTS_KEY = 'jornadaGuardianAttempts';
  const MAX_ATTEMPTS = 5;
  const LOCK_MS = 30_000;
  const ITERATIONS = 120_000;

  const enc = new TextEncoder();
  const toB64 = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes)));
  const fromB64 = str => Uint8Array.from(atob(str), c => c.charCodeAt(0));

  async function derive(pin, salt) {
    const material = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
    return crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: ITERATIONS, hash: 'SHA-256' }, material, 256);
  }

  async function makeHash(pin) {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const hash = await derive(pin, salt);
    return `pbkdf2-sha256:${ITERATIONS}:${toB64(salt)}:${toB64(hash)}`;
  }

  async function verifyHash(pin, stored) {
    const parts = String(stored || '').split(':');
    if (parts.length !== 4 || parts[0] !== 'pbkdf2-sha256') return false;
    const iterations = Number(parts[1]);
    if (!Number.isInteger(iterations) || iterations < 10000 || iterations > 500000) return false;
    const material = await crypto.subtle.importKey('raw', enc.encode(pin), 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name:'PBKDF2', salt:fromB64(parts[2]), iterations, hash:'SHA-256' }, material, 256);
    const a = new Uint8Array(bits), b = fromB64(parts[3]);
    if (a.length !== b.length) return false;
    let diff = 0; for (let i=0;i<a.length;i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function attempts() {
    try { return JSON.parse(sessionStorage.getItem(ATTEMPTS_KEY) || '{}'); } catch { return {}; }
  }
  function saveAttempts(v) { sessionStorage.setItem(ATTEMPTS_KEY, JSON.stringify(v)); }

  window.SecurityService = {
    async hasPin() {
      if (localStorage.getItem(PIN_KEY)) return true;
      const legacy = localStorage.getItem(LEGACY_PIN_KEY);
      if (/^\d{4}$/.test(legacy || '')) {
        const hashed = await makeHash(legacy);
        localStorage.setItem(PIN_KEY, hashed);
        localStorage.removeItem(LEGACY_PIN_KEY);
        return true;
      }
      return false;
    },
    async migrateLegacyPin() {
      return this.hasPin();
    },
    async setPin(pin) {
      if (!/^\d{4}$/.test(pin || '')) throw new Error('PIN inválido');
      localStorage.setItem(PIN_KEY, await makeHash(pin));
      sessionStorage.removeItem(ATTEMPTS_KEY);
    },
    async verifyPin(pin) {
      const now = Date.now();
      const a = attempts();
      if (a.lockUntil && now < a.lockUntil) return { ok:false, reason:'locked', remaining:0 };
      if (!/^\d{4}$/.test(pin || '')) return { ok:false, reason:'invalid', remaining:MAX_ATTEMPTS };
      await this.hasPin();
      const stored = localStorage.getItem(PIN_KEY);
      if (!stored) return { ok:false, reason:'missing', remaining:MAX_ATTEMPTS };
      const ok = await verifyHash(pin, stored);
      if (ok) { saveAttempts({ count:0, lockUntil:0 }); return { ok:true, remaining:MAX_ATTEMPTS }; }
      const count = (a.count || 0) + 1;
      if (count >= MAX_ATTEMPTS) { saveAttempts({ count, lockUntil:now + LOCK_MS }); return { ok:false, reason:'locked', remaining:0 }; }
      saveAttempts({ count, lockUntil:0 });
      return { ok:false, reason:'wrong', remaining:MAX_ATTEMPTS-count };
    },
    isLocked() { const a=attempts(); return !!(a.lockUntil && Date.now()<a.lockUntil); },
    isUnlocked() { return sessionStorage.getItem(SESSION_KEY) === 'true'; },
    setSessionUnlocked(value) {
      if (value) {
        sessionStorage.setItem(SESSION_KEY,'true');
        window.JornadaBiaSecurity?.touch?.();
      } else {
        sessionStorage.removeItem(SESSION_KEY);
        sessionStorage.removeItem('jornadaBia:guardianSessionAt');
      }
    }
  };
})();
