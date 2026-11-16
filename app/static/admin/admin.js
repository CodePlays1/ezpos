'use strict';

(() => {
  const apiRoot = '/api/v1/admin';
  const setupPanel = document.querySelector('#setup-panel');
  const setupForm = document.querySelector('#setup-form');
  const loginPanel = document.querySelector('#login-panel');
  const loginForm = document.querySelector('#login-form');
  const createForm = document.querySelector('#create-form');
  const workspace = document.querySelector('#workspace');
  const notice = document.querySelector('#notice');
  const rows = document.querySelector('#license-rows');
  const newCode = document.querySelector('#new-code');
  const codeValue = document.querySelector('#code-value');
  let credentials = null;
  let signingReady = false;

  function basicAuthorization(username, password) {
    const bytes = new TextEncoder().encode(`${username}:${password}`);
    let binary = '';
    for (const byte of bytes) binary += String.fromCharCode(byte);
    return `Basic ${btoa(binary)}`;
  }

  function showNotice(message, isError = false) {
    notice.textContent = message;
    notice.classList.toggle('error', isError);
    notice.hidden = false;
  }

  async function request(path, options = {}) {
    const response = await fetch(`${apiRoot}${path}`, {
      ...options,
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/json',
        ...(credentials
          ? { Authorization: basicAuthorization(credentials.username, credentials.password) }
          : {}),
        ...options.headers
      }
    });
    const result = response.status === 204 ? null : await response.json();
    if (!response.ok) {
      throw new Error(result?.error?.message || `Request failed (${response.status}).`);
    }
    return result;
  }

  function addCell(row, value) {
    const cell = document.createElement('td');
    cell.textContent = value || '—';
    row.append(cell);
    return cell;
  }

  function shortFingerprint(value) {
    return value ? `${value.slice(0, 8)}…${value.slice(-6)}` : 'Not activated';
  }

  function renderLicenses(licenses) {
    rows.replaceChildren();
    if (!licenses.length) {
      const row = document.createElement('tr');
      const cell = addCell(row, 'No customer licenses yet.');
      cell.colSpan = 7;
      cell.className = 'empty';
      rows.append(row);
      return;
    }
    for (const license of licenses) {
      const row = document.createElement('tr');
      addCell(row, license.username);
      addCell(row, license.customer_name);
      addCell(row, license.license_id);
      addCell(row, shortFingerprint(license.device_fingerprint));
      const status = addCell(row, license.status);
      status.textContent = '';
      const badge = document.createElement('span');
      badge.className = `status${license.status === 'revoked' ? ' revoked' : ''}`;
      badge.textContent = license.status;
      status.append(badge);
      addCell(row, new Date(license.created_at).toLocaleDateString());
      const actions = document.createElement('td');
      actions.className = 'row-actions';
      if (license.status === 'active') {
        const resetCode = document.createElement('button');
        resetCode.type = 'button';
        resetCode.className = 'button secondary';
        resetCode.textContent = 'New code';
        resetCode.addEventListener('click', () => regenerateCode(license.license_id));
        actions.append(resetCode);
        if (license.device_fingerprint) {
          const deactivate = document.createElement('button');
          deactivate.type = 'button';
          deactivate.className = 'button secondary';
          deactivate.textContent = 'Reset device';
          deactivate.addEventListener('click', () => resetDevice(license.license_id));
          actions.append(deactivate);
        }
        const revoke = document.createElement('button');
        revoke.type = 'button';
        revoke.className = 'button secondary';
        revoke.textContent = 'Revoke';
        revoke.addEventListener('click', () => revokeLicense(license.license_id));
        actions.append(revoke);
      }
      row.append(actions);
      rows.append(row);
    }
  }

  async function refresh() {
    const licenses = await request('/licenses');
    renderLicenses(licenses);
  }

  async function resetDevice(licenseId) {
    if (!window.confirm('Reset this license device binding? The customer can then activate the same code on another device.')) return;
    try {
      await request(`/licenses/${encodeURIComponent(licenseId)}/deactivate`, { method: 'POST' });
      showNotice('Device binding reset. The customer may activate the license again.');
      await refresh();
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  async function revokeLicense(licenseId) {
    if (!window.confirm('Revoke this lifetime license? This cannot be undone.')) return;
    try {
      await request(`/licenses/${encodeURIComponent(licenseId)}/revoke`, {
        method: 'POST',
        body: JSON.stringify({ license_id: licenseId, reason: 'Revoked by administrator' })
      });
      showNotice('License revoked.');
      await refresh();
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  async function regenerateCode(licenseId) {
    if (!window.confirm('Replace this customer activation code? The new code will be shown only once.')) return;
    try {
      const created = await request(
        `/licenses/${encodeURIComponent(licenseId)}/reset-code`,
        { method: 'POST' }
      );
      codeValue.textContent = created.activation_code;
      newCode.hidden = false;
      showNotice(`A new activation code was created for ${created.username}. The previous code no longer works.`);
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  setupForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const values = Object.fromEntries(new FormData(setupForm));
    try {
      const response = await fetch(`${apiRoot}/setup`, {
        method: 'POST',
        headers: { Accept: 'application/json', 'Content-Type': 'application/json' },
        body: JSON.stringify(values)
      });
      const result = await response.json();
      if (!response.ok) throw new Error(result?.error?.message || `Setup failed (${response.status}).`);
      credentials = { username: values.username, password: values.password };
      signingReady = result.signing_ready;
      setupPanel.hidden = true;
      await openWorkspace();
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  loginForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    credentials = {
      username: document.querySelector('#admin-username').value.trim(),
      password: document.querySelector('#admin-password').value
    };
    try {
      if (!signingReady) {
        const response = await request('/unlock', {
          method: 'POST',
          body: JSON.stringify({
            signing_key_password: document.querySelector('#signing-password').value
          })
        });
        signingReady = response.signing_ready;
      }
      await openWorkspace();
    } catch (error) {
      credentials = null;
      showNotice(error.message, true);
    }
  });

  async function openWorkspace() {
    await refresh();
    workspace.hidden = false;
    loginPanel.hidden = true;
    setupPanel.hidden = true;
    document.querySelector('#refresh').disabled = false;
    document.querySelector('#signing-password').value = '';
    showNotice('Dashboard ready. Create and manage customer licenses below.');
  }

  document.querySelector('#refresh').addEventListener('click', async () => {
    try {
      await refresh();
      showNotice('License list refreshed.');
    } catch (error) {
      showNotice(error.message, true);
    }
  });

  createForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const submit = createForm.querySelector('button[type="submit"]');
    submit.disabled = true;
    newCode.hidden = true;
    try {
      const values = Object.fromEntries(new FormData(createForm));
      if (!values.customer_email) delete values.customer_email;
      const created = await request('/licenses', {
        method: 'POST',
        body: JSON.stringify(values)
      });
      codeValue.textContent = created.activation_code;
      newCode.hidden = false;
      createForm.reset();
      showNotice(`License created for ${created.username}. Copy and deliver the activation code now.`);
      await refresh();
    } catch (error) {
      showNotice(error.message, true);
    } finally {
      submit.disabled = false;
    }
  });

  document.querySelector('#copy-code').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText(codeValue.textContent);
      showNotice('License code copied to the clipboard.');
    } catch (error) {
      showNotice(`Could not copy the license code: ${error.message}`, true);
    }
  });

  async function initialize() {
    try {
      const response = await fetch(`${apiRoot}/setup-status`, {
        headers: { Accept: 'application/json' }
      });
      const status = await response.json();
      if (!response.ok) throw new Error(status?.error?.message || `Could not check dashboard setup (${response.status}).`);
      signingReady = status.signing_ready;
      if (status.setup_required) {
        setupPanel.hidden = false;
        const tokenInput = document.querySelector('#setup-token');
        if (status.setup_token) tokenInput.value = status.setup_token;
        else tokenInput.placeholder = 'Enter the one-time setup code from the server logs';
      } else {
        loginPanel.hidden = false;
        document.querySelector('#unlock-label').hidden = signingReady;
        if (status.legacy_admin) {
          showNotice('This server uses legacy admin-key authentication. Configure a dashboard admin account to use username/password sign-in.', true);
        }
      }
    } catch (error) {
      showNotice(error.message, true);
    }
  }

  initialize();
})();
