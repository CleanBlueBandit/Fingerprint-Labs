(() => {
  const welcome = document.getElementById('welcome');
  const since = document.getElementById('since');
  const message = document.getElementById('message');
  const logout = document.getElementById('logout');

  async function loadUser() {
    try {
      const res = await fetch('/auth/me', { cache: 'no-store' });

      if (res.status === 401) {
        window.location.href = '/login';
        return;
      }

      const data = await res.json();
      if (!data.ok) throw new Error(data.message);

      // textContent, never innerHTML: the username is user-supplied
      welcome.textContent = `Signed in as ${data.user.username}.`;
      since.textContent = `Member since ${new Date(data.user.createdAt).toLocaleDateString()}.`;
    } catch (err) {
      welcome.textContent = '';
      message.textContent = 'Could not load your account.';
    }
  }

  logout.addEventListener('click', async () => {
    logout.disabled = true;
    message.textContent = '';

    try {
      const res = await fetch('/auth/logout', { method: 'POST' });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      window.location.href = '/login';
    } catch (err) {
      message.textContent = 'Could not log out. Try again.';
      logout.disabled = false;
    }
  });

  loadUser();
})();
