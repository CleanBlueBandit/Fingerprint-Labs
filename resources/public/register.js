const form = document.getElementById('form');
const message = document.getElementById('message');
const button = form.querySelector('button');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  message.textContent = '';
  button.disabled = true;

  const body = {
    username: form.username.value,
    password: form.password.value
  };

  try {
    const res = await fetch('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(body)
    });
    const data = await res.json();

    if (data.ok) {
      window.location.href = '/dashboard';
    } else {
      message.textContent = data.message;
    }
  } catch (err) {
    message.textContent = 'Could not reach the server.';
  } finally {
    button.disabled = false;
  }
});
