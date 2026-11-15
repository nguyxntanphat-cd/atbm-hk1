'use strict';
document.querySelector('form').addEventListener('submit', async event => {
  event.preventDefault();
  const errorBox = document.getElementById('err');
  const button = event.currentTarget.querySelector('button');
  errorBox.textContent = ''; button.disabled = true;
  try {
    const result = await App.request('/api/login', {
      username: document.getElementById('username').value.trim(),
      password: document.getElementById('password').value
    });
    location.href = result.redirect;
  } catch (error) { errorBox.textContent = error.message; }
  finally { button.disabled = false; }
});
