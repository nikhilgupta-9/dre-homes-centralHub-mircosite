document.querySelector('.lead-form').addEventListener('submit', function (e) {
  e.preventDefault();
  fetch('process.php', { method: 'POST', body: new FormData(this) })
    .then(function (r) { return r.text(); })
    .then(function (t) { document.getElementById('msg').innerHTML = t; });
});
