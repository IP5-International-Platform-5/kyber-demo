import './style.css'

// Main Kyber app bootstrap
console.log('Kyber app started')

// Home page: center the #app shell
if (document.querySelector('#app')) {
  // Extra body styles so the landing block is centered
  document.body.style.display = 'flex'
  document.body.style.justifyContent = 'center'
  document.body.style.alignItems = 'center'
  document.body.style.minHeight = '100vh'
  document.body.style.margin = '0'
  document.body.style.padding = '0'

  document.querySelector('#app').innerHTML = `
    <div class="container home">
      <h1>Kyber Post-Quantum Communication Protocol</h1>
      <p class="lead">
        Kyber (ML-KEM) is built for a world where today’s public-key math might break.
        This stack exposes it through PHP and liboqs so you can try real encapsulation and shared secrets—not just slides.
      </p>
      <p>
        <a href="/demo" class="cta">Open the interactive demo</a>
        — same browser, two logical roles, every step visible from keygen to decrypt.
      </p>
      <p class="meta">
        API surface: <code>/app</code> and <code>/api_server</code> · details in the README.
      </p>
    </div>
  `
}
