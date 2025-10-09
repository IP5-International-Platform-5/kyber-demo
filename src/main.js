import './style.css'

// Inicialización principal de la aplicación Kyber
console.log('Aplicación Kyber iniciada correctamente')

// Detectar si estamos en la página principal
if (document.querySelector('#app')) {
  // Agregar estilos adicionales al body para asegurar centrado
  document.body.style.display = 'flex';
  document.body.style.justifyContent = 'center';
  document.body.style.alignItems = 'center';
  document.body.style.minHeight = '100vh';
  document.body.style.margin = '0';
  document.body.style.padding = '0';

  document.querySelector('#app').innerHTML = `
    <div class="container">
      <h1>Kyber Post-Quantum Communication Protocol</h1>
      <p>Demo de la API cliente-servidor: <a href="/demo">Demo</a></p>
    </div>
  `
}
