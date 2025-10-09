import { defineConfig } from 'vite';
import { resolve } from 'path';

// Obtener la URL del servidor API desde variables de entorno o usar valor por defecto
const apiServerPort = process.env.VITE_SERVER_PORT || 8000;
const apiServerUrl = `http://localhost:${apiServerPort}`;

export default defineConfig({
  // Configuración básica de Vite
  base: '/',

  // Configuración de la compilación
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        demo: resolve(__dirname, 'demo.html')
      }
    }
  },

  // Servidor de desarrollo con proxy para evitar problemas de CORS
  server: {
    port: 5173,
    host: '0.0.0.0',
    proxy: {
      // Configurar proxy para las rutas api_client
      '/api_client': {
        target: apiServerUrl,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => {
          console.log('Ruta original API_CLIENT:', path);

          // Extraer el endpoint de la ruta
          const matches = path.match(/^\/api_client\/([^/?]+)/);
          if (matches) {
            const endpoint = matches[1];
            console.log('Endpoint API_CLIENT detectado:', endpoint);
            return `/api_client/${endpoint}.php`;
          }

          // Redirigir a public/index.php si no hay endpoint específico
          return '/public/index.php';
        }
      },
      // Configurar proxy para las rutas api_server
      '/api_server': {
        target: apiServerUrl,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => {
          console.log('Ruta original API_SERVER:', path);

          // Extraer el endpoint de la ruta
          const matches = path.match(/^\/api_server\/([^/?]+)/);
          if (matches) {
            const endpoint = matches[1];
            console.log('Endpoint API_SERVER detectado:', endpoint);
            return `/api_server/${endpoint}.php`;
          }

          // Redirigir a public/index.php si no hay endpoint específico
          return '/public/index.php';
        }
      },
      // Configurar proxy para las rutas antiguas sin prefijo
      '^/(get_public_key|get_shared_secret|set_shared_secret|encrypt|decrypt)': {
        target: apiServerUrl,
        changeOrigin: true,
        secure: false,
        rewrite: (path) => {
          console.log('Ruta original sin prefijo:', path);
          return `/public/router.php`;
        }
      }
    },
    cors: true
  },

  // Definir variables de entorno para el cliente
  define: {
    'import.meta.env.VITE_SERVER_PORT': JSON.stringify(apiServerPort)
  }
});
