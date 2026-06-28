import { defineConfig } from 'vite';
import { resolve } from 'path';

// Backend URL: default local PHP port; in Docker dev set VITE_DEV_PROXY_TARGET=http://web
const apiServerPort = process.env.VITE_SERVER_PORT || 8000;
const proxyTarget =
  process.env.VITE_DEV_PROXY_TARGET ||
  `http://localhost:${apiServerPort}`;

const isDockerDev = Boolean(process.env.VITE_DOCKER_DEV);

// Shared proxy for `vite dev` and `vite preview` so /app and /api_server hit PHP instead of index.html
const apiProxy = {
  '/app': {
    target: proxyTarget,
    changeOrigin: true,
    secure: false,
    rewrite: (path) => {
      // Map /app/foo -> /app/foo.php (user app backend)
      const matches = path.match(/^\/app\/([^/?]+)/);
      if (matches) {
        const endpoint = matches[1];
        return `/app/${endpoint}.php`;
      }
      return '/public/index.php';
    }
  },
  '/api_server': {
    target: proxyTarget,
    changeOrigin: true,
    secure: false,
    rewrite: (path) => {
      // Map /api_server/foo -> /api_server/foo.php
      const matches = path.match(/^\/api_server\/([^/?]+)/);
      if (matches) {
        const endpoint = matches[1];
        return `/api_server/${endpoint}.php`;
      }
      return '/public/index.php';
    }
  },
  // Legacy unprefixed routes (if router is present on the PHP side)
  '^/(get_public_key|get_shared_secret|set_shared_secret|encrypt|decrypt)': {
    target: proxyTarget,
    changeOrigin: true,
    secure: false,
    rewrite: () => '/public/router.php'
  }
};

/** /demo -> demo.html (same as Nginx / .htaccess) */
function demoRoutePlugin() {
  return {
    name: 'kyber-demo-route',
    configureServer(server) {
      server.middlewares.use((req, _res, next) => {
        const url = req.url?.split('?')[0] ?? '';
        if (url === '/demo' || url === '/demo/') {
          const qs = req.url?.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
          req.url = `/demo.html${qs}`;
        }
        next();
      });
    }
  };
}

export default defineConfig({
  base: '/',

  plugins: [demoRoutePlugin()],

  // Production bundle (includes demo.html as a second entry)
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

  // Dev server: proxies API calls to PHP; serves source files — refresh manually (F5)
  server: {
    port: 5173,
    host: '0.0.0.0',
    proxy: apiProxy,
    cors: true,
    hmr: false,
    headers: {
      'Cache-Control': 'no-store'
    },
    // Docker bind mounts (esp. Windows) may miss file events without polling
    watch: isDockerDev ? { usePolling: true, interval: 300 } : undefined
  },

  // `vite preview` uses the same API proxy as dev
  preview: {
    port: 4173,
    host: '0.0.0.0',
    proxy: apiProxy
  },

  // Expose default API port to client bundles if needed
  define: {
    'import.meta.env.VITE_SERVER_PORT': JSON.stringify(apiServerPort)
  }
});
