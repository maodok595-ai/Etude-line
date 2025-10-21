const CACHE_VERSION = 'etude-line-v11';
const STATIC_CACHE = 'etude-line-static-v11';
const DYNAMIC_CACHE = 'etude-line-dynamic-v11';
const FONT_CACHE = 'etude-line-fonts-v11';
const IMAGE_CACHE = 'etude-line-images-v11';

// Limite de taille des caches (en nombre d'entrées)
const MAX_CACHE_SIZE = {
  dynamic: 50,
  images: 100,
  fonts: 20
};

const STATIC_ASSETS = [
  '/',
  '/login',
  '/static/offline.html',
  '/static/manifest.json',
  '/static/icons/icon-192.png',
  '/static/icons/icon-512.png'
];

self.addEventListener('install', (event) => {
  console.log('[Service Worker] Installation en cours...');
  event.waitUntil(
    caches.open(STATIC_CACHE)
      .then(cache => {
        console.log('[Service Worker] Mise en cache des assets statiques');
        return cache.addAll(STATIC_ASSETS);
      })
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', (event) => {
  console.log('[Service Worker] Activation en cours...');
  event.waitUntil(
    caches.keys().then(cacheNames => {
      return Promise.all(
        cacheNames.map(cache => {
          if (![STATIC_CACHE, DYNAMIC_CACHE, FONT_CACHE, IMAGE_CACHE].includes(cache)) {
            console.log('[Service Worker] Suppression ancien cache:', cache);
            return caches.delete(cache);
          }
        })
      );
    }).then(() => self.clients.claim())
  );
});

self.addEventListener('fetch', (event) => {
  const { request } = event;
  const url = new URL(request.url);

  if (request.method !== 'GET') {
    return;
  }

  // Fonts : cache first avec cache dédié
  if (url.pathname.match(/\.(woff2?|ttf|otf|eot)$/)) {
    event.respondWith(cacheFirstWithLimit(request, FONT_CACHE, MAX_CACHE_SIZE.fonts));
  }
  // Images : cache first avec cache dédié et limite
  else if (url.pathname.match(/\.(png|jpg|jpeg|webp|svg|gif|ico)$/)) {
    event.respondWith(cacheFirstWithLimit(request, IMAGE_CACHE, MAX_CACHE_SIZE.images));
  }
  // Fichiers statiques CSS/JS : cache first
  else if (url.pathname.startsWith('/static/')) {
    event.respondWith(cacheFirstStrategy(request));
  } 
  // Routes API : network only (jamais de cache)
  else if (url.pathname.startsWith('/api/')) {
    event.respondWith(networkOnlyStrategy(request));
  } 
  // Dashboards et pages dynamiques : network only avec fallback offline (toujours à jour)
  else if (url.pathname.startsWith('/dashboard/')) {
    event.respondWith(networkOnlyWithOfflineFallback(request));
  } 
  // Autres pages (login, homepage) : network first avec fallback cache
  else {
    event.respondWith(networkFirstStrategy(request));
  }
});

async function cacheFirstStrategy(request) {
  const cached = await caches.match(request);
  if (cached) {
    return cached;
  }
  
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(STATIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    console.log('[Service Worker] Erreur cache-first:', error);
    return new Response('Offline', { status: 503 });
  }
}

async function networkFirstStrategy(request) {
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(DYNAMIC_CACHE);
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    const cached = await caches.match(request);
    if (cached) {
      return cached;
    }
    
    const offlinePage = await caches.match('/static/offline.html');
    return offlinePage || new Response('Offline', { 
      status: 503,
      statusText: 'Service Unavailable' 
    });
  }
}

async function networkOnlyStrategy(request) {
  try {
    return await fetch(request);
  } catch (error) {
    return new Response(JSON.stringify({ error: 'Connexion réseau requise' }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' }
    });
  }
}

async function networkOnlyWithOfflineFallback(request) {
  try {
    const response = await fetch(request);
    return response;
  } catch (error) {
    // Pour les pages HTML, afficher la page offline
    const offlinePage = await caches.match('/static/offline.html');
    return offlinePage || new Response('Offline', { 
      status: 503,
      statusText: 'Service Unavailable' 
    });
  }
}

// Stratégie cache-first avec limite de taille
async function cacheFirstWithLimit(request, cacheName, maxSize) {
  const cached = await caches.match(request);
  if (cached) {
    return cached;
  }
  
  try {
    const response = await fetch(request);
    if (response.ok) {
      const cache = await caches.open(cacheName);
      
      // Limiter la taille du cache
      const keys = await cache.keys();
      if (keys.length >= maxSize) {
        // Supprimer le plus ancien
        await cache.delete(keys[0]);
      }
      
      cache.put(request, response.clone());
    }
    return response;
  } catch (error) {
    console.log('[Service Worker] Erreur cache-first-limit:', error);
    return new Response('Offline', { status: 503 });
  }
}

// Nettoyer les caches périodiquement
async function cleanupCaches() {
  try {
    const cacheCleanups = [
      { name: DYNAMIC_CACHE, max: MAX_CACHE_SIZE.dynamic },
      { name: IMAGE_CACHE, max: MAX_CACHE_SIZE.images },
      { name: FONT_CACHE, max: MAX_CACHE_SIZE.fonts }
    ];
    
    for (const { name, max } of cacheCleanups) {
      const cache = await caches.open(name);
      const keys = await cache.keys();
      
      if (keys.length > max) {
        const deleteCount = keys.length - max;
        for (let i = 0; i < deleteCount; i++) {
          await cache.delete(keys[i]);
        }
        console.log(`[Service Worker] Nettoyé ${deleteCount} entrées de ${name}`);
      }
    }
  } catch (error) {
    console.log('[Service Worker] Erreur nettoyage cache:', error);
  }
}

// Nettoyer les caches toutes les heures
setInterval(cleanupCaches, 3600000);

// Gestion des notifications push
self.addEventListener('push', (event) => {
  console.log('[Service Worker] Notification push reçue');
  
  const data = event.data ? event.data.json() : {};
  const title = data.title || '📚 Étude LINE';
  const options = {
    body: data.body || 'Nouvelle notification',
    icon: data.icon || '/static/icons/icon-192.png',
    badge: '/static/icons/icon-192.png',
    vibrate: [200, 100, 200, 100, 200],
    tag: 'etude-line-' + Date.now(),
    requireInteraction: false,
    silent: false,
    renotify: true,
    data: {
      url: data.url || '/',
      timestamp: Date.now()
    }
  };
  
  event.waitUntil(
    self.registration.showNotification(title, options)
  );
});

// Gestion du clic sur les notifications
self.addEventListener('notificationclick', (event) => {
  console.log('[Service Worker] Clic sur notification');
  
  event.notification.close();
  
  const urlToOpen = event.notification.data.url || '/';
  
  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true })
      .then((clientList) => {
        // Si une fenêtre est déjà ouverte, la focus
        for (let client of clientList) {
          if (client.url === urlToOpen && 'focus' in client) {
            return client.focus();
          }
        }
        // Sinon, ouvrir une nouvelle fenêtre
        if (clients.openWindow) {
          return clients.openWindow(urlToOpen);
        }
      })
  );
});

// Gestion de la fermeture des notifications
self.addEventListener('notificationclose', (event) => {
  console.log('[Service Worker] Notification fermée');
});

// Écouter les messages de la page pour afficher des notifications
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SHOW_NOTIFICATION') {
    const { title, body, icon, url } = event.data;
    
    const options = {
      body: body || 'Nouvelle notification',
      icon: icon || '/static/icons/icon-192.png',
      badge: '/static/icons/icon-192.png',
      vibrate: [200, 100, 200, 100, 200],
      tag: 'etude-line-' + Date.now(),
      requireInteraction: false,
      silent: false,
      renotify: true,
      data: {
        url: url || '/',
        timestamp: Date.now()
      }
    };
    
    self.registration.showNotification(title || '📚 Étude LINE', options)
      .then(() => {
        // Envoyer message aux clients pour jouer le son
        return self.clients.matchAll({ type: 'window', includeUncontrolled: true });
      })
      .then(clients => {
        clients.forEach(client => {
          client.postMessage({
            type: 'PLAY_NOTIFICATION_SOUND'
          });
        });
      });
  }
  
  // Mettre à jour le badge de l'icône PWA
  if (event.data && event.data.type === 'UPDATE_BADGE') {
    const count = event.data.count || 0;
    
    if ('setAppBadge' in navigator) {
      if (count > 0) {
        navigator.setAppBadge(count).catch(err => {
          console.log('[Service Worker] Erreur mise à jour badge:', err);
        });
      } else {
        navigator.clearAppBadge().catch(err => {
          console.log('[Service Worker] Erreur effacement badge:', err);
        });
      }
    }
  }
});
