const CACHE_VERSION = 'etude-line-v14';
const STATIC_CACHE = 'etude-line-static-v14';
const DYNAMIC_CACHE = 'etude-line-dynamic-v14';

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
          if (cache !== STATIC_CACHE && cache !== DYNAMIC_CACHE) {
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

  // Fichiers statiques : cache first
  if (url.pathname.startsWith('/static/')) {
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
    
    // Afficher la notification ET jouer le son immédiatement
    event.waitUntil(
      self.registration.showNotification(title || '📚 Étude LINE', options)
        .then(() => {
          // Envoyer message aux clients pour jouer le son
          return self.clients.matchAll({ type: 'window', includeUncontrolled: true });
        })
        .then(clients => {
          console.log('[Service Worker] Envoi message son à', clients.length, 'client(s)');
          clients.forEach(client => {
            client.postMessage({
              type: 'PLAY_NOTIFICATION_SOUND'
            });
          });
          
          // Si aucun client n'est ouvert, le son ne peut pas être joué
          // mais la notification système sera quand même affichée
          if (clients.length === 0) {
            console.log('[Service Worker] Aucun client actif - son impossible');
          }
        })
        .catch(err => {
          console.error('[Service Worker] Erreur notification:', err);
        })
    );
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
