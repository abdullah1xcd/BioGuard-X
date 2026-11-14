/**
 * Copyright 2018 Google Inc. All Rights Reserved.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *     http://www.apache.org/licenses/LICENSE-2.0
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// If the loader is already loaded, just stop.
if (!self.define) {
  let registry = {};

  // Used for `eval` and `importScripts` where we can't get script URL by other means.
  // In both cases, it's safe to use a global var because those functions are synchronous.
  let nextDefineUri;

  const singleRequire = (uri, parentUri) => {
    uri = new URL(uri + ".js", parentUri).href;
    return registry[uri] || (
      
        new Promise(resolve => {
          if ("document" in self) {
            const script = document.createElement("script");
            script.src = uri;
            script.onload = resolve;
            document.head.appendChild(script);
          } else {
            nextDefineUri = uri;
            importScripts(uri);
            resolve();
          }
        })
      
      .then(() => {
        let promise = registry[uri];
        if (!promise) {
          throw new Error(`Module ${uri} didn’t register its module`);
        }
        return promise;
      })
    );
  };

  self.define = (depsNames, factory) => {
    const uri = nextDefineUri || ("document" in self ? document.currentScript.src : "") || location.href;
    if (registry[uri]) {
      // Module is already loading or loaded.
      return;
    }
    let exports = {};
    const require = depUri => singleRequire(depUri, uri);
    const specialDeps = {
      module: { uri },
      exports,
      require
    };
    registry[uri] = Promise.all(depsNames.map(
      depName => specialDeps[depName] || require(depName)
    )).then(deps => {
      factory(...deps);
      return exports;
    });
  };
}
define(['./workbox-43e44e5a'], (function (workbox) { 'use strict';

  self.skipWaiting();
  workbox.clientsClaim();
  /**
   * The precacheAndRoute() method efficiently caches and responds to
   * requests for URLs in the manifest.
   * See https://goo.gl/S9QRab
   */
  workbox.precacheAndRoute([{
    "url": "build/workbox-window.prod.es5-CzJxx9q2.js",
    "revision": null
  }, {
    "url": "build/workbox-window.prod.es5-Bd17z0YL.js",
    "revision": null
  }, {
    "url": "build/index-emyw3ViA.css",
    "revision": null
  }, {
    "url": "build/index-Dum-13eF.css",
    "revision": null
  }, {
    "url": "build/index-Dl_s2wkh.js",
    "revision": null
  }, {
    "url": "build/index-Cdl1I7dx.js",
    "revision": null
  }, {
    "url": "build/index-C9Bm-1vd.js",
    "revision": null
  }, {
    "url": "build/index-Bo-U08gp.js",
    "revision": null
  }, {
    "url": "build/index-4CRxGwv3.css",
    "revision": null
  }, {
    "url": "index.html",
    "revision": "31d3eda7be63d7aad2755dc6aa11e9ab"
  }, {
    "url": "icon.svg",
    "revision": "0ffa5258381da71bb527865d7a90e591"
  }, {
    "url": "pwa-maskable-512x512.png",
    "revision": "6a32bc742e32357ef18f032c2f05b2a1"
  }, {
    "url": "pwa-512x512.png",
    "revision": "d3a1212e01ce728d50ba87840deef5c7"
  }, {
    "url": "pwa-192x192.png",
    "revision": "7feca5df6db79394c8ec7a4aaab12e3d"
  }, {
    "url": "apple-touch-icon.png",
    "revision": "65b838f5be0f701624303c95db4250db"
  }, {
    "url": "manifest.webmanifest",
    "revision": "c280f48cbd8ff6cfecca9e2d06b5bec9"
  }], {});
  workbox.cleanupOutdatedCaches();
  workbox.registerRoute(new workbox.NavigationRoute(workbox.createHandlerBoundToURL("/index.html"), {
    denylist: [/^\/api\//]
  }));
  workbox.registerRoute(/^\/api\/.*/i, new workbox.NetworkOnly(), 'GET');
  workbox.registerRoute(/^https:\/\/(firestore|identitytoolkit|securetoken)\.googleapis\.com\/.*/i, new workbox.NetworkOnly(), 'GET');
  workbox.registerRoute(/\/models\/human\/.*/i, new workbox.CacheFirst({
    "cacheName": "bioguard-face-models-v2",
    plugins: [new workbox.ExpirationPlugin({
      maxEntries: 24,
      maxAgeSeconds: 2592000
    }), new workbox.CacheableResponsePlugin({
      statuses: [0, 200]
    })]
  }), 'GET');
  workbox.registerRoute(/^https:\/\/fonts\.(googleapis|gstatic)\.com\/.*/i, new workbox.CacheFirst({
    "cacheName": "google-fonts-cache",
    plugins: [new workbox.ExpirationPlugin({
      maxEntries: 12,
      maxAgeSeconds: 31536000
    }), new workbox.CacheableResponsePlugin({
      statuses: [0, 200]
    })]
  }), 'GET');

}));
