# Auth Service — Documentation technique

> Aucune librairie d'authentification, de rate limiting, de session ou de PoW n'est utilisée.  
> Tout est implémenté à la main avec le module natif `crypto` de Node.js.  
> Plateforme : **DANEBCYS**.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture du projet](#2-architecture-du-projet)
3. [JWT maison (HMAC-SHA256)](#3-jwt-maison-hmac-sha256)
4. [Hachage de mot de passe (scrypt)](#4-hachage-de-mot-de-passe-scrypt)
5. [Double Pepper (microservices externes)](#5-double-pepper-microservices-externes)
6. [Rotation de token (refresh token)](#6-rotation-de-token-refresh-token)
7. [Rate Limiter basé sur le token](#7-rate-limiter-basé-sur-le-token)
8. [Proof of Work (PoW)](#8-proof-of-work-pow)
9. [Authentification inter-microservices](#9-authentification-inter-microservices)
10. [Schéma de base de données](#10-schéma-de-base-de-données)
11. [Endpoints API](#11-endpoints-api)
12. [Installation et lancement](#12-installation-et-lancement)
13. [Variables d'environnement](#13-variables-denvironnement)
14. [Exemples d'utilisation (cURL)](#14-exemples-dutilisation-curl)
15. [Mot de passe oublié (forgot / reset)](#15-mot-de-passe-oublié-forgot--reset)

---

## 1. Vue d'ensemble

Le **Auth Service** est un microservice d'authentification **zéro librairie auth** pour la plateforme **DANEBCYS** :

| Ce qu'on fait                     | Ce qu'on n'utilise PAS          |
|-----------------------------------|---------------------------------|
| JWT signé à la main (HMAC-SHA256) | ~~jsonwebtoken~~                |
| Rate limiter maison (par token)   | ~~express-rate-limit~~          |
| PoW maison (challenge HMAC)       | ~~toute lib PoW~~               |
| Gestion de session maison         | ~~toute lib de session~~        |

**Stack :**
- Express.js (JavaScript pur, pas de TypeScript)
- PostgreSQL avec driver natif `pg` (base `danebcys`)
- `crypto.scrypt` pour le hachage (pas de bcrypt)
- Nodemailer pour les emails (expéditeur : DANEBCYS)

---

## 2. Architecture du projet

```
Auth-service/
├── src/
│   ├── config/
│   │   ├── database.js           # Pool PostgreSQL natif (pg) + initDB()
│   │   └── env.js                # Variables d'environnement
│   ├── controllers/
│   │   └── auth.controller.js    # Handlers HTTP
│   ├── middlewares/
│   │   ├── auth.js               # Vérification JWT maison
│   │   ├── rateLimiter.js        # Rate limiter maison (par token)
│   │   ├── pow.js                # Proof of Work maison (HMAC)
│   │   └── serviceAuth.js        # Auth inter-microservices
│   ├── routes/
│   │   ├── auth.routes.js        # Routes publiques /api/v1/auth
│   │   └── internal.routes.js    # Routes internes /internal
│   ├── services/
│   │   ├── auth.service.js       # Logique métier
│   │   ├── mail.service.js       # Nodemailer (expéditeur : DANEBCYS)
│   │   ├── pepper.service.js     # Double pepper (local + remote)
│   │   └── token.service.js      # JWT maison + rotation refresh tokens
│   ├── utils/
│   │   ├── jwt.js                # Implémentation JWT HMAC-SHA256
│   │   ├── hash.js               # scrypt + timing-safe compare
│   │   └── errors.js             # Classes d'erreur
│   └── app.js                    # Config Express
├── public/                       # Frontend de test
│   ├── index.html                # Interface de test (navigateur)
│   └── test.js                   # Logique client (PoW solver, appels API)
├── init.sql                      # Schéma PostgreSQL
├── .env.example
├── package.json
├── server.js                     # Point d'entrée
└── Auth-doc.MD

pepper-primary/                   # Pepper primaire (HORS du dossier Auth-service)
├── server.js                     # Serveur HTTP natif
├── package.json
└── .env

pepper-service/                   # Pepper secondaire (HORS du dossier Auth-service)
├── server.js                     # Serveur HTTP natif
├── package.json
└── .env
```

---

## 3. JWT maison (HMAC-SHA256)

**Fichier :** `src/utils/jwt.js`

On a implémenté le standard JWT (RFC 7519) uniquement avec `crypto` natif :

### Structure d'un token

```
HEADER.PAYLOAD.SIGNATURE
```

Chaque partie est encodée en **Base64URL** (pas Base64 classique) :

```
Header:    { "alg": "HS256", "typ": "JWT" }
Payload:   { "sub": "user-uuid", "email": "...", "role": "user", "iat": ..., "exp": ... }
Signature: HMAC-SHA256(header_b64 + "." + payload_b64, secret)
```

### Création (`sign`)

1. Encoder le header en Base64URL
2. Ajouter iat (issued at) et exp (expiration) au payload
3. Encoder le payload en Base64URL
4. Calculer HMAC-SHA256 sur "header.payload" avec le secret
5. Encoder la signature en Base64URL
6. Retourner "header.payload.signature"

### Vérification (`verify`)

1. Séparer le token en 3 parties
2. Recalculer HMAC-SHA256 sur "header.payload"
3. Comparer avec la signature reçue via `crypto.timingSafeEqual()` (timing-safe)
4. Décoder le payload, vérifier que exp > maintenant
5. Retourner le payload

### Pourquoi `timingSafeEqual` ?

Une comparaison classique (`===`) s'arrête au premier octet différent. Un attaquant pourrait mesurer le temps de réponse pour deviner la signature octet par octet. `timingSafeEqual` compare TOUS les octets en temps constant.

---

## 4. Hachage de mot de passe (scrypt)

**Fichier :** `src/utils/hash.js`

### Pourquoi pas bcrypt ?

- bcrypt est une dépendance **native C++** (problèmes de compilation)
- bcrypt ne résiste pas aussi bien aux attaques **GPU/ASIC**
- `crypto.scrypt` est **intégré à Node.js**, zéro dépendance

### Pourquoi scrypt ?

scrypt est une fonction de dérivation de clé **memory-hard** : elle nécessite beaucoup de **mémoire** en plus du CPU. Cela rend les attaques par GPU/ASIC très coûteuses.

### Paramètres

| Paramètre | Valeur | Rôle                        |
|-----------|--------|-----------------------------|
| N         | 16384  | Coût CPU/mémoire            |
| r         | 8      | Taille de bloc              |
| p         | 1      | Parallélisme                |
| keyLength | 64     | Taille de la clé dérivée    |

### Flux de hachage

1. Générer un salt aléatoire de 32 octets
2. Concaténer le mot de passe + le double pepper
3. Appliquer scrypt(input, salt, 64) avec les paramètres ci-dessus
4. Stocker en DB : salt et password_hash séparément

### Flux de vérification

1. Extraire le salt et le hash depuis la DB
2. Recalculer scrypt(password + pepper, salt, 64)
3. Comparer avec `crypto.timingSafeEqual()` (pas de ===)

---

## 5. Double Pepper (microservices externes)

**Fichiers :** `src/services/pepper.service.js` + `pepper-primary/` + `pepper-service/`

### Concept

Le **pepper** est un secret cryptographique ajouté au mot de passe avant le hachage. Contrairement au salt (stocké en DB), le pepper est **hors de la base de données**.

On utilise un **double pepper entièrement externe** — le Auth Service ne stocke aucun pepper :

| Pepper      | Source                            | Stockage                          |
|-------------|-----------------------------------|-----------------------------------|
| Primaire    | pepper-primary (microservice)     | .env du pepper-primary            |
| Secondaire  | pepper-service (microservice)     | .env du pepper-service            |

### Combinaison

```
combined_pepper = HMAC-SHA256(PRIMARY_PEPPER, SECONDARY_PEPPER)
```

### Les deux Pepper Services

| Service         | Port par défaut | Clé Auth Service              |
|-----------------|-----------------|-------------------------------|
| pepper-primary  | 3098            | `PEPPER_PRIMARY_KEY`          |
| pepper-service  | 3099            | `PEPPER_SECONDARY_KEY`        |

### Avantage sécurité

Le Auth Service ne contient **aucun pepper**. Un attaquant doit compromettre les trois services pour reconstituer le pepper complet.

### Mode développement

Si aucun `PEPPER_PRIMARY_URL` / `PEPPER_SECONDARY_URL` n'est configuré, le Auth Service utilise un fallback déterministe (uniquement en `NODE_ENV=development`). En production, les deux services sont obligatoires.

---

## 6. Rotation de token (refresh token)

**Fichier :** `src/services/token.service.js`

### Concept

À chaque utilisation d'un refresh token, l'ancien est **marqué comme invalidé** et un nouveau est émis. Si un token invalidé est réutilisé, c'est une **attaque par vol de token** → toutes les sessions du user sont détruites.

### Flux normal

1. User se connecte → reçoit Access Token (15 min) + Refresh Token T1
2. Access Token expire → User envoie T1 à POST /refresh
3. Serveur : T1 existe et n'est PAS invalidated → Marquer T1 comme invalidated → Générer et retourner T2 + nouvel Access Token
4. Plus tard, User envoie T2 → même processus → T3, etc.

### Détection de vol

1. Attaquant vole T1
2. Le vrai User utilise T1 → reçoit T2 (T1 est marqué invalidated)
3. L'Attaquant utilise T1 (déjà invalidated !) → DÉTECTION → DELETE toutes les sessions du user (révoque tout)

### Stockage

Les refresh tokens sont stockés **hashés** en SHA-256 dans la table `sessions`. Même si la DB est compromise, les tokens bruts ne sont pas exposés.

---

## 7. Rate Limiter basé sur le token

**Fichier :** `src/middlewares/rateLimiter.js`

### Pourquoi basé sur le token et pas l'IP ?

- Derrière un proxy/VPN, des milliers d'utilisateurs partagent la même IP
- Un attaquant peut changer d'IP facilement (proxy rotating)
- Le token identifie **l'utilisateur réel**, pas l'infrastructure réseau

### Trois niveaux

| Limiter             | Clé              | Cible                        | Config              |
|---------------------|------------------|------------------------------|---------------------|
| tokenLimiter        | `req.user.id`    | Routes authentifiées         | 100 req / 15 min    |
| preAuthTokenLimiter | JWT decode (sub) | POST /refresh                | 100 req / 15 min    |
| challengeLimiter    | IP (fallback)    | GET /pow-challenge           | 30 req / 1 min      |

Les routes signup/login sont protégées par le **PoW** (pas de rate limiter, le PoW est la protection).

---

## 8. Proof of Work (PoW)

**Fichier :** `src/middlewares/pow.js`

### Concept

Le PoW force le client à effectuer un calcul coûteux avant chaque signup/login. Cela empêche les attaques automatisées (bots, brute force).

### Flux

1. Client → GET /api/v1/auth/pow-challenge → reçoit `{ challenge, difficulty, signature, expiresAt }`
2. Client résout le puzzle : trouver un nonce tel que SHA-256(challenge + nonce) commence par `difficulty` zéros hexadécimaux
3. Client → POST /api/v1/auth/signup (ou /login) avec headers : `x-pow-challenge`, `x-pow-nonce`, `x-pow-signature`

### Vérification serveur

1. Vérifier la signature HMAC du challenge (anti-forge) via `crypto.timingSafeEqual`
2. Vérifier que le challenge n'est pas expiré (timestamp intégré)
3. Vérifier SHA-256(challenge + nonce) commence par N zéros

### Pourquoi stateless ?

Le challenge est signé par HMAC avec un secret serveur. Pas besoin de le stocker en DB. Le timestamp intégré dans le challenge permet de vérifier l'expiration.

### Difficulté

Avec `POW_DIFFICULTY=4`, le client doit trouver un hash commençant par `0000`. En moyenne, cela prend ~65 000 tentatives. C'est instantané pour un humain (navigateur moderne) mais coûteux pour un bot.

---

## 9. Authentification inter-microservices

**Fichiers :** `src/middlewares/serviceAuth.js` + `src/routes/internal.routes.js`

### Concept

Les autres microservices (Users Service, Products Service, etc.) doivent pouvoir valider les tokens des utilisateurs sans connaître le secret JWT. Ils appellent le Auth Service via une route interne.

### Middleware `serviceAuth`

1. Lire le header X-Service-Key
2. Comparer avec INTER_SERVICE_KEY via SHA-256 + timingSafeEqual
3. Si valide → req.isService = true → next()

### Route interne

```
POST /internal/validate-token
Header: X-Service-Key: <clé partagée>
Body: { "accessToken": "eyJhbG..." }

Réponse OK : { "valid": true, "user": { "id": "...", "email": "...", "role": "..." } }
Réponse KO : { "valid": false, "error": "Token expiré" }
```

---

## 10. Schéma de base de données

### Table `roles`

| Colonne | Type | Description |
|---------|------|-------------|
| id | SERIAL (PK) | Auto-increment |
| name | VARCHAR(50) | UNIQUE NOT NULL (user, vendeur, assistance, admin) |
| description | TEXT | Description du rôle |
| created_at, updated_at | TIMESTAMPTZ | Horodatage |

### Table `users`

| Colonne         | Type         | Description                        |
|-----------------|--------------|------------------------------------|
| id              | UUID (PK)    | gen_random_uuid()                  |
| username        | VARCHAR(100) | NOT NULL                          |
| email           | VARCHAR(255) | UNIQUE NOT NULL                    |
| phone           | VARCHAR(20)  | Optionnel                          |
| password_hash   | VARCHAR(512) | scrypt hash                        |
| salt            | VARCHAR(128) | Salt séparé                        |
| role_id         | INTEGER (FK) | → roles.id, défaut: 1 (user)      |
| premium_level   | premium_level_enum | 'none', 'premium', 'premium_avancee', 'etudiant' |
| student_proof   | VARCHAR(512) | Justificatif étudiant              |
| country         | VARCHAR(100) | Pays                               |
| first_name      | VARCHAR(100) | Prénom                             |
| last_name       | VARCHAR(100) | Nom                                |
| email_verified  | BOOLEAN      | Défaut: false                      |
| phone_verified  | BOOLEAN      | Défaut: false                      |
| deleted         | BOOLEAN      | Soft delete                        |
| created_at      | TIMESTAMPTZ  | Date de création                   |
| updated_at      | TIMESTAMPTZ  | Dernière modification              |
| last_login_at   | TIMESTAMPTZ  | Dernière connexion                 |

### Table `sessions`

| Colonne    | Type        | Description                              |
|------------|-------------|------------------------------------------|
| id         | UUID (PK)   | gen_random_uuid()                        |
| user_id    | UUID (FK)   | → users.id ON DELETE CASCADE             |
| token_hash | VARCHAR(512) | SHA-256 du refresh token                 |
| fingerprint_hash | VARCHAR(256) | SHA-256 du User-Agent                 |
| ip_address | VARCHAR(45) | IP du client                             |
| invalidated | BOOLEAN    | Pour la détection de réutilisation       |
| expires_at | TIMESTAMPTZ | Expiration (7 jours)                     |
| created_at | TIMESTAMPTZ | Date de création                         |
| last_used_at | TIMESTAMPTZ | Dernière utilisation                    |

### Table `email_verifications`

| Colonne    | Type        | Description                              |
|------------|-------------|------------------------------------------|
| id         | UUID (PK)   | gen_random_uuid()                        |
| user_id    | UUID (FK)   | → users.id                               |
| code       | VARCHAR(6)  | Code à 6 chiffres                        |
| expires_at | TIMESTAMPTZ | 15 min après création                    |
| used       | BOOLEAN     | Défaut: false                            |
| created_at | TIMESTAMPTZ | Date de création                         |

### Table `password_resets`

| Colonne    | Type        | Description                              |
|------------|-------------|------------------------------------------|
| id         | UUID (PK)   | gen_random_uuid()                        |
| user_id    | UUID (FK)   | → users.id ON DELETE CASCADE             |
| code       | VARCHAR(6)  | Code à 6 chiffres                        |
| expires_at | TIMESTAMPTZ | 15 min après création                    |
| used       | BOOLEAN     | Défaut: false                            |
| created_at | TIMESTAMPTZ | Date de création                         |

---

## 11. Endpoints API

### Routes publiques — `/api/v1/auth`

| Méthode | Route            | Protection          | Description                     |
|---------|------------------|---------------------|---------------------------------|
| GET     | /pow-challenge   | Rate limit (IP)     | Obtenir un challenge PoW        |
| POST    | /signup          | PoW                 | Inscription                     |
| POST    | /login           | PoW                 | Connexion                       |
| POST    | /forgot-password | PoW                 | Demande de réinitialisation     |
| POST    | /reset-password  | PoW                 | Réinitialisation du mot de passe|
| POST    | /refresh         | Rate limit (token)   | Rotation des tokens             |
| POST    | /logout          | JWT + Rate (token)  | Déconnexion                     |
| GET     | /me              | JWT + Rate (token)  | Profil connecté                 |
| POST    | /verify-email    | JWT + Rate (token)  | Vérification email              |
| POST    | /send-phone-code | JWT + Rate (token)  | Envoyer code SMS                |
| POST    | /verify-phone    | JWT + Rate (token)  | Vérifier téléphone              |

### Routes internes — `/internal`

| Méthode | Route            | Protection          | Description                     |
|---------|------------------|---------------------|---------------------------------|
| POST    | /validate-token  | X-Service-Key       | Validation de token pour les autres microservices |

---

## 12. Installation et lancement

### Prérequis

- Node.js >= 18
- PostgreSQL >= 14

### Auth Service

```bash
cd Auth-service
npm install

cp .env.example .env
# Modifier .env avec vos valeurs

psql -U postgres -c "CREATE DATABASE danebcys;"
npm run db:init

# Développement (auto-reload)
npm run dev

# Production
npm start
```

### Pepper Services (microservices externes)

```bash
# Pepper primaire
cd ../pepper-primary
npm install
cp .env.example .env
npm start
# → [Pepper Primary] Port 3098

# Pepper secondaire
cd ../pepper-service
npm install
cp .env.example .env
npm start
# → [Pepper Service] Port 3099
```

### Ordre de démarrage

1. **pepper-primary** d'abord (port 3098)
2. **pepper-service** ensuite (port 3099)
3. **Auth Service** en dernier (port 3001) — il récupère les deux peppers au démarrage

---

## 13. Variables d'environnement

### Auth Service (.env)

| Variable                | Description                           | Défaut          |
|-------------------------|---------------------------------------|-----------------|
| PORT                    | Port du serveur                       | 3001            |
| NODE_ENV                | Environnement                         | development     |
| PG_HOST                 | Hôte PostgreSQL                       | localhost       |
| PG_PORT                 | Port PostgreSQL                       | 5432            |
| PG_DATABASE             | Nom de la base                        | danebcys        |
| PG_USER                 | Utilisateur PostgreSQL                | postgres        |
| PG_PASSWORD             | Mot de passe PostgreSQL               | postgres        |
| JWT_ACCESS_SECRET       | Secret HMAC pour les access tokens    | *requis*        |
| JWT_REFRESH_SECRET      | Secret HMAC pour les refresh tokens   | *requis*        |
| JWT_ACCESS_EXPIRES_IN   | Durée access token                    | 15m             |
| JWT_REFRESH_EXPIRES_IN  | Durée refresh token                   | 7d              |
| PEPPER_PRIMARY_URL      | URL du pepper-primary                 | *requis en prod*|
| PEPPER_PRIMARY_KEY      | Clé partagée avec pepper-primary      | *requis en prod*|
| PEPPER_SECONDARY_URL    | URL du pepper-service                 | *requis en prod*|
| PEPPER_SECONDARY_KEY    | Clé partagée avec pepper-service      | *requis en prod*|
| EMAIL_USER              | Adresse Gmail (expéditeur DANEBCYS)   | *requis*        |
| EMAIL_PASS              | App password Gmail                    | *requis*        |
| POW_DIFFICULTY          | Zéros requis pour le PoW              | 4               |
| POW_SECRET              | Secret HMAC pour les challenges PoW   | *requis*        |
| POW_EXPIRY_SECONDS      | Durée de validité d'un challenge      | 300             |
| INTER_SERVICE_KEY       | Clé pour l'auth inter-microservices   | *requis*        |
| RATE_LIMIT_WINDOW_MS    | Fenêtre du rate limit (ms)            | 900000          |
| RATE_LIMIT_MAX_REQUESTS | Max requêtes par fenêtre              | 100             |

---

## 14. Exemples d'utilisation (cURL)

### Health check

```bash
curl http://localhost:3001/health
```

### Obtenir un challenge PoW

```bash
curl http://localhost:3001/api/v1/auth/pow-challenge
```

### Inscription

```bash
curl -X POST http://localhost:3001/api/v1/auth/signup \
  -H "Content-Type: application/json" \
  -H "x-pow-challenge: CHALLENGE" \
  -H "x-pow-nonce: NONCE" \
  -H "x-pow-signature: SIGNATURE" \
  -d '{
    "username": "jeandupont",
    "email": "jean@example.com",
    "password": "motDePasse123",
    "firstName": "Jean",
    "lastName": "Dupont"
  }'
```

### Connexion

```bash
curl -X POST http://localhost:3001/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -H "x-pow-challenge: CHALLENGE" \
  -H "x-pow-nonce: NONCE" \
  -H "x-pow-signature: SIGNATURE" \
  -d '{ "email": "jean@example.com", "password": "motDePasse123" }'
```

### Profil

```bash
curl http://localhost:3001/api/v1/auth/me \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

### Rafraîchir les tokens (rotation)

```bash
curl -X POST http://localhost:3001/api/v1/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{ "refreshToken": "REFRESH_TOKEN" }'
```

### Interface de test

Ouvrir `http://localhost:3001` dans le navigateur. Le frontend résout automatiquement le PoW côté client via `crypto.subtle.digest('SHA-256', ...)` et permet de tester tous les endpoints graphiquement.

---

## 15. Mot de passe oublié (forgot / reset)

**Fichiers :** `src/services/auth.service.js` + `src/services/mail.service.js`

### Flux

1. User appelle POST /forgot-password avec { email }
   → Le serveur NE RÉVÈLE PAS si l'email existe (toujours même réponse)
   → Si l'email existe : génère un code 6 chiffres, stocke dans password_resets, envoie par email
   → Le code expire après 15 minutes

2. User reçoit l'email avec le code

3. User appelle POST /reset-password avec { email, code, newPassword }
   → Le serveur vérifie le code (non utilisé, non expiré)
   → Hash le nouveau mot de passe avec scrypt + double pepper
   → Met à jour le mot de passe en DB
   → Révoque TOUS les refresh tokens du user (déconnexion forcée de toutes les sessions)

### Sécurité

- **Anti-énumération** : POST /forgot-password retourne toujours le même message, qu'il y ait un compte ou non
- **PoW obligatoire** : empêche le spam d'emails de réinitialisation
- **Code à usage unique** : marqué `used = TRUE` après utilisation
- **Révocation totale** : après un reset, toutes les sessions actives sont détruites

---

## Récapitulatif sécurité

| Mesure                        | Implémentation                                              |
|-------------------------------|-------------------------------------------------------------|
| JWT                           | HMAC-SHA256 maison (`crypto`), timingSafeEqual              |
| Hachage mot de passe          | scrypt (memory-hard) + salt unique + double pepper          |
| Double pepper                 | Deux microservices externes, combinés via HMAC              |
| Rotation refresh token        | Invalidation + détection de réutilisation (vol de token)    |
| Rate limiting                 | Maison, basé sur le token (user ID), pas l'IP               |
| Proof of Work                 | Challenge HMAC stateless, SHA-256 avec difficulté ajustable |
| Auth inter-services           | X-Service-Key + SHA-256 timingSafeEqual                     |
| Anti-timing attack            | `crypto.timingSafeEqual` partout (JWT, passwords, clés)     |
| Injection SQL                 | Requêtes paramétrées (`$1, $2, ...`) exclusivement          |
| Headers sécurité              | `helmet` (CSP, X-Frame-Options, etc.)                       |
| Soft Delete                   | Champ `deleted` au lieu de suppression physique              |
| Refresh token hashé           | SHA-256 en DB, jamais en clair                               |
| Reset password                | Code 6 chiffres, 15 min, usage unique, révocation totale    |
| Anti-énumération              | forgot-password ne révèle pas si l'email existe              |

**Librairies auth utilisées : aucune.**
