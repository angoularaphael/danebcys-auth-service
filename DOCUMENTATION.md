# Auth-service

## Rôle
Service d'authentification central: signup/login, JWT, refresh rotation, PoW, vérification email/téléphone, reset mot de passe, routes internes de validation.

## Mise à jour 2026-03 (entrée API)
- `Auth-service` est aussi l'entrée API publique unique (`/api/v1/*`).
- Il proxyfie vers les autres microservices (users, products, search, orders, messaging, assistance, subscriptions, favorites, notifications).
- CORS doit autoriser les origines frontend et les origines locales de test (`localhost:3001`, `127.0.0.1:3001`) en environnement non production.

## Port et santé
- Port par défaut: `3001`
- Healthcheck: `GET /health`

## Variables d'environnement (canoniques)
- `PORT`, `NODE_ENV`
- `PG_HOST`, `PG_PORT`, `PG_DATABASE`, `PG_USER`, `PG_PASSWORD`
- `JWT_ACCESS_SECRET`, `JWT_REFRESH_SECRET`, `JWT_ACCESS_EXPIRES_IN`, `JWT_REFRESH_EXPIRES_IN`
- `POW_SECRET`, `POW_DIFFICULTY`, `POW_EXPIRY_SECONDS`
- `PEPPER_PRIMARY_URL`, `PEPPER_PRIMARY_KEY`, `PEPPER_SECONDARY_URL`, `PEPPER_SECONDARY_KEY`
- `INTER_SERVICE_KEY`
- `EMAIL_USER`, `EMAIL_PASS`
- `RATE_LIMIT_WINDOW_MS`, `RATE_LIMIT_MAX_REQUESTS`

## Routes publiques (`/api/v1/auth`)
- `GET /pow-challenge`
- `POST /signup`
- `POST /login`
- `POST /forgot-password`
- `POST /reset-password`
- `POST /refresh`
- `POST /logout`
- `GET /me`
- `POST /verify-email`
- `POST /send-phone-code`
- `POST /verify-phone`

## Routes internes (`/internal`, protégées X-Service-Key)
- `POST /validate-token`
- `GET /users`
- `GET /users/:id` — consommé notamment par **Products-service** pour enrichir le catalogue public / boutique (`sellerName` sur les annonces, à partir du profil utilisateur).
- `PUT /users/:id`
- `PUT /users/:id/role`
- `PUT /users/:id/premium`
- `DELETE /users/:id`
- `PUT /users/:id/restore`
- `GET /roles`

## Dépendances
- PostgreSQL
- `pepper-primary` (3098)
- `pepper-service` (3099)

## Démarrage
- Local: `npm run dev`
- Docker: via `docker compose --env-file .env.docker up --build`
- Seed super admin à la demande: `npm run seed:admin`  
  (email: `giffareno05@gmail.com`, mot de passe: `#Fareno12`)

## Secrets & configuration
- **Fichier source** : `Auth-service/.env` (non versionné par Git).
- **Copie locale de référence** : `Secrets-Danebcys/Auth-service/.env`, synchronisée depuis la racine du monorepo avec `.\scripts\sync-secrets-danebcys.ps1` (PowerShell).
- Ne jamais committer les valeurs sensibles.

# Auth Service — Documentation technique

> Documentation condensée. Pour la documentation complète, voir **Auth-doc.MD**.  
> Microservice d'authentification pour **DANEBCYS**.  
> JWT maison, scrypt + double pepper, refresh token rotation, Proof of Work, rate limiting.  
> Zéro librairie d'authentification externe.

---

## Table des matières

1. [Vue d'ensemble](#1-vue-densemble)
2. [Architecture du projet](#2-architecture-du-projet)
3. [Hash & Pepper](#3-hash--pepper)
4. [JWT maison](#4-jwt-maison)
5. [Refresh Token Rotation](#5-refresh-token-rotation)
6. [Proof of Work](#6-proof-of-work)
7. [Vérification email & téléphone](#7-vérification-email--téléphone)
8. [Rate Limiter](#8-rate-limiter)
9. [Routes internes (inter-services)](#9-routes-internes-inter-services)
10. [Schéma PostgreSQL](#10-schéma-postgresql)
11. [Endpoints API](#11-endpoints-api)
12. [Variables d'environnement](#12-variables-denvironnement)
13. [Installation et lancement](#13-installation-et-lancement)

---

## 1. Vue d'ensemble

| Fonctionnalité | Technologie |
|---|---|
| Hash mot de passe | `crypto.scrypt` (N=16384, r=8, p=1) |
| Pepper | Double pepper via 2 microservices + HMAC-SHA256 |
| JWT | Maison (HMAC-SHA256, Base64URL) |
| Refresh tokens | Rotation avec détection de réutilisation |
| Proof of Work | SHA-256, difficulté dynamique |
| Email | Nodemailer (Gmail) |
| SMS | Stub dev (Twilio en production) |
| Rate limiting | In-memory, user ID ou IP |

**Port** : 3001  
**Base de données** : PostgreSQL (`danebcys`)

---

## 2. Architecture du projet

```
Auth-service/
├── src/
│   ├── config/
│   │   ├── database.js          # Pool PostgreSQL + initDB()
│   │   └── env.js               # Variables d'environnement
│   ├── controllers/
│   │   └── auth.controller.js   # Handlers HTTP
│   ├── middlewares/
│   │   ├── auth.js              # authenticate middleware
│   │   ├── pow.js               # Proof of Work (challenge + verify)
│   │   ├── rateLimiter.js       # Rate limiter maison
│   │   └── serviceAuth.js       # X-Service-Key (inter-services)
│   ├── routes/
│   │   ├── auth.routes.js       # Routes publiques /api/v1/auth
│   │   └── internal.routes.js   # Routes internes /internal
│   ├── services/
│   │   ├── auth.service.js      # Logique métier auth
│   │   ├── token.service.js     # JWT + refresh tokens
│   │   ├── pepper.service.js    # Double pepper
│   │   └── mail.service.js      # Nodemailer + SMS stub
│   ├── utils/
│   │   ├── hash.js              # scrypt, safeCompare
│   │   ├── jwt.js               # sign/verify JWT maison
│   │   └── errors.js            # Classes d'erreur
│   └── app.js
├── public/
│   ├── index.html               # Interface de test
│   └── test.js
├── init.sql                     # Schéma PostgreSQL
├── server.js
├── .env
├── .gitignore
└── package.json
```

---

## 3. Hash & Pepper

**Algorithme** : `crypto.scrypt(password + pepper, salt, 64, {N:16384, r:8, p:1})`

- **Salt** : 32 bytes random, unique par utilisateur
- **Pepper** : combinaison HMAC-SHA256 de 2 peppers externes
  - `pepper-primary` (port 3098) + `pepper-service` (port 3099)
  - `combinedPepper = HMAC-SHA256(primary, secondary)`
- **Vérification** : `crypto.timingSafeEqual` pour empêcher les timing attacks

---

## 4. JWT maison

- Header : `{"alg":"HS256","typ":"JWT"}`
- Payload : `{ sub, email, role, iat, exp }`
- Signature : `HMAC-SHA256(header.payload, JWT_ACCESS_SECRET)`
- Encodage : Base64URL (sans padding)
- Vérification : `crypto.timingSafeEqual` sur la signature
- Expiration : 15 minutes (access), 7 jours (refresh)

---

## 5. Refresh Token Rotation

1. Client envoie POST /refresh avec l'ancien refreshToken
2. Le service vérifie le hash du token en base
3. Si valide → crée un nouveau accessToken + refreshToken, supprime l'ancien
4. Si réutilisation détectée → révoque TOUTES les sessions de l'utilisateur (protection vol de token)

---

## 6. Proof of Work

- Challenge : `{ challenge, difficulty, expiresAt }` signé HMAC-SHA256
- Client : trouve `nonce` tel que `SHA256(challenge + nonce)` commence par N zéros
- Difficulté : configurable via `POW_DIFFICULTY` (défaut 4)
- Expiration : 5 minutes
- Protège : signup, login, forgot-password, reset-password

---

## 7. Vérification email & téléphone

- **Email** : code 6 chiffres envoyé via Nodemailer/Gmail, expire 15 min
- **Configuration Gmail** : `EMAIL_USER` = adresse Gmail, `EMAIL_PASS` = **mot de passe d'application** (pas le mot de passe du compte). Créer un mot de passe d'application : https://myaccount.google.com/apppasswords
- **Téléphone** : code 6 chiffres, stub en dev (console.log), Twilio en production
- Routes : `POST /verify-email`, `POST /send-phone-code`, `POST /verify-phone`

---

## 8. Rate Limiter

| Limiter | Clé | Fenêtre | Max |
|---|---|---|---|
| tokenLimiter | user:{id} | 15 min | 100 |
| preAuthTokenLimiter | JWT payload decode | 15 min | 100 |
| challengeLimiter | ip:{ip} | 1 min | 30 |

---

## 9. Routes internes (inter-services)

Protégées par `X-Service-Key` + SHA-256 + `timingSafeEqual`.

| Route | Description |
|---|---|
| POST /internal/validate-token | Valider un access token |
| GET /internal/users | Lister users (pagination, filtres) |
| GET /internal/users/:id | Détail user |
| PUT /internal/users/:id | Modifier profil user |
| PUT /internal/users/:id/role | Modifier rôle |
| PUT /internal/users/:id/premium | Modifier premium |
| DELETE /internal/users/:id | Soft delete user |
| PUT /internal/users/:id/restore | Restaurer user |
| GET /internal/roles | Liste des rôles |

---

## 10. Schéma PostgreSQL

| Table | Description |
|---|---|
| roles | user, vendeur, assistance, admin |
| users | Comptes utilisateurs (UUID PK, soft delete) |
| sessions | Refresh tokens hashés, fingerprint, IP |
| email_verifications | Codes de vérification email |
| password_resets | Codes de réinitialisation mot de passe |
| phone_verifications | Codes de vérification téléphone |

---

## 11. Endpoints API

### Routes publiques — `/api/v1/auth`

| Méthode | Route | Protection | Description |
|---|---|---|---|
| GET | /pow-challenge | IP rate limit | Obtenir un challenge PoW |
| POST | /signup | PoW | Inscription |
| POST | /login | PoW | Connexion |
| POST | /forgot-password | PoW | Demande reset mot de passe |
| POST | /reset-password | PoW | Reset mot de passe |
| POST | /refresh | Token rate limit | Rafraîchir tokens |
| POST | /logout | Auth | Déconnexion |
| GET | /me | Auth | Profil connecté |
| POST | /verify-email | Auth | Vérifier email |
| POST | /send-phone-code | Auth | Envoyer code SMS |
| POST | /verify-phone | Auth | Vérifier téléphone |

---

## 12. Variables d'environnement

| Variable | Description |
|---|---|
| PORT | Port (défaut 3001) |
| PG_HOST, PG_PORT, PG_DATABASE, PG_USER, PG_PASSWORD | PostgreSQL |
| JWT_ACCESS_SECRET, JWT_REFRESH_SECRET | Secrets JWT |
| JWT_ACCESS_EXPIRES_IN, JWT_REFRESH_EXPIRES_IN | Expiration tokens |
| PEPPER_PRIMARY_URL, PEPPER_PRIMARY_KEY | Pepper service 1 |
| PEPPER_SECONDARY_URL, PEPPER_SECONDARY_KEY | Pepper service 2 |
| EMAIL_USER, EMAIL_PASS | Nodemailer Gmail |
| POW_DIFFICULTY, POW_SECRET, POW_EXPIRY_SECONDS | Proof of Work |
| INTER_SERVICE_KEY | Clé inter-services |

---

## 13. Installation et lancement

```bash
cd Auth-service
npm install

# Démarrage (les pepper services doivent être lancés avant)
npm start
```

### Ordre de démarrage

1. pepper-primary (3098)
2. pepper-service (3099)
3. **Auth Service** (3001)
4. Users Service (3002)
5. Search Service (3003)
6. Products Service (3004)
7. Orders Service (3005)
8. Messaging Service (3006)
9. Assistance Service (3007)
