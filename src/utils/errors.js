// Erreur de base avec un code HTTP (400, 401, 404, etc.)
class AppError extends Error {
  constructor(message, statusCode) {
    super(message);
    this.statusCode = statusCode;
    this.name = this.constructor.name;
  }
}

// Erreur 400 — la requête est incorrecte ou incomplète
class BadRequestError extends AppError {
  constructor(message = 'Bad Request') {
    super(message, 400);
  }
}

// Erreur 401 — connexion requise ou identifiants incorrects
class UnauthorizedError extends AppError {
  constructor(message = 'Unauthorized') {
    super(message, 401);
  }
}

// Erreur 403 — accès refusé même si l'utilisateur est connecté
class ForbiddenError extends AppError {
  constructor(message = 'Forbidden') {
    super(message, 403);
  }
}

// Erreur 404 — élément introuvable
class NotFoundError extends AppError {
  constructor(message = 'Not Found') {
    super(message, 404);
  }
}

// Erreur 409 — conflit (ex. email déjà utilisé)
class ConflictError extends AppError {
  constructor(message = 'Conflict') {
    super(message, 409);
  }
}

// Erreur 429 — trop de requêtes en peu de temps
class TooManyRequestsError extends AppError {
  constructor(message = 'Too Many Requests') {
    super(message, 429);
  }
}

module.exports = {
  AppError,
  BadRequestError,
  UnauthorizedError,
  ForbiddenError,
  NotFoundError,
  ConflictError,
  TooManyRequestsError
};
