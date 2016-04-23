(function() {
  'use strict';

  var cookieParser = require('cookie-parser');

  module.exports = {
    handshakeMiddleware : function(options) {
      return function(req, next) {
        if (!options.key) {
          return next('Handshake middleware missing key option');
        }

        if (!options.secret) {
          return next('Handshake middleware missing secret option');
        }

        if (!options.store) {
          return next('Handshake middleware missing store option');
        }

        cookieParser(options.secret)(req, {}, function(err) {
          if (err) {
            return next(err);
          }

          var sessionId = (req.signedCookies || req.cookies)[options.key];

          if (!sessionId) {
            return next("Could not resolve sessionId");
          }

          options.store.get(sessionId, function(sessionErr, session) {
            req.session = session;
            return next(sessionErr);
          });
        });
      };
    }
  };

}).call(this);