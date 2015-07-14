'use strict';

/**
 * Module dependencies.
 */
var util = require('util'),
    OAuth2Strategy = require('passport-oauth').OAuth2Strategy,
    InternalOAuthError = require('passport-oauth').InternalOAuthError;

/**
 * `Strategy` constructor.
 *
 * The Yahoo authentication strategy authenticates requests by delegating to
 * Yahoo using the OAuth protocol.
 *
 * Applications must supply a `verify` callback which accepts a `token`,
 * `tokenSecret` and service-specific `profile`, and then calls the `done`
 * callback supplying a `user`, which should be set to `false` if the
 * credentials are not valid.  If an exception occured, `err` should be set.
 *
 * Options:
 *   - `consumerKey`     identifies client to Yahoo
 *   - `consumerSecret`  secret used to establish ownership of the consumer key
 *   - `callbackURL`     URL to which Yahoo will redirect the user after obtaining authorization
 *
 * Examples:
 *
 *     passport.use(new YahooStrategy({
 *         consumerKey: '123-456-789',
 *         consumerSecret: 'shhh-its-a-secret'
 *         callbackURL: 'https://www.example.net/auth/yahoo/callback'
 *       },
 *       function(token, tokenSecret, profile, done) {
 *         User.findOrCreate(..., function (err, user) {
 *           done(err, user);
 *         });
 *       }
 *     ));
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
    //https://api.login.yahoo.com/oauth2/request_auth
    options = options || {};
    options.authorizationURL = options.authorizationURL || 'https://api.login.yahoo.com/oauth2/request_auth';
    options.tokenURL = options.tokenURL || 'https://api.login.yahoo.com/oauth2/get_token';
    options.customHeaders = {
        'Authorization': 'Basic ' + new Buffer(options.clientID + ':' + options.clientSecret).toString('base64')
    };

    OAuth2Strategy.call(this, options, verify);

    this.name = 'yahoo';
    this._userProfileURL = options.userProfileURL || 'https://social.yahooapis.com/v1/user/:xoauthYahooGuid/profile?format=json';
    this._userGUIDUrl = options.userGUIDUrl || 'https://social.yahooapis.com/v1/me/guid?format=json';

    this._oauth2.useAuthorizationHeaderforGET(true);
}

/**
 * Inherit from `OAuthStrategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Yahoo.
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `id`
 *   - `displayName`
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function (accessToken, done) {
    var self = this;
    this._oauth2.get(this._userGUIDUrl, accessToken, function (err, body) {
        var json;
        if (err) {
            if (err.data) {
                try {
                    json = JSON.parse(err.data);
                } catch (e) {
                    json = null;
                }

                if (json && json.error) {
                    return done(new InternalOAuthError('Failed to get user GUID: ' + err.detail, err.statusCode));
                }

                return done(new InternalOAuthError('Failed to get user GUID'));
            }
        }

        var xoauthYahooGuid;
        try {
            xoauthYahooGuid = JSON.parse(body).guid.value;
        } catch (e) {
            return done(new Error('Failed to parse GUID response'));
        }

        var url = self._userProfileURL.replace(':xoauthYahooGuid', xoauthYahooGuid);
        self._oauth2.get(url, accessToken, function(profileError, profileBody) {
            if (profileError) {
                if (profileError.data) {
                    try {
                        json = JSON.parse(profileError.data);
                    } catch (e) {
                        json = null;
                    }
                }

                if (json && json.error) {
                    return done(new InternalOAuthError(json.error.description, profileError.statusCode));
                }

                return done(new InternalOAuthError('Failed to fetch user profile', err));
            }

            try {
                json = JSON.parse(profileBody);
            } catch (ex) {
                return done(new Error('Failed to parse user profile'));
            }

            json.id = xoauthYahooGuid;

            var profile = {
                provider: 'yahoo',
                id: json.id,
                displayName: [json.givenName || '', json.familyName || ''].join(' '),
                name: {
                    familyName: json.familyName || '',
                    givenName: json.givenName || ''
                },
                emails: json.emails && json.emails.map(function (email) {
                    var obj = { value: email.handle };
                    obj.type = obj.primary ? 'account' : obj.type || 'unknown';
                    return obj;
                }) || [],
                photos: [{
                    value: (json.image && json.image.imageUrl) || ''
                }],
                _raw: profileBody,
                _json: json
            };

            done(null, profile);
        });
    });
};

/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
