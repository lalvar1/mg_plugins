'use strict';

var debug = require('debug')('plugin:custom-extauth');
var request = require('request');
var rs = require('jsrsasign');
var JWS = rs.jws.JWS;

const authHeaderRegex = /Bearer (.+)/;
const acceptAlg = ['RS256'];

var acceptField = {};
acceptField.alg = acceptAlg;
acceptField.aud = [];
acceptField.tid = [];
acceptField.iss = [];

const CONSOLE_LOG_TAG_COMP = 'microgateway-plugins custom-extauth';
const LOG_TAG_COMP = 'custom-extauth';

module.exports.init = function(config, logger, stats) {

    var cacheBackends = {};
    //set keyType to pem if the endpoint returns a single pem file
    var keyType = config.hasOwnProperty("keyType") ? config.keyType : 'jwk';
    //check for jwt expiry
    var exp = config.hasOwnProperty('exp') ? config.exp : true;
    //return error from plugin
    var sendErr = config.hasOwnProperty("sendErr") ? config.sendErr : true;
    //preserve or delete the auth header
    var keepAuthHeader = config.hasOwnProperty('keep-authorization-header') ? config['keep-authorization-header'] : true;

    function parameterValue(paramName, res){
        return config[parameterName(paramName, res)] || config[paramName];
    }
    
    function parameterName(paramName, res){
        var base_path = res.proxy.base_path;
        var prefix = base_path.split("/")[1] + "-";

        return prefix+paramName;
    }

    (function(){
        debug("Creating cache...");
        //Should Match: "api1-tenant", "other-api-tenant", and "tenant".
        //Should NOT Match: "mytenant".
        var tenantPatt = /^((-*\w*)*-)?tenant$/; 

        Object.keys(config)
            .filter(n => n.match(tenantPatt))
            .forEach(prop => {
                var tenantValue = config[prop];
                
                //if no tenant, resume...
                if(!tenantValue) return;

                cacheBackends[prop] = {};
                
                cacheBackends[prop].iss = `https://sts.windows.net/${tenantValue}/`

                request({  // The middleware is supposed to be called much later
                    url: `https://login.microsoftonline.com/${tenantValue}/discovery/v2.0/keys`,
                    method: 'GET'
                }, function(err, response, body) {
                    if (err) {
                        debug('publickey gateway timeout');
                        logger.consoleLog('log',{component: CONSOLE_LOG_TAG_COMP}, err);
                    } else {
                        debug("loaded public keys");
                        if (keyType === 'jwk') {
                            debug("keyType is jwk");
                            try {
                                cacheBackends[prop].publicKeys = JSON.parse(body);
                            } catch(e) {
                                logger.consoleLog('log', {component: CONSOLE_LOG_TAG_COMP}, e.message );
                            }                
                        } else {
                            //the body should contain a single pem
                            cacheBackends[prop].publicKeys = body;
                        }
                        debug(`Added public keys cache for "${prop}".`);
                    }
                });
            });
    })();
    
    
    function getJWK(kid, localPublicKeys) {
        if (localPublicKeys.keys && localPublicKeys.keys.constructor === Array) {
            for (var i = 0; i < localPublicKeys.keys.length; i++) {
                if (localPublicKeys.keys[i].kid === kid) {
                    return localPublicKeys.keys[i];
                }
            }
            debug("no public key that matches kid found");
            return null;
        } else if (localPublicKeys[kid]) { //handle cases like https://www.googleapis.com/oauth2/v1/certs
            return localPublicKeys[kid];
        } else { //if the publickeys url does not return arrays, then use the only public key
            debug("returning default public key");
            return localPublicKeys;
        }
    }


    function validateJWT(pem, payload, exp) {
        var isValid = false;
        if (exp) {
            debug("JWT Expiry enabled");
            acceptField.verifyAt = rs.KJUR.jws.IntDate.getNow();
            try {
                isValid = rs.jws.JWS.verifyJWT(payload, pem, acceptField);
            } catch(e) {
                logger.consoleLog('log', {component: CONSOLE_LOG_TAG_COMP}, e.message );
            }
        } else {
            debug("JWT Expiry disabled");
            try {
                isValid = rs.jws.JWS.verify(payload, pem, acceptAlg);
            } catch(e) {
                logger.consoleLog('log', {component: CONSOLE_LOG_TAG_COMP}, e.message );
            }
        }
        return isValid;
    }


    

    return {
        onrequest: function(req, res, next) {
            debug('plugin onrequest');
            var isValid = false;
            var tenant = parameterValue("tenant", res);
            
            //if no tenant, resume...
            if(!tenant) return next();
            
            acceptField.aud[0] = parameterValue("app_id", res);
            acceptField.tid[0] = tenant;
            var localCache = cacheBackends[parameterName("tenant", res)] || cacheBackends["tenant"];
            acceptField.iss[0] = localCache.iss;
            var localPublicKeys = localCache.publicKeys;

            try {
                var jwtpayload = authHeaderRegex.exec(req.headers['authorization']);
                if ( !(jwtpayload) || (jwtpayload.length < 2) ) {
                    debug("ERROR - JWT Token Missing in Auth header");
                    delete(req.headers['authorization']);
                    if (sendErr) {
                        return sendError(req, res, next, logger, stats, 'missing_authorization', 'missing_authorization');
                    }
                } else {
                    var jwtdecode = JWS.parse(jwtpayload[1]);
                    if ( jwtdecode.headerObj ) {
                        var kid = jwtdecode.headerObj.kid;
                        debug("Found jwt kid: " + kid);
                        if ( keyType !== 'jwk' ) {
                            debug("key type is PEM");
                            isValid = validateJWT(localPublicKeys, jwtpayload[1], exp);
                            if (isValid) {
                                if (!keepAuthHeader) {
                                    delete(req.headers['authorization']);
                                }
                            } else {
                                debug("ERROR - JWT is invalid");
                                delete(req.headers['authorization']);
                                if (sendErr) {
                                    return sendError(req, res, next, logger, stats, 'invalid_token','invalid_token');
                                }                                
                            }
                        } else if (!kid && keyType === 'jwk') {
                            debug("ERROR - JWT Missing kid in header");
                            delete(req.headers['authorization']);
                            if (sendErr) {
                                return sendError(req, res, next, logger, stats, 'invalid_token','invalid_token');
                            }
                        } else {
                            var jwk = getJWK(kid, localPublicKeys);
                            if (!jwk) {
                                debug("ERROR - Could not find public key to match kid");
                                delete(req.headers['authorization']);
                                if (sendErr) {
                                    return sendError(req, res, next, logger, stats, 'invalid_authorization','invalid_authorization');
                                }                                
                            } else {
                                debug("Found JWK");
                                var publickey = rs.KEYUTIL.getKey(jwk);
                                var pem = rs.KEYUTIL.getPEM(publickey);
                                isValid = validateJWT(pem, jwtpayload[1], exp);
                                if (isValid) {
                                    debug("JWT is valid");
                                    if (!keepAuthHeader) {
                                        delete(req.headers['authorization']);
                                    }
                                } else {
                                    debug("ERROR - JWT is invalid");
                                    delete(req.headers['authorization']);
                                    if (sendErr) {
                                        return sendError(req, res, next, logger, stats, 'access_denied', 'JWT is invalid');
                                    }                                    
                                }
                            }
                        }
                    } else {
                        debug("ERROR - Missing header in JWT");
                        delete(req.headers['authorization']);
                        if (sendErr) {
                            return sendError(req, res, next, logger, stats,'missing_authorization', 'missing_authorization');
                        }
                    }
                }
            } catch (err) {
                debug("ERROR - " + err);
                delete(req.headers['authorization']);
                if (sendErr) {
                    return sendError(req, res, next, logger, stats,'invalid_authorization', 'invalid_authorization');
                }
            }
            next();
        }
    };

  
}


function setResponseCode(res,code) {
    switch ( code ) {
        case 'invalid_request': {
            res.statusCode = 400;
            break;
        }
        case 'access_denied':{
            res.statusCode = 403;
            break;
        }
        case 'invalid_token':
        case 'missing_authorization':
        case 'invalid_authorization': {
            res.statusCode = 401;
            break;
        }
        case 'gateway_timeout': {
            res.statusCode = 504;
            break;
        }
        default: {
            res.statusCode = 500;
            break;
        }
    }
}


function sendError(req, res, next, logger, stats, code, message) {

    setResponseCode(res,code)

    var response = {
        error: code,
        error_description: message
    };
    const err = Error(message)
    debug('auth failure', res.statusCode, code, message ? message : '', req.headers, req.method, req.url);
    logger.eventLog({level:'error', req: req, res: res, err:err, component:LOG_TAG_COMP }, message);

    //opentracing
    if (process.env.EDGEMICRO_OPENTRACE) {
        const traceHelper = require('../microgateway-core/lib/trace-helper');
        traceHelper.setChildErrorSpan('extauth', req.headers);    
    }

    if (!res.finished) res.setHeader('content-type', 'application/json');
    res.end(JSON.stringify(response));
    stats.incrementStatusCount(res.statusCode);
    next(code, message);
    return code;
}