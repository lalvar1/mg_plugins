'use strict';
var debug = require('debug')

module.exports.init = function(config, logger, stats) {

    function overrideHeaders(req){
        const configHeaders = config.overrideHeaders;
        if(! configHeaders)return;

        Object.keys(configHeaders)
            .forEach(function(header) {
                let newValue = configHeaders[header];
                req.headers[header] = newValue;
            }
        );
    }

    function addMissingHeaders(req){
        const configHeaders = config.addMissingHeaders;
        if(! configHeaders)return;

        Object.keys(configHeaders)
            .forEach(function(header) {
                let newValue = configHeaders[header];
                if(! req.headers[header]) req.headers[header] = newValue;
            }
        );
    }

    function removeHeaders(req){
        const configHeaders = config.removeHeaders;
        if(! configHeaders)return;

        configHeaders.forEach(function(header) {
            delete req.headers[header];
        });
    }

    return {

        onrequest: function(req, res, next) {
            overrideHeaders(req);
            addMissingHeaders(req);
            removeHeaders(req);

            next();
        }
    };
}
