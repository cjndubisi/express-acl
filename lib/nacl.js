/**
 *  nacl
 *  copyright(c) 2016 - 2019 Andela Kenya Ltd
 *  MIT Lincensed
 */

'use strict';
let helper = require('./helpers');
const utils = require('./utils');
const unless = require('express-unless');
const _ = require('lodash');
let opt = {};
var redisConfig;

/**
 * [config Loads the rules from our config file]
 * @param  {[options]} options [defines where the
 * config file is located, and the encoding type]
 *
 */
function config(config) {
  let options = config || {};
  let yml = options.yml || false;
  opt.baseUrl = options.baseUrl;

  var redis = config.redis



  if (options.rules) {
    opt.rules = utils.validate(options.rules);
  }

  /**
   * Get the filename
   */

  let defaultFilename = yml ? 'nacl.yml' : 'nacl.json';
  let filename = options.filename ? options.filename : defaultFilename;

  /**
   * Merge filename and path
   */

  let path = filename && options.path ?
    (`${options.path}/${filename}`) : filename;


  opt.rules = opt.rules || helper.getRules(path, options.encoding, yml);
  if (!redis) {
    return opt.rules
  }

  var fileRules = helper.rulesFromFilePath(path, options.encoding, yml);

  helper.redisGetRules(redis, function(err, rules) {
    if (err) {
      return helper.saveToRedis(redis.key, fileRules, function (err) {
        if (!err) {
          redisConfig = redis;
          return opt.rules;
        }
      });

    }
    opt.rules = rules;
    redisConfig = redis;
    return opt.rules;
  });
  
}

/**
 * [authorize Express middleware]
 * @param  {[type]}   req  [Th request object]
 * @param  {[type]}   res  [The response object]
 * @param  {Function} next [description]
 * @return {[type]}        [description]
 */

function authorize(req, res, next) {
  let method = req.method;
  let resource = helper.resource(next, req.originalUrl, opt.baseUrl);
  /**
   * if not resource terminate script
   */

  if (!resource || !_.isString(resource)) {
    return;
  }

  /**
   * [group description]
   * @type {[type]}
   */

  let role = helper.getRole(res, req.decoded, req.session);

  if (!_.isString(role) || !role) {
    return;
  }

  /**
   * get resource from the url
   */

  let groupPermissions = opt.rules.get(role);

  /**
   * if no groupPermissions
   */

  if (!groupPermissions || groupPermissions.length === 0) {
    return utils.deny(
      res,
      404,
      'REQUIRED: Group not found'
    );
  }

  let policy = groupPermissions[0];
  let currResource = policy.resource;
  let length = groupPermissions.length;
  let methods = policy.methods;

  /**
   * Globs/ resources
   */
  if (length === 1 && currResource === '*') {
    switch (policy.action) {
      case 'allow':
        return utils.whenGlobAndActionAllow(
          res,
          next,
          method,
          methods
        );
      default:
        return utils.whenGlobAndActionDeny(
          res,
          next,
          method,
          methods
        );
    }
  }

  /**
   * If we have more that one group and we no glob '*'
   */

  if (length >= 1 && resource !== '*') {

    /**
     * [methods Get all the methods defined on the group]
     * @param {[Object]} [group]
     * @param {string} [resource]
     * @type {[Array]}
     */

    let policy = helper.getPolicy(groupPermissions, resource);

    if (!policy) {
      return utils.deny(
        res,
        404,
        'REQUIRED: Policy not found'
      );
    }

    let methods = policy.methods;

    /**
     * If the methods are defined with a glob "*"
     */

    if (methods && _.isString(methods)) {
      return utils.whenResourceAndMethodGlob(
        res,
        next,
        policy.action,
        methods
      );
    }

    /**
     * If the methods are defined in an array
     */

    if (_.isArray(methods)) {
      return utils.whenIsArrayMethod(
        res,
        next,
        policy.action,
        method,
        methods
      );
    }
  }
}

/**
 * Add unless to the authorize middleware.
 * By default express-acl will block all traffic to routes that have no plocy
 * defined against them, this module will enable express-acl to exclude them
 */

authorize.unless = unless;

/**
 * export the functionality
 *
 */

module.exports = {
  config,
  authorize
};
