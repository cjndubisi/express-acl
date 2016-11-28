'use strict';
const fs = require('fs');
const utils = require('./utils');
const yaml = require('js-yaml');
const _ = require('lodash');
const redis = require('redis')
var client;
/**
 * Get the rules from the specified file path
 * @param {[String]} path
 * @param {[String]} encoding
 * @param {[Boolean]} isYaml
 * @return {[Object Map]}
 */

function getRules(path, encoding, isYaml) {
  let rules, buffer;

  try {
    buffer = fs.readFileSync(path, { encoding });
    rules = (isYaml) ? yaml.safeLoad(buffer) : JSON.parse(buffer);
  } catch (error) {
    throw Error(error);
  }

  return utils.validate(rules);
}

/**
 * Get the rules from the specified file path
 * @param {[String]} path
 * @param {[String]} encoding
 * @param {[Boolean]} isYaml
 * @return {[JSON]}
 */

function rulesFromFilePath(path, encoding, isYaml) {
  let rules, buffer;

  try {
    buffer = fs.readFileSync(path, { encoding });
    rules = (isYaml) ? yaml.safeLoad(buffer) : JSON.parse(buffer);
    if (utils.validate(rules)) {
      return rules;
    }
  } catch (error) {
    throw Error(error);
  }
}


/**
 * Callback for fetching existing rules from Redis server.
 *
 * @callback cb
 * @param {[err]} error
 * @param {[JSON]} rules
 */

/**
 * Get the rules from Redis server
 * @param {[JSON]} config
 * @param {[Function]} cb
 */
function redisGetRules(config, cb) {
  let port = config.port;
  let host = config.host;
  let key = config.key;
  if (!key) {
    return cb(new Error('Missing redis Key'), null);
  }

  client = client || (port && host) ? redis.createClient(port, host) : redis.createClient()

  client.on('error', function (err) {
    cb(err, null);
  });

  client.get(key, function(err, rules) {
    if (!rules || err) {
      return cb(err || new Error(key+' not set'), null);
    }
    return cb(null, utils.validate(JSON.parse(rules)));
  });

} 

/**
 * Callback for saving rules to Redis server.
 *
 * @callback cb
 * @param {[Error]} err
 */
 
/**
 * Get the rules from Redis server
 * @param {[string]} config 
 * @param {[Object]} rules
 * @param {[Function]} cb
 */

function saveToRedis(key, rules, cb) {
  client.set(key, JSON.stringify(rules), function (err, reply) {
      if (err) {
        return cb(err);
      }
      return cb(null);
  })
}

/**
 * [Gets the methods from the selected group]
 * @param  {[Object]} group
 * @param  {[String]} resource
 * @return {[Array/String]} Returns an array of methods
 * or a string incase a glob is used;
 */

function getPolicy(permissions, resource) {
  let policy = _.find(permissions, {
    resource: resource
  });

  if (policy) {
    return {
      methods: policy.methods,
      action: policy.action
    };
  }
  return policy;
}

function getRole(res, decoded, session) {

  /**
   * if role is attached to the session
   * Return role
   */

  if (decoded && decoded.role) {
    return decoded.role;
  }

  /**
   * if role is attached to the decoded
   * Return role
   */

  if (session && session.role) {
    return session.role;
  }

  /**
   * if role is not attached to the session or decoed object
   * Return role
   */

  return utils.deny(res, 404, 'REQUIRED: Role not found');
}


/**
 * [resource finds the resource based of the baseurl specified]
 * @param  {Function} next    [Express next function]
 * @param  {[String}  url     [Request url]
 * @param  {[String]} baseUrl [The api baseUrl]
 * @return {[String]}           [The matched resource]
 */

function resource(next, url, baseUrl) {
  let base = (baseUrl) ? baseUrl.match(/([A-Z])\w+/gi) : '';
  let lengthOfTheBaseUrl = (base) ? base.length : 0;
  let arr = url.match(/([A-Z])\w+/gi);

  if (arr) {
    arr = arr.splice(lengthOfTheBaseUrl);
    return arr[0];
  }
  return next();
}

module.exports = {
  getRules,
  getPolicy,
  getRole,
  resource,
  redisGetRules,
  rulesFromFilePath,
  saveToRedis
};
