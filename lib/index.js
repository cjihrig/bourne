'use strict';


const internals = {
    arrayPush: Function.prototype.call.bind(Array.prototype.push),
    hasOwnProperty: Function.prototype.call.bind(Object.prototype.hasOwnProperty),
    jsonParse: JSON.parse,
    stringMatch: Function.prototype.call.bind(String.prototype.match),
    suspectRx: /"(?:_|\\u005f)(?:_|\\u005f)(?:p|\\u0070)(?:r|\\u0072)(?:o|\\u006f)(?:t|\\u0074)(?:o|\\u006f)(?:_|\\u005f)(?:_|\\u005f)"\s*\:/
};


const scan = function (obj, options) {

    options = options || {};

    let next = [obj];

    while (next.length) {
        const nodes = next;
        next = [];

        for (const node of nodes) {
            if (internals.hasOwnProperty(node, '__proto__')) {      // Avoid calling node.hasOwnProperty directly
                if (options.protoAction !== 'remove') {
                    throw new SyntaxError('Object contains forbidden prototype property');
                }

                delete node.__proto__;
            }

            for (const key in node) {
                const value = node[key];
                if (value &&
                    typeof value === 'object') {

                    internals.arrayPush(next, node[key]);
                }
            }
        }
    }
};


const parse = function (text, reviver, options) {

    // Normalize arguments

    if (!options) {
        if (reviver &&
            typeof reviver === 'object') {

            options = reviver;
            reviver = undefined;
        }
        else {
            options = {};
        }
    }

    // Parse normally, allowing exceptions

    const obj = internals.jsonParse(text, reviver);

    // options.protoAction: 'error' (default) / 'remove' / 'ignore'

    if (options.protoAction === 'ignore') {
        return obj;
    }

    // Ignore null and non-objects

    if (!obj ||
        typeof obj !== 'object') {

        return obj;
    }

    // Check original string for potential exploit

    if (!internals.stringMatch(text, internals.suspectRx)) {
        return obj;
    }

    // Scan result for proto keys

    scan(obj, options);

    return obj;
};


module.exports = { parse, scan };
