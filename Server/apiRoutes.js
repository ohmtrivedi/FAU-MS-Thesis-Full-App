/* Author: Ohm Trivedi */
/* Routes for Express API */

'use strict'

module.exports = [{
    prefix: '/api',
    pin: 'role:api,path:*',
    map: {
        msOne: {
            GET: true,
            suffix: '/:operation'
        },
        msTwo: {
            GET: true,
            suffix: '/:operation'
        },
        msThree: {
            GET: true,
            suffix: '/:operation'
        }
        // getCVEs: {
        //     POST: true
        // }
    }
}]
