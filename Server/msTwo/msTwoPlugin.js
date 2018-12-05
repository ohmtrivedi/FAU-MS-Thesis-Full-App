/* Author: Ohm Trivedi */
/* Plugin for Fingerprinting Attack Detection (Live mode) */

'use strict'

const { fork } = require('child_process');
    // util = require('util');

process.setMaxListeners(0);

let newSession, sessionData;

// let addSessionListener = () => {
//     sessionData = null;
//     newSession.on('message', (data) => {
//         sessionData = data;
//     });
// }

module.exports = function msTwo (options) {
    let seneca = this;

    seneca.add({ init: 'msTwo' }, function(pluginInfo, respond) {
        console.log(options.message);
        respond();
    });

    seneca.add({ role: 'msTwo', cmd: 'start' }, function (msg, respond) {
        newSession = fork('./liveFPDetection.js', [], { silent: false });
        newSession.send('start');
        newSession.on('message', (status) => {
            respond(null, { status });
        });
    });

    seneca.add({ role: 'msTwo', cmd: 'getLogs' }, function (msg, respond) {
        if (msg.type == 'StatelessAttack') {
            newSession.send('getLogs:StatelessAttack');
            newSession.on('message', (SLALogs) => {
                respond(null, { SLALogs });
            });
        } else if (msg.type == 'StatefullAttack') {
            newSession.send('getLogs:StatefullAttack');
            newSession.on('message', (SFALogs) => {
                respond(null, { SFALogs });
            });
        }
    });

    seneca.add({ role: 'msTwo', cmd: 'stop' }, function (msg, respond) {
        newSession.send('stop');
        newSession.on('message', (response) => {
            newSession.kill();
            respond(null, response);
        });
    });
}
