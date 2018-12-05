/* Author: Ohm Trivedi */
/* Plugin for Fingerprinting Attack Detection (Passive mode) */

'use strict'

const { fork } = require('child_process');
    // util = require('util');

module.exports = function msThree (options) {
    let seneca = this; 

    seneca.add({ init: 'msThree' }, function(pluginInfo, respond) {
        console.log(options.message);
        respond();
    });

    seneca.add({ role: 'msThree', cmd: 'analyzePCAP' }, function (msg, respond) {
        const { fileName } = msg;
        let filePath = `${__dirname}/uploads/${fileName}`;

        let newSession = fork('./passiveFPDetection.js',  [], { silent: false });
        newSession.send(filePath);
        newSession.on('message', (results) => {
            let { pktCounts, consoleLogs, analysisResults } = results;
            newSession.kill();
            console.log(`Response: Analyzed ${pktCounts.totalPkts} packets.`);
            respond(null, { pktCounts, consoleLogs, analysisResults });
        });
    });
}

