/* Author: Ohm Trivedi */
/* Script to analyze the collected traffic of each attacker */

// const util = require('util');

const MAX_ALLOWED_CONNECTIONS = 5;
const MAX_ALLOWED_SYN_AND_RST = 5;

let analysisResults = '';

function attackersAnalysis(attackers) {
    // console.log(util.inspect(attackers, false, null, true));
    attackers.forEach((attackerState, attacker) => {
        // console.log(attacker + ": " + attackerState.tcpConnections.length);
        let openConnections = 0; // All open connections to the server
        // console.log(attackerState.tcpConnections);
        attackerState.tcpConnections.forEach(connection => {
            openConnections += connection.pktCounts_SYN;
            if (openConnections >= MAX_ALLOWED_CONNECTIONS && !connection.portScan) {
                connection.portScan = true;
                let curTimestamp = new Date();
                analysisResults += `[${curTimestamp.toLocaleString()}] ${attacker} connected multiple times with the same Source Port: ${connection.srcPort} and Destination Port: ${connection.dstPort} to ${connection.dstIP}. Suspecting OSFP.\n`;
            }
        });

        if (openConnections > (MAX_ALLOWED_CONNECTIONS*3) && !attackerState.allPortsScan) {
            attackerState.allPortsScan = true;
            let curTimestamp = new Date();
            analysisResults += `[${curTimestamp.toLocaleString()}] ${attacker} attempting Port Scan. Suspecting OSFP.\n`;
        }

        if (attackerState.pktCounts_SYNARST >= MAX_ALLOWED_SYN_AND_RST && !attackerState.tcp_SYNARST) {
            attackerState.tcp_SYNARST = true;
            let curTimestamp = new Date();
            analysisResults += `[${curTimestamp.toLocaleString()}] ${attacker} sending multiple SYN then RST TCP packets to multiple ports. Suspecting OSFP.\n`;
        }
    });
    process.send(analysisResults);
}

process.on('message', (args) => {
    let attackers = new Map(JSON.parse(args));
    // console.log(attackers.size);
    // console.log('\n*****Analyzing the collected traffic of all attackers*****\n');
    attackersAnalysis(attackers);
});