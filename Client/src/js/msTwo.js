/* Author: Ohm Trivedi */
/* JS file for msTwo Window */

'use strict'

const electron = require('electron'),
    axios = require('axios');

const { remote } = electron;

const API_URL = 'ohm.eng.fau.edu:80';
// const API_URL = '10.15.4.110:14000';
// const API_URL = '10.13.210.243:12001';
// const API_URL = '192.168.1.81:12001';

document.addEventListener('keydown', event => {
    let thisWindow = remote.getCurrentWindow(); 
    switch (event.key) {
        case 'Escape':
            if (thisWindow.isFullScreen()) thisWindow.setFullScreen(false);
            break;
        case 'F11':
            if (!thisWindow.isFullScreen()) thisWindow.setFullScreen(true);
            break;
    }
});

let timer1, timer2;

document.querySelector('#startBtn').addEventListener('click', (event) => {
    axios.get(`http://${API_URL}/api/msTwo/start`)
        .then((response) => {
            // console.log(response);
            let { status } = response.data;
            document.querySelector('#sessionStatus').innerHTML = `Status: <b>${status}</b>`;
            document.querySelector('#summary').style.display = 'none';
            document.querySelector('#logsDiv1').style.display = 'block';
            document.querySelector('#consoleLogsSLA').value = '';
            document.querySelector('#logsDiv2').style.display = 'block';
            document.querySelector('#consoleLogsSFA').value = '';
        })
        .catch(err => {
            throw err;
        });
    timer1 = setInterval(getStatelessAttackLogs, 5000);
    timer2 = setInterval(getStatefullAttackLogs, 70000);
});

document.querySelector('#stopBtn').addEventListener('click', (event) => {
    axios.get(`http://${API_URL}/api/msTwo/stop`)
        .then((response) => {
            // console.log(response);
            let { status, pktCounts, SLALogs, SFALogs } = response.data;
            document.querySelector('#sessionStatus').innerHTML = `Status: <b>${status}</b>`;
            document.querySelector('#summary').style.display = 'block';
            document.querySelector('#summary').innerHTML = processResults(pktCounts);
            document.querySelector('#consoleLogsSLA').value += SLALogs;
            document.querySelector('#consoleLogsSFA').value += SFALogs;
            clearInterval(timer1);
            clearInterval(timer2);
        })
        .catch(err => {
            throw err;
        });
});

let getStatelessAttackLogs = () => {
    axios.get(`http://${API_URL}/api/msTwo/updateSLA`)
        .then((response) => {
            // console.log(response);
            let { SLALogs } = response.data;
            if (SLALogs.length > 0) {
                document.querySelector('#consoleLogsSLA').value += SLALogs;
            } else {
                console.log('No update (SLA) this time!');
            }
        })
        .catch(err => {
            throw err;
        });
}

let getStatefullAttackLogs = () => {
    axios.get(`http://${API_URL}/api/msTwo/updateSFA`)
        .then((response) => {
            // console.log(response);
            let { SFALogs } = response.data;
            if (SFALogs.length > 0) {
                document.querySelector('#consoleLogsSFA').value += SFALogs;
            } else {
                console.log('No update (SFA) this time!');
            }
        })
        .catch(err => {
            throw err;
        });
}

let processResults = (pktCounts) => {
    let results = '<b>Summary</b><br>';
    results += `Total packets parsed: <b>${pktCounts.totalPkts}</b><br>`;
    results += `Total TCP Packets: <b>${pktCounts.tcpPkts}</b><br>`;
    results += `Total UDP Packets: <b>${pktCounts.udpPkts}</b><br>`;
    results += `Total ICMP Packets: <b>${pktCounts.icmpPkts}</b><br><br>`;
    results += '<b>Some unusual packets were found as follows, suspecting OS Fingerprinting attempt!</b><br>';
    results += `NULL Scan: <b>${pktCounts.statelessAttacks.NULLScan}</b><br>`;
    results += `Only PSH Set: <b>${pktCounts.statelessAttacks.PSH}</b><br>`;
    results += `SYN & FIN Set: <b>${pktCounts.statelessAttacks.SYN_FIN}</b><br>`;
    results += `RST & FIN Set: <b>${pktCounts.statelessAttacks.RST_FIN}</b><br>`;
    results += `RST & SYN Set: <b>${pktCounts.statelessAttacks.RST_SYN}</b><br>`;
    results += `FIN & URG Set: <b>${pktCounts.statelessAttacks.FIN_URG}</b><br>`;
    results += `SYN & URG Set: <b>${pktCounts.statelessAttacks.SYN_URG}</b><br>`;
    results += `SYN & FIN & URG Set: <b>${pktCounts.statelessAttacks.SYN_FIN_URG}</b><br>`;
    results += `X-MAS Scan Set: <b>${pktCounts.statelessAttacks.XMASScan}</b><br>`;
    results += `SYN & FIN & PSH & URG Set: <b>${pktCounts.statelessAttacks.SYN_FIN_PSH_URG}</b><br>`;
    results += `SYN & ECN & CWR Set: <b>${pktCounts.statelessAttacks.SYN_ECE_CWR}<br></b>`;
    results += `ACK & IP-DF Set & Window Size = 1024: <b>${pktCounts.statelessAttacks.ACK_DF_WS1024}</b><br>`;
    // results += `Without established TCP Session: <b>${pktCounts.statefullAttacks.noSession}</b><br>`;
    results += `FIN Scan: <b>${pktCounts.statefullAttacks.FINScan}</b><br>`;
    results += `ICMP Packets with invalid code: <b>${pktCounts.icmpAttacks.invalidCode}</b><br>`;
    results += `ICMP Packets with invalid type: <b>${pktCounts.icmpAttacks.invalidType}</b><br>`;

    return results;
}