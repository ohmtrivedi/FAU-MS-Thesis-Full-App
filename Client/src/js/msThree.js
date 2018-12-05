/* Author: Ohm Trivedi */
/* JS file for msThree Window */

'use strict'

const electron = require('electron'),
    { exec } = require('child_process'),
    request = require('request'),
    fs = require('fs'),
    axios = require('axios');
    // util = require('util');

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

document.querySelector('form').addEventListener('submit', (event) => {
    event.preventDefault();
    const { name, path } = document.querySelector('input').files[0];
    
    let commandToExec = `capinfos -Traec ${path}`;
    // console.log('Executing: ' + commandToExec);
    exec(commandToExec, (error, stdout, stderr) => {
        if (error) throw error;
        else if (stderr) throw stderr;
        else {
            let details = stdout.split('\t');
            document.querySelector('#pcapInfo').innerHTML = `File chosen: <b>${name}</b><br>`;
            document.querySelector('#pcapInfo').innerHTML += `Number of Packets: <b>${details[1]}</b><br>`;
            document.querySelector('#pcapInfo').innerHTML += `Start Time: <b>${details[2]}</b><br>`;
            document.querySelector('#pcapInfo').innerHTML += `End Time: <b>${details[3]}</b><br>`;
        }
    });

    let req = request.post(`http://${API_URL}/fileupload`, (err, response) => {
        if (err) throw err;
        else {
            if (response.statusCode == 200) {
                document.querySelector('#fileUpload').style.display = 'block';
                document.querySelector('#fileUpload').style.color = 'green';
                document.querySelector('#fileUpload').innerHTML = '<b>File Uploaded!</b>';
                axios.get(`http://${API_URL}/api/msThree/analyzePCAP?fileName=${name}`)
                .then((response) => {
                    // console.log(response.data);
                    let { consoleLogs, pktCounts, analysisResults } = response.data;
                    document.querySelector('#summary').innerHTML = processResults(pktCounts);
                    document.querySelector('#logsDiv1').style.display = 'block';
                    document.querySelector('#consoleLogsSLA').value = consoleLogs;
                    document.querySelector('#logsDiv2').style.display = 'block';
                    document.querySelector('#consoleLogsSFA').value = analysisResults;
                })
                .catch(err => {
                    document.querySelector('#summary').innerHTML = '<b><u>Errr, error!</u></b>';
                    throw err;
                });
            } else {
                document.querySelector('#fileUpload').style.display = 'block';
                document.querySelector('#fileUpload').style.color = 'red';
                document.querySelector('#fileUpload').innerHTML = '<b>File Upload failed!</b>';
            }
        }
    });
    let form = req.form();
    form.append('file', fs.createReadStream(path));
});

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
    results += `Without established TCP Session: <b>${pktCounts.statefullAttacks.noSession}</b><br>`;
    results += `FIN Scan: <b>${pktCounts.statefullAttacks.FINScan}</b><br>`;
    results += `ICMP Packets with invalid code: <b>${pktCounts.icmpAttacks.invalidCode}</b><br>`;
    results += `ICMP Packets with invalid type: <b>${pktCounts.icmpAttacks.invalidType}</b><br>`;

    return results;
}
