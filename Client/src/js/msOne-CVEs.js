/* Author: Ohm Trivedi */
/* JS file for msOne-CVEs Window */

'use strict'

const electron = require('electron'),
    axios = require('axios');

const { ipcRenderer, remote } = electron;

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

const osnameText = document.getElementById('osname');
const table = document.getElementById('cves-results');

document.addEventListener('DOMContentLoaded', function (event) {
    // console.log('From cves.js: DOM fully loaded & parsed');
    ipcRenderer.send('window-CVEs:loaded', true);
    // console.log('From cves.js: Sending did-finish-load msg');
});

ipcRenderer.on('targetOS:get', (event, osName) => {
    // console.log('From cves.js: Received targetOS');
    osnameText.innerHTML = osName;

    // axios.post(`http://${API_URL}/api/getCVEs/`, {
    //   role:'msOne',
    //   cmd: 'getCVEs',
    //   target: osName
    // })
    axios.get(`http://${API_URL}/api/msOne/getCVEs?target=${osName}`)
        .then((response) => {
            console.log(response);
            let cve_ids = response.data.cve_id;
            let cve_descs = response.data.cve_desc;
            for (let i=0; i < cve_ids.length; i++) {
                let newRow = table.insertRow(-1);
                let cell_id = newRow.insertCell(0);
                let cell_desc = newRow.insertCell(1);
                cell_id.innerHTML = cve_ids[i];
                cell_desc.innerHTML = cve_descs[i];
            }
        })
        .catch(err => {
            console.log(err);
        });
});
