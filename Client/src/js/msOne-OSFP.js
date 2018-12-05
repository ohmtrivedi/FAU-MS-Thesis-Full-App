/* Author: Ohm Trivedi */
/* JS file for msOne-OSFP Window */

'use strict'

const electron = require('electron'),
    axios = require('axios'),
    shodanClient = require('shodan-client'),
    net = require('net');

const { ipcRenderer, remote } = electron;

const API_URL = 'ohm.eng.fau.edu:80';
// const API_URL = '10.15.4.110:14000';
// const API_URL = '10.13.210.243:12001';
// const API_URL = '192.168.1.81:12001';
const SHODAN_API_KEY = 'Z7cRqljCHEczyRZQbuG3djUxikmDW6sT';

let newRow, cellRef_IP, cellRef_Location, 
    cellRef_Ports, cellRef_OS, cellRef_CVES;

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

const ipValid = document.getElementById('ipValid');
const table = document.getElementById('results');
const targetIP = document.getElementById('targetIP');
let btnID = 1;

document.querySelector('#btn0').addEventListener('click', (event) => {
    ipcRenderer.send('targetOS:set', 'Microsoft Windows Server 2008 R2 SP1');
    // console.log('From osfp.js: Sending set-target-os msg');
});

function getIPInfo(queryIP, locationCell, portsCell) {
    shodanClient
        .host(queryIP, SHODAN_API_KEY, { minify: true })
        .then(result => {
            // console.log(result);
            let { city, country_name, ports } = result;
            locationCell.innerHTML = (city ? `${city}, ` : '') + (country_name ? country_name : '');
            portsCell.innerHTML = (ports ? ports.join(',') : 'Unavailable');
        })
        .catch(err => {
            locationCell.innerHTML = 'Unavailable';
            portsCell.innerHTML = 'Unavailable';
            console.log(err);
        });
}

function getOS(queryIP, osCell, cvesCell) {
    axios.get(`http://${API_URL}/api/msOne/fpOS?target=${queryIP}`)
        .then(response => {
            // console.log(response);
            const { osGuess } = response.data;
            osCell.innerHTML = '<b>' + osGuess + '</b>';
            if (!osGuess.startsWith("Too many")) {
                cvesCell.innerHTML = '<button class=\"cve_btns\" id=btn' + btnID + '>Get CVEs</button>';
                cvesCell.addEventListener('click', (event) => {
                    ipcRenderer.send('targetOS:set', osGuess);
                    // console.log('From osfp.js: Sending set-target-os msg');
                });
                btnID += 1;
            }
        })
        .catch(err => {
            osCell.innerHTML = '<u>Errr, error!</u>'
            console.log(err);
        });
}

document.querySelector('#submitBtn').addEventListener('click', (event) => {
    if(net.isIPv4(targetIP.value)) {
        ipValid.innerHTML = '';
        newRow = table.insertRow(-1);
        cellRef_IP = newRow.insertCell(0);
        cellRef_Location = newRow.insertCell(1);
        cellRef_Ports = newRow.insertCell(2);
        cellRef_OS = newRow.insertCell(3);
        cellRef_CVES = newRow.insertCell(4);

        cellRef_IP.innerHTML = '<h4>' + targetIP.value + '</h4>';
        // console.log('From osfp.js: Getting IP details from Shodan...');
        getIPInfo(targetIP.value, cellRef_Location, cellRef_Ports);

        // console.log('From osfp.js: Sending OS FP request of ' + targetIP.value);
        getOS(targetIP.value, cellRef_OS, cellRef_CVES);
    } else {
        ipValid.style.color = 'red';
        ipValid.innerHTML = '<b>Invalid IP, try again!</b>';
    }
});
