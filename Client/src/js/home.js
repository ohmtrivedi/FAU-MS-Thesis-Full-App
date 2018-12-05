const electron = require('electron');

const { ipcRenderer } = electron;

document.querySelector('#msOne').addEventListener('click', (event) => {    
    // console.log("index.js sends message to open osfp.html");
    ipcRenderer.send('window-OSFP:open', true);
});

document.querySelector('#msTwo').addEventListener('click', (event) => {
    ipcRenderer.send('window-LiveAttack:open', true);
});

document.querySelector('#msThree').addEventListener('click', (event) => {
    ipcRenderer.send('window-PassiveAttack:open', true);
});