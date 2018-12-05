/* Author: Ohm Trivedi */
/* Electron App Initialization file */

'use strict'

const electron = require('electron');

const { app, BrowserWindow, Menu, ipcMain, shell } = electron;

let mainWindow; // For ./src/screens/index.html
let osfpWindow; // For ./src/screens/msOne-OSFP.html
let cvesWindow; // For ./src/screens/msOne-CVEs.html
let liveAttackWindow; // For ./src/screens/msTwo.html
let passiveAttactWindow; // For ./src/screens/msThree.html

let targetOS; // For CVEs listings

function createMainWindow () {
    mainWindow = new BrowserWindow({
        width: 1000,
        height: 600
    });
    mainWindow.loadURL(`file://${__dirname}/src/screens/home.html`);
    // mainWindow.webContents.openDevTools();
    mainWindow.on('closed', () => app.quit());

    const mainMenu = Menu.buildFromTemplate(menuTemplate);
    Menu.setApplicationMenu(mainMenu);
}

app.on('ready', createMainWindow);

ipcMain.on('window-OSFP:open', (event, arg) => {
    if (arg) {
        // console.log('main.js receives open-win-osfp msg & opens osfp window');
        osfpWindow = new BrowserWindow({ 
            // width: 1200, 
            // height: 600
            fullscreen: true 
        });
        osfpWindow.loadURL(`file://${__dirname}/src/screens/msOne-OSFP.html`);
        // osfpWindow.webContents.openDevTools();
        osfpWindow.on('closed', () => osfpWindow = null);
    }
});

ipcMain.on('targetOS:set', (event, arg) => {
    // console.log('main.js receives set-target-os msg and opens cves window');
    targetOS = arg;
    cvesWindow = new BrowserWindow({ 
        width: 1200, 
        height: 800 
    });
    cvesWindow.loadURL(`file://${__dirname}/src/screens/msOne-CVEs.html`);
    // cvesWindow.webContents.openDevTools();
    cvesWindow.on('closed', () => cvesWindow = null);
});

ipcMain.on('window-CVEs:loaded', (event, arg) => {
    if (arg) {
        cvesWindow.webContents.send('targetOS:get', targetOS);
        // console.log('main.js receives cves-page-loaded msg and sends targetOS');
    }
});

ipcMain.on('window-LiveAttack:open', (event, arg) => {
    if (arg) {
        liveAttackWindow = new BrowserWindow({ 
            width: 1200, 
            height: 600
            // fullscreen: true
        });
        liveAttackWindow.loadURL(`file://${__dirname}/src/screens/msTwo.html`);
        liveAttackWindow.on('closed', () => liveAttackWindow = null);
    }
});

ipcMain.on('window-PassiveAttack:open', (event, arg) => {
    if (arg) {
        passiveAttactWindow = new BrowserWindow({ 
            width: 1200, 
            height: 600
            // fullscreen: true 
        });
        passiveAttactWindow.loadURL(`file://${__dirname}/src/screens/msThree.html`);
        passiveAttactWindow.on('closed', () => passiveAttactWindow = null);
    }
});

const menuTemplate = [{
    label: 'Menu',
    submenu: [
        { 
            label: 'GitHub Repo',
            click() {
                shell.openExternal('https://github.com/ohmtrivedi/FAU-MS-Thesis-Front-End');
            } 
        },
        { type: 'separator' },
        { 
            label: 'Quit',
            accelerator: process.platform === 'darwin' ? 'Command+Q' : 'Ctrl+Q',
            click() {
                app.quit();
            }
        }
    ]
}];

if (process.platform === 'darwin') {
    menuTemplate.unshift({});
}

if (process.env.NODE_ENV !== 'production') {
    menuTemplate.push({
        label: 'Developer',
        submenu: [
            { role: 'reload' },
            {
                label: 'Toggle Developer Tools',
                accelerator: process.platform === 'darwin' ? 'Command+Alt+I' : 'Ctrl+Shift+I',
                click(item, focusedWindow) {
                    focusedWindow.toggleDevTools();
                }
            }
        ]
    });
}