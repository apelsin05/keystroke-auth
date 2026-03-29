const keystrokes = [];
let previousUpTime = null;
let position = 0;
let hasBackspace = false;

const passwordField = document.getElementById('password');

if (passwordField) {
    passwordField.addEventListener('keydown', function(event) {
        if (event.key === 'Backspace') {
            hasBackspace = true;
        }

        const thisDownTime = performance.now();
        let flightTime = null;
        if (previousUpTime !== null) {
            flightTime = thisDownTime - previousUpTime;
        }
        event.target._downTime = thisDownTime;
        event.target._flightTime = flightTime;
    });

    passwordField.addEventListener('keyup', function(event) {
        const thisUpTime = performance.now();
        const thisDownTime = event.target._downTime;
        const dwellTime = thisUpTime - thisDownTime;
        keystrokes.push({
            key: event.key,
            position: position,
            downTime: thisDownTime,
            upTime: thisUpTime,
            dwellTime: dwellTime,
            flightTime: event.target._flightTime
        });
        previousUpTime = thisUpTime;
        position++;
    });

    passwordField.addEventListener('paste', function(event) {
        event.preventDefault();
    });

    passwordField.addEventListener('input', function() {
        if (passwordField.value.length === 0) {
            previousUpTime = null;
            position = 0;
            keystrokes.length = 0;
            hasBackspace = false;
        }
    });
}

const deviceInfo = {
    userAgent:    navigator.userAgent    || '',
    screenWidth:  screen.width          || '',
    screenHeight: screen.height         || '',
    timezone:     Intl.DateTimeFormat().resolvedOptions().timeZone || '',
    language:     navigator.language    || '',
    platform:     navigator.platform    || '',
};

const deviceToken = document.cookie.split('; ').find(r => r.startsWith('device_token='))?.split('=')[1] || ''; // Extract device token from cookie

const form = document.querySelector('form');
if (form) {
    form.addEventListener('submit', function(event) {
        event.preventDefault();

        const hiddenKeystrokes = document.getElementById('keystrokes_data');
        if (hiddenKeystrokes) {
            hiddenKeystrokes.value = JSON.stringify({
                events:      keystrokes,
                hasBackspace: hasBackspace,
            });
        }

        const hiddenToken = document.getElementById('device_token');
        if (hiddenToken) {
            hiddenToken.value = deviceToken;
        }

        const fields = [
            ['device_userAgent',    deviceInfo.userAgent],
            ['device_screenWidth',  deviceInfo.screenWidth],
            ['device_screenHeight', deviceInfo.screenHeight],
            ['device_timezone',     deviceInfo.timezone],
            ['device_language',     deviceInfo.language],
            ['device_platform',     deviceInfo.platform],
        ];
        fields.forEach(([name, value]) => {
            const input = document.getElementById(name);
            if (input) input.value = value;
        });

        this.submit();
    });
}