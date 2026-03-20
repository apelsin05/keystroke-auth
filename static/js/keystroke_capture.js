const keystrokes = [];
let previousUpTime = null;
let position = 0;

const passwordField = document.getElementById('password');

if (passwordField) {

    // keydown: record when key was pressed and compute flight time
    passwordField.addEventListener('keydown', function(event) {
        const thisDownTime = performance.now();
        let flightTime = null;

        if (previousUpTime !== null) {
            flightTime = thisDownTime - previousUpTime;
        }

        // store temporarily so keyup can access them
        event.target._downTime = thisDownTime;
        event.target._flightTime = flightTime;
    });

    // keyup: compute dwell time and push complete record
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

    // block pasting into the password field to ensure keystroke data is consistent with user input
    passwordField.addEventListener('paste', function(event) {
        event.preventDefault();
    });

    // reset state if user clears the password field entirely
    passwordField.addEventListener('input', function() {
        if (passwordField.value.length === 0) {
            previousUpTime = null;
            position = 0;
            keystrokes.length = 0;
        }
    });
}

// on submit: serialize keystroke array into hidden field, then submit
const form = document.querySelector('form');
if (form) {
    form.addEventListener('submit', function(event) {
        event.preventDefault();
        const hidden = document.getElementById('keystrokes_data');
        if (hidden) {
            hidden.value = JSON.stringify(keystrokes);
        }
        this.submit();
    });
}