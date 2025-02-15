

function debug_javascript(code, consoleOutput) {

    try {

        // Capture console.log output
        const oldLog = console.log;
        console.log = function (...args) {
            consoleOutput.innerHTML += args.join(' ') + '\n';
            oldLog.apply(console, args);
        };

        // Run the code
        const result = eval(code);

        //console.log("Code execution result:", result);

        //alert("Code executed successfully. Check the console for output.");

        // Restore original console.log
        //console.log = oldLog;
    } catch (error) {
        console.error("Error executing code:", error);
        consoleOutput.innerHTML += 'Error: ' + error.message + '\n';
        alert("Error executing code. Check the console for details.");
    }
}
