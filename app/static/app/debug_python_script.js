





 // Function to run Python script
 function debug_python_script(scriptToRun, consoleOutput, language) {
    const baseUrl = window.location.origin;

    // Select the meta tag with the name attribute 'csrf-token'
    const metaCsrfToken = document.querySelector('meta[name="csrf-token"]');

    // Get the content attribute value
    const csrfToken = metaCsrfToken ? metaCsrfToken.getAttribute('content') : null;

    if (!csrfToken) {
        console.error('CSRF token not found');
        consoleOutput.innerHTML += 'Error: CSRF token not found\n';
    } else {
        const dataForm = new FormData();
        dataForm.append("code", scriptToRun);
        dataForm.append("language", language)

        const myHeaders = new Headers();
        // No need to set Content-Type for FormData
        myHeaders.append('X-CSRFToken', csrfToken);

        fetch(baseUrl + '/course/learn/laubcode/debug-python', {
            method: "POST",
            body: dataForm,
            headers: myHeaders,
        })
            .then(response => response.json())
            .then(data => {
                
                if (data) {
                    console.log("Code execution result:", data);
                    //consoleOutput.innerHTML += '#laubcode\\editor\\main$: \n' + JSON.stringify(data.output) + '\n';
                    
                    consoleOutput.innerHTML += '<pre>' + data.output + '</pre>'
                } else {
                    consoleOutput.innerHTML += '<pre class="text-danger">Failed! ' + data.output + '</pre>'
                }
            })
            .catch(err => {
                console.error('Error:', err);
                consoleOutput.innerHTML += '<pre class="text-danger">Error! ' + err + '</pre>'
            });
    }

}

/* Run with pyodide */
async function smain(code) {
    try{
        let pyodide = await loadPyodide();
            console.log(pyodide.runPython(`
            import sys
            sys.version
        `));
        //pyodide.runPython("print(1 + 2)");
        pyodide.runPython(code);
    }catch(err){
        console.error(`Error: ${err}`)
    }
   
}

async function runPythonScript(scriptToRun) { 
    let pyodide = await loadPyodide();
    let outputDiv = document.getElementById('output');
    
    let pythonVersion = pyodide.runPython(`
        import sys
        sys.version
    `);
    consoleOutput.innerHTML += `Python Version: ${pythonVersion} \n` 
    consoleOutput.innerHTML += 'Check your browser console in case of existing "print" commands in your code \n'
    consoleOutput.innerHTML += '#laubcode\\editor\\main$: \n';
    
    //let result = pyodide.runPython("print(2 + 2)");
    /*await pyodide.runPythonAsync(`
    print(2 + 2)
    soma=2+5
    # Display the image in the HTML
    from js import document
    document.getElementById('consoleOutput').innerHTML = f'<p>Result of 1 + 2: {soma}</p>'
    
    `);
    var print = 'print(22+4)'
    var scriptToRun = `
    a=11
    b=111
    soma=a+b
    print(soma)
    soma
    
    `*/
    /*await pyodide.runPythonAsync(`
    ${print}          
    # Display the image in the HTML
    from js import document
    document.getElementById('consoleOutput').innerHTML = f'<p>Result of 1 + 2: {scriptToRun}</p>'
    
    `);*/

    try {
        if(scriptToRun !=''){
            let output = pyodide.runPython(scriptToRun);

            if(output === 'undefined'){
                document.getElementById('consoleOutput').innerHTML += `
                Probably no variable hasbeen set to be printed.
                Follow the example below:
                a=12
                b=11
                soma=a+b
                # Use the 'print' command to get the response on browser console
                print(soma)
                # Put the setted variable alone after the end of each block of code 
                soma
                ` + '\n';
            }else{
                document.getElementById('consoleOutput').innerHTML += output + '\n';
            }

            document.getElementById('consoleOutput').innerHTML += '\n\n\n\n...\n\n';
            
        }
        
    } catch (err) {
        document.getElementById('consoleOutput').innerHTML += err + '\n';
    }

    
    //consoleOutput.innerHTML += `<p>Result of 1 + 2: ${result}</p>`;
}
