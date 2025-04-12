


const editor = ace.edit("editor");
            editor.setTheme("ace/theme/monokai");
            editor.session.setMode("ace/mode/javascript");
            editor.setValue(`// Welcome to the LaubCoder Code Editor!
                // Start coding here...
                `);
                //Line number
        //editor.renderer.setShowGutter(true); // or false to hide
        //Highlight Active Line
        editor.setHighlightActiveLine(true); // or false to disable

        // Show print margin
        editor.setShowPrintMargin(false); // or true to show

        
        editor.commands.addCommand({
            name: 'save',
            bindKey: { win: 'Ctrl-S', mac: 'Command-S' },
            exec: function (editor) {
                document.execCommand('save');
            }
        });

        editor.commands.addCommand({
            name: 'copy',
            bindKey: { win: 'Ctrl-C', mac: 'Command-C' },
            exec: function (editor) {
                //document.execCommand('copy');
                navigator.clipboard.writeText(editor.getSelectedText()).then(function() {
                    console.log('Text copied to clipboard');
                }).catch(function(err) {
                    console.error('Could not copy text: ', err);
                });
            }
        });

        // Add command to paste data
        editor.commands.addCommand({
            name: 'paste',
            bindKey: { win: 'Ctrl-V', mac: 'Command-V' },
            exec: function (editor) {
                document.execCommand('paste');
            }
        });

        // Add command to paste data
        editor.commands.addCommand({
            name: 'cut',
            bindKey: { win: 'Ctrl-X', mac: 'Command-X' },
            exec: function (editor) {
                document.execCommand('cut');
            }
        });

        // Add formatter function
        editor.commands.addCommand({
            name: 'format',
            bindKey: { win: 'Ctrl-Shift-F', mac: 'Command-Shift-F' },
            exec: function (editor) {
                ace.require("ace/ext/beautify").beautify(editor.session);
            }
        });

        
        editor.setOptions({
            fontSize: "11pt",
            showLineNumbers: true,
            enableSnippets: true,
            showGutter: true,
            vScrollBarAlwaysVisible: true,
            enableBasicAutocompletion: true,
            enableLiveAutocompletion: true,
        });
        /*
        var customSnippets = `
        snippet log
            console.log('\${1:message}');
        snippet func
            function \${1:name}(\${2:params}) {
                \${3:// body}
            }
        `;

        var snippetManager = ace.require("ace/snippets").snippetManager;
        var id = editor.session.$mode.$id;
        var m = snippetManager.files[id];
        m.scope = editor.session.$mode.$id;
        m.snippetText = customSnippets;
        m.snippet = snippetManager.parseSnippetFile(customSnippets, m.scope);
        snippetManager.register(m.snippet, m.scope);
        */
