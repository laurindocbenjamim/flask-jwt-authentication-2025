
const editor = ace.edit("editor");
// Resizer logic
const resizer = document.getElementById("resizer");
const editorContainer = document.getElementById("editor-container");
let isResizing = false;

resizer.addEventListener('mousedown', function(e) {
    isResizing = true;
    document.body.style.cursor = 'ew-resize';
  });

  document.addEventListener('mousemove', function(e) {
    if (!isResizing) return;

    const newWidth = e.clientX - editorContainer.getBoundingClientRect().right;
    editorContainer.style.width = newWidth + 'px';
    editor.resize();
  });