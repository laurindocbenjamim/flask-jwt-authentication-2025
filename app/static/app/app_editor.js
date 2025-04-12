document.addEventListener("DOMContentLoaded", (e) => {
  e.preventDefault();

  const csrfToken = document
    .querySelector('meta[name="csrf-token"]')
    .getAttribute("content");
  const inputTag = "input";
  let inputField = document.createElement(inputTag);

  function update_the_page() {
    // Get the query string from the current URL
    const queryString = window.location.search;

    // Create a URLSearchParams object
    const urlParams = new URLSearchParams(queryString);

    // Get the value of a specific parameter
    const fileName = urlParams.get("fileName"); // "shirt"
    const courseID = urlParams.get("courseID"); // "shirt"
    const description = urlParams.get("description"); // "shirt"
    const user_token = urlParams.get("user_token"); // "shirt"

    window.location.href = `${window.location.origin}/course/learn/laubcode/root/load-scripts?
    fileName=${fileName}&&courseID=${courseID}&&description=${description}&&user_token=${user_token}`;
  }
  function createInputFileName(e) {
    e.preventDefault();

    inputField.setAttribute("type", "text");
    inputField.setAttribute("id", "newFile");
    inputField.style.borderRadius = "4px";
    inputField.style.backgroundColor = "#fff";
    inputField.style.fontSize = ".8rem";
    inputField.style.color = "#000";
    inputField.style.width = "100px";
    //inputField.value = String(text).trim();
    inputField.focus();

    const newFilenameInputfield = document.getElementById(
      "new-filename-inputfield"
    );

    // Check if the div contains the specified tag
    const containsTag = newFilenameInputfield.querySelector(inputTag) !== null;

    if (containsTag) {
      newFilenameInputfield.style.display = "none";
      newFilenameInputfield.removeChild(inputField);
    } else {
      newFilenameInputfield.appendChild(inputField);
      newFilenameInputfield.style.display = "block";
    }
  }

  function createNewFile(element, filename) {
    const progressBar = document.getElementById("myBar");
    progressBar.style.width = "0%";
    progressBar.setAttribute("aria-valuenow", 0);

    const endpoint = `${window.location.origin}/course/learn/laubcode/root/create-file`;

    const headers = new Headers();
    headers.append("X-CSRF-Token", csrfToken);
    headers.append("Authorization", ` Bearer ${csrfToken}`);
    const formData = new FormData();
    formData.append("fileDirectory", "root");
    formData.append("filename", String(filename));
    //formData.append("course_id", courseID)
    //formData.append("lesson", lesson)

    consoleOutput.innerHTML = "#laubcode\\editor\\main$: \n";

    fetch(endpoint, {
      method: "POST",
      headers: headers, // Add the CSRF token to the headers
      body: formData, //JSON.stringify({"comment": comment}),
    })
      .then((response) => {
        const reader = response.body.getReader();
        const contentLength = +response.headers.get("Content-Length");
        let receivedLength = 0;

        return new ReadableStream({
          start(controller) {
            function push() {
              reader.read().then(({ done, value }) => {
                if (done) {
                  controller.close();
                  progressBar.style.width = "100%";
                  progressBar.setAttribute("aria-valuenow", 100);
                  return;
                }
                receivedLength += value.length;
                const progress = (receivedLength / contentLength) * 100;
                progressBar.style.backgroundColor = "#3cd644";
                progressBar.style.width = progress + "%";
                progressBar.style.color = "#fff";
                progressBar.textContent = progress + "%";
                progressBar.setAttribute("aria-valuenow", progress);
                controller.enqueue(value);
                push();
              });
            }
            push();
          },
        });
      })
      .then((stream) => new Response(stream))
      .then((response) => {
        if (!response.ok) {
          throw new Error("Network response was not ok");
        }
        return response.json();
      })
      .then((data) => {
        console.log(data);
        element.style.display = "none";      

        if (data[1] === 400) {
          consoleOutput.innerHTML += `<pre class="text-danger">${String(
            data[0].message
          )}</pre>`;
        }else{
          if(data[0].status){ 
            update_the_page()
            //location.reload(true)    
          }            
        }
      })
      .catch((err) => {
        console.log("Error: " + err);        
        consoleOutput.innerHTML += `<pre class="text-danger">Failed to create file: \n${String(
          err
        )}</pre>`;

        progressBar.style.backgroundColor = "red";
      });
  }

  //const createNewFileBTN = document.getElementById('create-new-file')

  document
    .getElementById("create-new-file")
    .addEventListener("click", (e) => createInputFileName(e));

  try {
    // Add event listener to the input field to handle Enter key
    inputField.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && String(this.value) !== "") {
        createNewFile(this, this.value);
      }
    });
  } catch (err) {
    console.log(err);
  }

  document.addEventListener("click", function (event) {
    const button = document.getElementById("newFile");
    //if (!button.contains(event.target)) {
      //button.style.display = 'none'
      //alert('Mouse clicked outside the button!');
    //}
  });
});
