
  function sanitizeInput(input) {
    // Remove any script tags
    let sanitizedInput = input.replace(/<script[^>]*?>.*?<\/script>/gi, "");
    // Encode special characters
    sanitizedInput = sanitizedInput.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return sanitizedInput;
  }
  
  function sanitizeInput_2(str) {
    var div = document.createElement("div");
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
  }
  
  function filterString(input) {
    // This regular expression matches words with or without accentuation and punctuation
    var regex = /[A-Za-zÀ-ÖØ-öø-ÿ.,;?!'"\s]+/g;
    var result = input.match(regex);
    return result ? result.join('') : '';
  }
  
  function cleanForm() {
    var inputs = document
      .getElementById("subscriberForm")
      .getElementsByTagName("input");
    // Clear all input type="text" fields
    for (var i = 0; i < inputs.length; i++) {
      if (
        inputs[i].type.toLowerCase() == "text" ||
        inputs[i].type.toLowerCase() == "email"
      ) {
        inputs[i].value = "";
      }
    }
  }
  
  var navCharts = document.getElementById('nav-charts')
  
  document
    .getElementById("audio-book-fom")
    .addEventListener("submit", async (e) => {
        e.preventDefault()

        const baseUrl = window.location.origin;
        const dataForm = new FormData();
      
       
        dataForm.append("audio", "play");
        //
       
          const res = await fetch(
            `${baseUrl}/ai/audio-book`,
            {
              method: "POST",
              body: dataForm,
            }
          );
    
          const resData = await res.json();
    
          console.log(resData);

    });



    /**
     * 
     *  Activate microphone
     */

    /*navigator.mediaDevices.getUserMedia({ audio: true })
    .then(stream => {
      const mediaRecorder = new MediaRecorder(stream);
      mediaRecorder.start();
  
      const audioChunks = [];
      mediaRecorder.addEventListener("dataavailable", event => {
        audioChunks.push(event.data);
      });
  
      mediaRecorder.addEventListener("stop", () => {
        const audioBlob = new Blob(audioChunks);
        const audioUrl = URL.createObjectURL(audioBlob);
        const audio = new Audio(audioUrl);
        audio.play();
      });
  
      setTimeout(() => {
        mediaRecorder.stop();
      }, 3000);
    });*/
  



 
  /**
   *  This method is used to remove existent canvas child element from
   * the chart container
   */
  function removeCanvasChildElement(container) {
    try {
      var old = document.querySelector("canvas");
      if (old) {
        container.removeChild(old);
      } else {
        console.log(old);
      }
    } catch (error) {
      console.log(error);
    }
  }
