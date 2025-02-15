// Set up basic variables for app
const record = document.querySelector(".record");
const fa = document.querySelector('.record i')
const stop = document.querySelector(".stop");
const soundClips = document.querySelector(".sound-clips");
const canvas = document.querySelector(".visualizer");
const mainSection = document.querySelector(".main-controls");

var count = 0;


function myCurrentDateTime(){
  const currentDate = new Date()
 /* const dateFormatOptions = {
    weekday: "long",
    year: "numeric",
    month: "long",
    day: "numeric",
  };
  const newDate = currentDate.toLocaleDateString('en-US', dateFormatOptions);
  */
  const day = currentDate.getDate();
  const month = currentDate.getMonth() + 1; // Months are zero-indexed, so add 1
  const year = currentDate.getFullYear();
  const hours = currentDate.getHours();
  const minutes = currentDate.getMinutes();

// Pad single-digit values with leading zeros
const formattedDate = `${day.toString().padStart(2, '0')}/${month.toString().padStart(2, '0')}/${year} ${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}`;
return formattedDate
}
// Disable stop button while not recording
stop.disabled = true;

// Visualiser setup - create web audio api context and canvas
let audioCtx;
const canvasCtx = canvas.getContext("2d");



document.getElementById('audio').addEventListener('change', function() { 
  var fileName = this.files[0].name;
  document.getElementById('selected-file').textContent = fileName;  
});

document.getElementById('convert-to-text').addEventListener('click',function(){

  document.getElementById('convert-status-1').style.display = "none"
  document.getElementById('convert-status-2').style.display = "block"
  document.getElementById('spinner').style.display = "block"
})

// Main block for doing the audio recording
if (navigator.mediaDevices.getUserMedia) {
  console.log("The mediaDevices.getUserMedia() method is supported.");

  const constraints = { audio: true };
  let chunks = [];

  let onSuccess = function (stream) {
    const mediaRecorder = new MediaRecorder(stream);

    visualize(stream);

    record.onclick = function () {
      mediaRecorder.start();
      console.log(mediaRecorder.state);
      console.log("Recorder started ");
      //record.style.background = "red";
      record.setAttribute('class', 'btn btn-outline-danger')
      record.textContent = "Record started "
      record.appendChild(fa)

      stop.disabled = false;
      record.disabled = true;
      count=count+1
    };

    stop.onclick = function () {
      mediaRecorder.stop();
      console.log(mediaRecorder.state);
      console.log("Recorder stopped ");
      //record.style.background = "";
      //record.style.color = "";
      record.removeAttribute('class', "btn btn-outline-danger")
      record.setAttribute('class', "btn btn-outline-primary")
      record.textContent = "Start recording "
      record.appendChild(fa)

      stop.disabled = true;
      record.disabled = false;
    };

    mediaRecorder.onstop = function (e) {
      console.log("Last data to read (after MediaRecorder.stop() called).");
      let clipName = null

      /* This code display a modal form asking the user to enter a name for the sound clip
      /*clipName = prompt(
        "Enter a name for your sound clip?",
        "my speech voice"
      );*/

    
      const clipContainer = document.createElement("article");
      const clipLabel = document.createElement("p");
      const divAudio = document.createElement('div')
      const audio = document.createElement("audio");
      const audioSource = document.createElement('source')
      const deleteButton = document.createElement("button");
      const divButtons = document.createElement('div')


      clipContainer.classList.add("clip");
      divButtons.setAttribute('class', "btn-group btn-group-lg")
      divButtons.setAttribute('role', "group")
      divButtons.setAttribute('aria-label', "stream buttons")

      divAudio.setAttribute('class',"col-sm-4 col-sm-offset-4")
      audio.setAttribute("controls", "");
      audio.setAttribute('id', "audioPlayer")
      audio.style.width = "100%"
      audio.style.maxWidth = "500px"
      //audio.setAttribute('style', "width: 100%; max-width: 800px;")

      deleteButton.textContent = "Delete record";
      deleteButton.className = "btn btn-outline-danger delete";

      
      if (clipName === null) {
        clipLabel.textContent = `My speech voice_(${count})`;
      } else {
        clipLabel.textContent = clipName;
      }

      audio.appendChild(audioSource)
      divAudio.appendChild(audio)
      //clipContainer.appendChild(audio);
      clipContainer.appendChild(divAudio);
      clipContainer.appendChild(clipLabel);
      divButtons.appendChild(deleteButton)          
      
      const audioFormat = "mp3"
      audio.controls = true;
      //const blob = new Blob(chunks, { type: mediaRecorder.mimeType });
      const mediaRecorderMimeType = `audio/${audioFormat}`; // Replace with your actual MIME type
      const blob = new Blob(chunks, { type: mediaRecorderMimeType });
      chunks = [];
      const audioURL = window.URL.createObjectURL(blob);
      //audio.src = audioURL;
      audioSource.src = audioURL
      console.log("recorder stopped");
      console.log(`Audio URL ${audioURL}`)

      const link = document.createElement('a')
      link.setAttribute('class', 'btn btn-outline-success')
      link.textContent = "Download"
      link.href = URL.createObjectURL(blob)

      const date = new Date()
      
      link.download = `speech-${date.getDate()}_${date.getTime()}.${audioFormat}`
      
      divButtons.appendChild(link)
      clipContainer.appendChild(divButtons);
      soundClips.appendChild(clipContainer);
  
      //soundClips.appendChild(create_the_upload_file_form(audioURL))

      deleteButton.onclick = function (e) {
        e.target.closest(".clip").remove();
      };

      const audioPlayer = document.getElementById("audioPlayer");

      audio.addEventListener("play", () => {
        const currentSrc = audioPlayer.currentSrc;
        // Send 'currentSrc' to the server via an HTTP request.
        
        console.log(currentSrc)
        //sendAudioFile(currentSrc)
      });

      clipLabel.onclick = function () {
        const existingName = clipLabel.textContent;
        const newClipName = prompt("Enter a new name for your sound clip?");
        if (newClipName === null) {
          clipLabel.textContent = existingName;
        } else {
          clipLabel.textContent = newClipName;
        }
      };

    };

    mediaRecorder.ondataavailable = function (e) {
      chunks.push(e.data);
    };

  };

  let onError = function (err) {
    console.log("The following error occured: " + err);
  };

  navigator.mediaDevices.getUserMedia(constraints).then(onSuccess, onError);
} else {
  console.log("MediaDevices.getUserMedia() not supported on your browser!");
}


/**
 * 
 * @param {*} stream 
 */

let sendAudioFile = (blob) => {

  
  //const audioURL = URL.createObjectURL(blob)

  const baseUrl = window.location.origin;

  const formData = new FormData();
  formData.append('audio', blob); // 'audio-file' is the field name

  return fetch(`${baseUrl}/ai/speech`, {
    method: 'POST',
    body: formData
  }).then(response => response.json())
  .then(data => {
    // Handle the response from the server
    console.log('File uploaded successfully!', data);
  })
  .catch((e)=> console.error('Error uploading file:', e));
};



let create_the_upload_file_form = (file_url) =>{
  // Creating the html elements
  var form = document.createElement('form')
  var div = document.createElement('div')
  var button = document.createElement('button')
  var label = document.createElement('label')
  var input = document.createElement('input')

  // Setting properties to the elements 
  form.setAttribute('method', "POST")
  form.setAttribute('enctype', "multipart/form-data")
  div.setAttribute('class', "form-group")
  input.setAttribute('class', "form-control-file")
  input.setAttribute('type', "file")
  input.setAttribute('id', "audio") 
  input.setAttribute('name', "audio")
  //input.setAttribute('accept', "audio/*")
  input.setAttribute('maxlength', "5000000")
  input.setAttribute('value', file_url)

  label.setAttribute('for', "audio")
  label.textContent = "Choose an audio file:"
  button.setAttribute('class', "btn btn-primary")
  button.setAttribute('type', "submit")
  button.textContent = "Upload"

  div.appendChild(label)
  div.appendChild(input)
  form.appendChild(div)
  form.appendChild(button)
  return form
}


function visualize(stream) {
  if (!audioCtx) {
    audioCtx = new AudioContext();
  }

  const source = audioCtx.createMediaStreamSource(stream);

  const analyser = audioCtx.createAnalyser();
  analyser.fftSize = 2048;
  const bufferLength = analyser.frequencyBinCount;
  const dataArray = new Uint8Array(bufferLength);

  source.connect(analyser);

  draw();

  function draw() {
    const WIDTH = canvas.width;
    const HEIGHT = canvas.height;

    requestAnimationFrame(draw);

    analyser.getByteTimeDomainData(dataArray);

    canvasCtx.fillStyle = "rgb(255, 255, 255)";
    canvasCtx.fillRect(0, 0, WIDTH, HEIGHT);

    canvasCtx.lineWidth = 2;
    canvasCtx.strokeStyle = "rgb(0, 0, 0)";

    canvasCtx.beginPath();

    let sliceWidth = (WIDTH * 1.0) / bufferLength;
    let x = 0;

    for (let i = 0; i < bufferLength; i++) {
      let v = dataArray[i] / 128.0;
      let y = (v * HEIGHT) / 2;

      if (i === 0) {
        canvasCtx.moveTo(x, y);
      } else {
        canvasCtx.lineTo(x, y);
      }

      x += sliceWidth;
    }

    canvasCtx.lineTo(canvas.width, canvas.height / 2);
    canvasCtx.stroke();
  }
}

window.onresize = function () {
  canvas.width = mainSection.offsetWidth;
};

window.onresize();