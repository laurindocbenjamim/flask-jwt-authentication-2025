// Set up basic variables for app

let convert_to_text = document.getElementById('convert-to-text')

convert_to_text.addEventListener('click',function(){
  convert_to_text.style.fontSize = '14px'
  convert_to_text.style.display = 'flex'
  convert_to_text.removeAttribute('class', 'btn-lg') 
  convert_to_text.setAttribute('class', 'btn btn-secondary')
  
  document.getElementById('convert-status-1').style.display = "none"
  document.getElementById('convert-status-2').style.display = "block"
  document.getElementById('spinner').style.display = "block"
})

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


window.onresize = function () {
  canvas.width = mainSection.offsetWidth;
};

window.onresize();