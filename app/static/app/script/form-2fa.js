// Example starter JavaScript for disabling form submissions if there are invalid fields

const form = document.getElementById('form-register');

//const form2fa = document.getElementById('form-check-2fa');
var boxqrcode = document.getElementById('box-qrcode');
var qrcodeImage = document.getElementById('qrcodeImage');
var submit = document.getElementById('submit');
var getcode = document.getElementById('get_code');
var two_FA_div = document.getElementById('two-FA-div');
let divalert = document.querySelector('.alert');
let alertmessage = document.querySelector('.alert p');
let otpimage = document.getElementById('otpimage'); 
let code_alert = document.getElementById('code-alert'); 
alertmessage.style.color = "#f5324c";
divalert.style.display = "none";

form.addEventListener("submit", async event => {
    event.preventDefault();

  const dataForm = new FormData(form);

  const password = dataForm.get('password');
  const confirmPassword = dataForm.get('confirm');

  if (password !== confirmPassword) {
    divalert.style.display = "block";
    alertmessage.textContent = "The passwords do not match!";
    return;
  }else{
    
    alertmessage.textContent = "";
  }

  //console.log(Array.from(dataForm));
  const baseUrl = window.location.origin;
  
  //alert("base url" +baseUrl);

  try {

    if(localStorage.getItem('otpqrcode')){
      dataForm.append('otpqrcode', localStorage.getItem('otpqrcode'));
      dataForm.append('otpqrcode_uri', localStorage.getItem('otpqrcode_uri'));
      dataForm.append('secret', localStorage.getItem('secret'));

      localStorage.removeItem('secret');
      localStorage.removeItem('otpqrcode_uri');
      localStorage.removeItem('otpqrcode');
      localStorage.clear();
    }
    const res = await fetch(
      //baseUrl + '/auth/register',
      baseUrl + '/users/create',
      {
        method: 'POST',
        body: dataForm
      },
    );

    const resData = await res.json();
    
    console.log(resData);
    
    if(resData){
      if(resData[1] == 400){

        console.log(resData[0].object);      
        divalert.style.display = "block";
        alertmessage.style.color = "#f5324c";
        alertmessage.textContent = resData[0].message;

      }else if(resData[1] == 200){
        
        if(resData[0].status == 2){
          divalert.style.display = "block";
          alertmessage.textContent = resData[0].message;
          alertmessage.style.color = "green";
          boxqrcode.style.display = "block";
          qrcodeImage.src = baseUrl + "/" + resData[0].otpqrcode_uri;
          //qrcodeImage.setAttribute('src', baseUrl + "/" + resData[0].otpqrcode);
          submit.style.display = "none";
          getcode.style.display = "block";
          
          localStorage.setItem('secret', resData[0].secret);
          localStorage.setItem('otpqrcode', resData[0].otpqrcode);
          localStorage.setItem('otpqrcode_uri', resData[0].otpqrcode_uri);
          localStorage.setItem('dataForm', dataForm);

        }else if(resData[0].status == 3){

          divalert.style.display = "none";
          submit.textContent = "Submit";
          boxqrcode.style.display = "none";
          getcode.style.display = "none";
          two_FA_div.style.display = "block";
          localStorage.clear();
          form.reset();
          setTimeout(() => {
            window.open(baseUrl + '/' + resData[0].redirectUrl, '_self');
          });
        }
        

      }
        
    }
  } catch (err) { 
    console.log(resData);
    //alert("Erro ao realizar o cadastro, tente novamente mais tarde " + err.message);
    console.log(err.message);
  }
  
});

getcode.addEventListener("click", async event => {
  submit.style.display = "block";
  submit.textContent = "Submit";
  boxqrcode.style.display = "none";
  getcode.style.display = "none";
  two_FA_div.style.display = "block";

  //alertmessage.textContent = "Please enter the code sent to your email";
  alertmessage.textContent = "Please enter the code provided by your Authenticator app";
  alertmessage.style.color = "green";
  alertmessage.fontsize = "1rem";
})






function captureUserData() {
  const ipAddress = fetch('https://api.ipify.org?format=json')
    .then(response => response.json())
    .then(data => data.ip)
    .catch(error => {
      console.log('Error fetching IP address:', error);
      return null;
    });

  const macAddress = fetch('https://api.macaddress.io/v1?apiKey=YOUR_API_KEY')
    .then(response => response.json())
    .then(data => data.macAddress)
    .catch(error => {
      console.log('Error fetching MAC address:', error);
      return null;
    });

  const deviceType = navigator.userAgent;

  Promise.all([ipAddress, macAddress])
    .then(([ip, mac]) => {
      console.log('IP Address:', ip);
      console.log('MAC Address:', mac);
      console.log('Device Type:', deviceType);
      // Use the captured data as needed
    })
    .catch(error => {
      console.log('Error capturing user data:', error);
    });
}

captureUserData();



function setImage(url) {
  const img = document.getElementById('qrcodeImage');
  img.src = url;
  img.style.color = "red";
}

//setImage('https://th.bing.com/th/id/R.dcf4b6e228aef80dd1a58f4c76f07128?rik=Qj2LybacmBALtA&riu=http%3a%2f%2fpngimg.com%2fuploads%2fqr_code%2fqr_code_PNG25.png&ehk=eKH2pdoegouCUxO1rt6BJXt4avVYywmyOS8biIPp5zc%3d&risl=&pid=ImgRaw&r=0')


