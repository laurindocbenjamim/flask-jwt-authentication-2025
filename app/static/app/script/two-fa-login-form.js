// Example starter JavaScript for disabling form submissions if there are invalid fields

const form = document.getElementById('two-fa-login-form');

//const form2fa = document.getElementById('form-check-2fa');


form.addEventListener("submit", async event => {
    event.preventDefault();
  alert("submit");
  const dataForm = new FormData(form);

  const password = dataForm.get('password');
  const username = dataForm.get('username');

  if (username == '' || password == '') {
    divalert.style.display = "block";
    
    return;
  }else{
    
    alertmessage.textContent = "";
  }

  //console.log(Array.from(dataForm));
  const baseUrl = window.location.origin;
  
  //alert("base url" +baseUrl);

  try {

 
    const res = await fetch(
      baseUrl + '/auth/2fapp/login',
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
       

      }else if(resData[1] == 200){
        
        if(resData[0].status == 1){
 

        }else if(resData[0].status == 2){

         
          setTimeout(() => {
            //window.open(baseUrl + '/' + resData[0].redirectUrl, '_self');
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


