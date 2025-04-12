// Example starter JavaScript for disabling form submissions if there are invalid fields

const form = document.getElementById('form-register');

let register = (form) => {

  form.addEventListener("submit", async event => {
    event.preventDefault();

  const data = new FormData(form);

  console.log(Array.from(data));

  try {
    const res = await fetch(
      'http://localhost:5000/auth/register',
      {
        method: 'POST',
        body: data
      },
    );

    const resData = await res.json();

    const baseUrl = window.location.origin;
    alert("base url" +baseUrl);
    console.log(resData[0].object);
    if(resData){
      console.log(resData[0].object);
      //alert(resData[0].object)
      //window.open('http://localhost:5000/auth/login', '_self');
    }
  } catch (err) { 
    //alert("Erro ao realizar o cadastro, tente novamente mais tarde " + err.message);
    console.log(err.message);
  }
  
});


}

register(form);