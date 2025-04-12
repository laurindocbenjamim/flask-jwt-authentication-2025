
class Subscriber{

    constructor(id, email) {
        this.id = id;
        this.email = email;
    }

    getId(){
        return this.id
    }
    getEmail(){
        return this.email
    }

    validateFields(id, email){
        return true
    }

    
    
    
}

function sanitizeInput(input){
    // Remove any script tags
    let sanitizedInput = input.replace(/<script[^>]*?>.*?<\/script>/gi, '');
    // Encode special characters
    sanitizedInput = sanitizedInput.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return sanitizedInput;
}

function cleanForm(){
    var inputs = document.getElementById('subscriberForm').getElementsByTagName('input');
    // Clear all input type="text" fields
    for (var i = 0; i < inputs.length; i++) {
        if (inputs[i].type.toLowerCase() == 'text' || inputs[i].type.toLowerCase() == 'email') {
            inputs[i].value = '';
        }
        
    }
}


document.getElementById('subscriberForm').addEventListener('submit', async e => {
    e.preventDefault();   

    const baseUrl = window.location.origin;
    const dataForm = new FormData();

    //var alert_message = document.querySelectorAll('.form-message')
    var alertmessage = document.querySelector('.form-message p')

    var email = sanitizeInput(document.getElementById("subscriber").value);
    
    if (email.length > 100){
        return
    }
    var obj = new Subscriber(1, email);
    dataForm.append('email', obj.email)
    //

    try {
        const res = await fetch(
            `${baseUrl}/subscriber/subscribe`,
            {
              method: 'POST',
              body: dataForm
            },
          );
      
        const resData = await res.json();
        
        console.log(resData);
        
        if(resData){
            if(resData[1] == 400){
                
                /*alertmessage.forEach(element => {
                    var p = document.createElement('p');
                    element.classList.add(resData[0].category)
                    p.style.color = resData[0].category=='error'? '#c8233e' : '#0986fa'                    
                    p.textContent = resData[0].message     
                    var child = alertmessage.querySelector('p')
                    if(child){
                        element.removeChild(p)
                    }           
                    element.appendChild(p)
                     
                });*/
                //alertmessage.style.color = resData[0].category=='error'? '#c8233e' : '#0986fa'//"#f5324c";
                alertmessage.classList.add(resData[0].category)
                alertmessage.textContent = ''
                alertmessage.textContent = resData[0].message;
            }else{
                //
                cleanForm()
                /*alertmessage.forEach(element => {
                    var p = document.createElement('p');
                    element.classList.add(resData[0].category)
                    //p.style.color = '#25d45a'
                    p.style.color = resData[0].category=='success'? '#25d45a' : '#0986fa'
                    p.textContent = resData[0].message
                    
                    if(resData[0].category=='success'){
                        resData[0].category
                    }
                    var child = alertmessage.querySelector('p')
                    if(child){
                        element.removeChild(p)
                    }           
                    element.appendChild(p)
                });*/
                //alertmessage.style.color = resData[0].category=='success'? '#25d45a' : '#0986fa'//"#f5324c";
                alertmessage.classList.add(resData[0].category)
                alertmessage.textContent = ''
                alertmessage.textContent = resData[0].message;
            }
        }
    } catch (err) {
        console.log(err.message);
    }

    

});




/*document.addEventListener('DOMContentLoaded', (ev) => {
    document.getElementById('subscriberForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        var email = document.getElementById("subscriber").value;
        var obj = new Subscriber(1, email);
        //

        const res = await fetch(
            //baseUrl + '/auth/register',
            baseUrl + '/register/user/create',
            {
              method: 'POST',
              body: dataForm
            },
          );
      
        const resData = await res.json();

    })
})*/