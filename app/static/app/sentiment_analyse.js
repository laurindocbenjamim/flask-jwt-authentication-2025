
class Sentiment{

    constructor(id, comment) {
        this.id = id;
        this.comment = comment;
    }

   

    
    
    
}

function sanitizeInput(input){
    // Remove any script tags
    let sanitizedInput = input.replace(/<script[^>]*?>.*?<\/script>/gi, '');
    // Encode special characters
    sanitizedInput = sanitizedInput.replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return sanitizedInput;
}

function sanitizeInput_2(str) {
    var div = document.createElement('div');
    div.appendChild(document.createTextNode(str));
    return div.innerHTML;
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


document.getElementById('sentimentAnalyserForm').addEventListener('submit', async e => {
    e.preventDefault();   
    
    const baseUrl = window.location.origin;
    const headers = new Headers();
    headers.append("X-CSRF-Token", csrfToken);
    headers.append("Authorization", ` Bearer ${csrfToken}`);
    const dataForm = new FormData();
    //const data = [{'name': 'laurindo', 'age': 12},{'name': 'mauro', 'age': 111}]    

    var token = document.querySelector('meta[name="token"]').getAttribute('content')

    var alertmessage = document.querySelector('.form-message p')
    var response = document.getElementById('response')
    var comment = sanitizeInput(document.getElementById('comment').value);
    
    if (comment.length > 255){
        return
    }
    var obj = new Sentiment(1, comment);
    dataForm.append('comment', obj.comment)
    //

    try {
        const res = await fetch(
            `${baseUrl}/data-science/project/emotion-detector/${ token }`,
            {
              method: 'POST',
              headers: headers,
              body: dataForm
            },
          );
      
        const resData = await res.json();
        
        console.log(resData);
        
        if(resData){
            if(resData[1] == 400){
                
                alertmessage.classList.add(resData[0].category)
                alertmessage.textContent = ''
                alertmessage.textContent = resData[0].message;
            }else if(resData[1] == 200){
                //
                cleanForm()
                const emotions = resData[0].emotions
                emotions.forEach((element) => {
                    var ol = document.createElement('ol')
                    ol.className = "list-group list-group-numbered"
                    var li = document.createElement('li')
                    li.className = "list-group-item d-flex justify-content-between align-items-start"
                    
                    var divChild = document.createElement('div')
                    divChild.className = "fw-bold"
                    divChild.textContent = "Anger"

                    var divParent = document.createElement('div')
                    divParent.className = "ms-2 me-auto"
                    divParent.textContent = 'The anger is a bad feeling'                    

                    var span = document.createElement('span')
                    span.className = "badge text-bg-primary rounded-pill"
                    span.textContent = `${element.anger}`
                    
                    divParent.appendChild(divChild)   
                    li.appendChild(divParent)
                    li.appendChild(span)
                    ol.appendChild(li)

                    /**
                     * 
                     */

                    var ol_2 = document.createElement('ol')
                    ol_2.className = "list-group list-group-numbered"
                    var li_2 = document.createElement('li')
                    li_2.className = "list-group-item d-flex justify-content-between align-items-start"

                    var divChild_2 = document.createElement('div')
                    divChild_2.className = "fw-bold"
                    divChild_2.textContent = "DISGUST"

                    var divParent_2 = document.createElement('div')
                    divParent_2.className = "ms-2 me-auto"
                    divParent_2.textContent = 'The DISGUST is a bad feeling'                    

                    var span_2 = document.createElement('span')
                    span_2.className = "badge text-bg-primary rounded-pill"
                    span_2.textContent = `${element.disgust}`

                    divParent_2.appendChild(divChild_2)   
                    li_2.appendChild(divParent_2)
                    li_2.appendChild(span_2)
                    ol_2.appendChild(li_2)


                    var p = document.createElement('p')
                    p.textContent = `ANGER: ${element.anger}
                    DISGUST [${element.disgust}] 
                    FEAR: ${element.fear}
                    JOY: ${element.joy}
                    SADNESS: ${element.sadness}
                    Dominant Emotion: ${element.max_emotion} with score ${element.max_score} `                  
                    response.appendChild(ol)
                    response.appendChild(ol_2)
                })
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