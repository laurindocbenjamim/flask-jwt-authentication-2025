

document.addEventListener('DOMContentLoaded', (e)=>{
    e.preventDefault()

    const sidebar = document.getElementById('sidebar')
    
    sidebar.addEventListener('click', (e)=>{})

    var topic = 'Introduction to python programming language'
    var contentDescription = `Try out this interactive JavaScript demo:`;
    var iframeComponent = null;

    function getContent(address, topicCont){
        topic = topicCont
       document.getElementById('javascript-demo').innerHTML = `
    <h3 class="mt-5">${topic}</h3>
        <p>${ contentDescription }</p>
    <section class="video-section container fade-in">
            <div class="video-container">
                <iframe class="iframe-video" src="https://www.youtube.com/embed/FuXJln-UtNQ" title="TechInnovate: Revolutionizing Business with Data Science" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture" allowfullscreen></iframe>
            </div>
        </section>
    `

       /* await fetch(`${window.location.origin}/course/learn/python-basic/get/1`)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then((data)=>{
            console.log(data)
        }).catch((err)=> console.log(err))
        */
    }
})