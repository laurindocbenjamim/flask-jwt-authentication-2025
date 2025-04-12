

class Country{

    constructor(){

    }
}

function populate_countries(){
    
    const baseUrl = window.location.origin;

    let select = document.getElementById('country')

    fetch(baseUrl + '/ws/api/countries')
    .then(response => response.json())
    .then(data => {
        if(data){
            if(data.OBJECTS && data.OBJECTS.length > 0){
                localStorage.setItem('countries', JSON.stringify(data.OBJECTS))
                data.OBJECTS.forEach(element => {
                    var option = document.createElement('option')
                    option.text = element.Country
                    option.value = element.Country
                    select.add(option)
                });
            }
        }
    })
    .catch(error => console.error('Error:', error));
    
    
}

populate_countries()

document.getElementById('country').addEventListener('change', async (e) =>{
    e.preventDefault()
    const baseUrl = window.location.origin;

    if(e.target.value){
        const country = e.target.value            
        filter_country_2(country)
    }
        
    
})



function filter_country_2(country){
    var country_code = document.getElementById('country_code')
    const countriesL = JSON.parse(localStorage.getItem('countries'))
    
    if(countriesL){
        if(countriesL.length > 0){ 
            
            var element = countriesL.filter(obj => obj.Country.toLowerCase() == country.toLowerCase())
            
                if(element && element.length > 0){                    
                    
                    country_code.value = `+${element[0].CountryCode}`
                }
        }
    }            
        
}

function filter_country_1(e, baseUrl){
    if(e.target.value){
        const country = e.target.value
        
        console.log()
        let countries = fetch(//await fetch(
            baseUrl + '/ws/api/countries',
            {
                method: 'GET'
            },
        )
        
        const resData = countries.json();//await countries.json();
        if(resData){
            
            if(resData.OBJECTS && resData.OBJECTS.length > 0){
                /*for(var i=0;i < resData.OBJECTS.length;i++){
                   if(resData.OBJECTS[i].Country.toLowerCase() == country.toLowerCase()){
                    let country_code = document.getElementById('country_code')
                    country_code.value = `+${resData.OBJECTS[i].CountryCode}`
                   }
                }*/
               //var filteredKeys = Object.keys(obj).filter(key => obj[key] === "value2");
               // This line of code is relativelly more faster then the above one
               /*var element = resData.OBJECTS.filter(obj => obj.Country.toLowerCase() == country.toLowerCase())
               
                if(element && element.length > 0){
                    let country_code = document.getElementById('country_code')
                    country_code.value = `+${element[0].CountryCode}`
                }*/
            }
        }
        
        console.log(resData);

    }
}


function first_way(){
    fetch('https://api.example.com/data')
    .then(response => response.json())
    .then(data => console.log(data))
    .catch(error => console.error('Error:', error));
}