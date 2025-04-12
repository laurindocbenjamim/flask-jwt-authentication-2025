

async function fetch01(endpoint,fetchHeaders, formData, fetchMethod){

    try {
        var response = null
        if(fetchMethod ==="POST"){
            response = await fetch(endpoint, {
                method: `${fetchMethod}`,
                headers: fetchHeaders,
                body: formData
            });
        }else if(fetchMethod ==="GET"){
            response = await fetch(endpoint, {
                method: `${fetchMethod}`,
                headers: fetchHeaders
            });
        }
        
        const data = await response.json();
        
        return data
    } catch (error) {
        console.error('Error fetching suggestion:', error);
        return false
    }
}

function chatBoxTest(val){
    return `Welcome Mr. ${val}`
}
