class AuthJWTNoCookies{
    constructor(){
        this.baseURL = window.location.origin;
        this.serverEndpoint = 'http://localhost:5000';
    }

    async getOptionJWT(method, body){
        // getting the jwt token 
        const token = localStorage.getItem('jwtToken')? localStorage.getItem('jwtToken') : null;
        
        // Create headers
        const headers = token? {
            'Content-Type': 'application/json', 'Authorization': `Bearer ${token}`,
        } : {'Content-Type': 'application/json'};

        return method==='POST'? {
            methods: method,
            body: body,
            credentials: 'same-origin',
            headers: headers,
        } : {
            methods: method, credentials: 'same-origin', headers: headers,
        };

    };

    async login(endpoint, formData){ 
        const route = `${this.serverEndpoint}/${endpoint}`;
        const options = this.getOptionJWT('POST', formData)
        console.log("Options...")
        console.log(options)
        const response = await fetch(route, 
        options)
        .then(response => response.json());
        console.log(response.json())
        return response.json();
    }

    async logout(){
        localStorage.removeItem('jwtToken')
        window.location.href = this.baseURL + '/login_without_cookies.html'
    }

    async callProtectedRoute(endpoint, formData){
        if(formData){
            const response = await fetch(this.serverEndpoint + '/'+endpoint, 
        this.getOptionJWT('GET', formData))
        .then(response => response.json())
        return ;
        }

        const response = await fetch(this.serverEndpoint + '/'+endpoint, 
        this.getOptionJWT('GET', formData))
        .then(response => response.json())
        return response.json();
    }
};

//alert("Ola")