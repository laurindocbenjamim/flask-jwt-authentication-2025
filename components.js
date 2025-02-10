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


class AuthUser {
    constructor() {
        this.baseURL = window.location.origin;
        this.serverEndpoint = 'http://localhost:5000';
    }
    async login(options) {
        const response = await fetch(`${this.serverEndpoint}/login-w-cookies`, options);
        return response.json();
    }

    async makeRequest(options, endpoint) {
        const response = await fetch(`${this.serverEndpoint}/${endpoint}`, options);
        return response.json();
    }

    async logout(options) {
        const response = fetch(`${this.serverEndpoint}/logout_with_cookies`, options);
        return response.json();
    }

    async getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
    }

    async getOptions2(method, formData) {
        if(!method || !formData){ return null;};

        const headers = {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': await this.getCookie('csrf_access_token'),
        };
        const options = {
            method: method,
            credentials: 'include',// method === 'GET' ? 'same-origin' : 'include',
            headers: headers,
        };
        if (method !== 'GET') {
            options.body = formData;
        }
        console.log(options)
        return options;
    };

    async getOptions(method, formData){
        const csrfToken = await this.getCookie('csrf_access_token');
        const headers = {
            'Content-Type': 'application/json',
            'X-CSRF-TOKEN': csrfToken,
        };
        return method === 'GET' ? {
            method: method,
            credentials: 'same-origin',
            headers: headers,
        } : {
            method: method,
            credentials: 'include',
            body: formData,
            headers: headers,
        };
    };
    async makeRequestWithJWT() {
        const options = {
            method: 'post',
            credentials: 'same-origin',
            headers: {
                'X-CSRF-TOKEN': await this.getCookie('csrf_access_token'),
            },
        };
        const response = await fetch(`${this.serverEndpoint}/protected`, options);
        const result = await response.json();
        return result;
    };

    async handlingErrors(response){
        if (!response.ok) {
            const errorMessages = {
                400: 'Bad Request',
                401: 'Unauthorized',
                415: 'Unsupported Media Type',
                422: 'Unprocessable Entity',
                423: 'Locked',
                500: 'Internal Server Error'
            };
            console.log(response)
            return errorMessages[response.status] || `HTTP error! status: ${response}`;
        }
    };
};

