function cacheDeviceInfo() {
    // Get the user agent string
    const userAgent = navigator.userAgent;
  
    // Get the screen width and height
    const screenWidth = window.screen.width;
    const screenHeight = window.screen.height;
  
    // Get the browser's language
    const language = navigator.language;
  
    // Create an object to store the device information
    const deviceInfo = {
      userAgent,
      screenWidth,
      screenHeight,
      language
    };
  
    // Store the device information in local storage
    localStorage.setItem('deviceInfo', JSON.stringify(deviceInfo));
  }
  
  // Call the cacheDeviceInfo function to cache the device information
  cacheDeviceInfo();