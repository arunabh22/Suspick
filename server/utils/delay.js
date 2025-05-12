function getRandomDelay(min = 1000, max = 5000) {
    return Math.floor(Math.random() * (max - min + 1)) + min;
  }
  
  async function waitBeforeRequest() {
    const delay = getRandomDelay(1000, 6000);
    console.log(`Waiting for ${delay}ms before making the request...`);
    await new Promise(resolve => setTimeout(resolve, delay));  // Wait for the delay
  }
  
  module.exports = { waitBeforeRequest };
  