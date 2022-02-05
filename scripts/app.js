// Api key
const API_KEY = 'afa7b9c93ff71996ee531bd54ee3bd1c46064268';
// const password = 'myapiforthis';
// Basic structure 
const basicStructure = 'https://zenquotes.io/api/[mode]/[key]?option1=value&option2=value';
const api_url =`https://zenquotes.io/api/quotes/`;
// Fetch Request
const getAPI = async (url) => {
  await fetch(api_url, {mode: 'no-cors'})
        .then(Response => {
          Response.json().then(response => console.log(response))
        })
        
  
}

// const api_url ="https://zenquotes.io/api/quotes/";
// let myData = 1;
// async function getapi(url)
// {
//   const response = await fetch(url, {mode:'no-cors'});
//   // var data = await response.json();
//   // console.log(data);
//   myData = response;
//   console.log(myData);
// }

const myData = getAPI(api_url);
console.log(myData);


