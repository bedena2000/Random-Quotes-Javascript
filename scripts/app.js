// Try to get random quote

let myResult1;

// Api URL
const apiURL = 'https://goquotes-api.herokuapp.com/api/v1/random?count=1';

const getQuote = () => {
	const promiseOfQuote = fetch(apiURL);
	return promiseOfQuote.then(data => data.json());
};

// Get Click Button

const btn = document.querySelector(".btn");
btn.addEventListener("click", (event) => {
	let myQuote;
	const dataOfQuote = getQuote();
	dataOfQuote.then(data => {
		const quotesText = document.querySelector(".quotes-text");
		const authorText = document.querySelector(".author");
		authorText.textContent = data.quotes[0].author;
		quotesText.textContent = data.quotes[0].text;
		console.log(data);
	})
});