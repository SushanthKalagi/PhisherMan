document.getElementById('submit-btn').addEventListener('click', async () => {
    const userInput = document.getElementById('user-input').value;

    // Perform input validation if needed
    if (userInput.trim() === '') {
        alert('Please enter a valid input.');
        return;
    }

    // Send the input to the model and get the output
    const modelOutput = await sendToModel(userInput);

    // Display the model output
    document.getElementById('model-output').innerText = modelOutput;
});

async function sendToModel(input) {
    let url = input;
    try {
        let response = await fetch('/predict', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({url: url }),
        });

        if (!response.ok) {
            throw new Error('Network response was not ok');
        }

        let data = await response.json();
        return data.result;
    } catch (error) {
        console.error('There was a problem with the fetch operation:', error);
        return 'Error: Unable to get prediction';
    }
}
