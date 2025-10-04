document.getElementById('cvss-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const formData = new FormData(e.target);
    const resultDiv = document.getElementById('result');

    try {
        const response = await fetch('/calculate', {
            method: 'POST',
            body: formData,
        });
        const data = await response.json();

        if (response.ok) {
            resultDiv.innerHTML = `<p class="text-green-600 font-bold">CVSS v3.1 Base Score: ${data.score}</p>`;
        } else {
            resultDiv.innerHTML = `<p class="text-red-600">${data.error}</p>`;
        }
    } catch (error) {
        resultDiv.innerHTML = `<p class="text-red-600">An error occurred: ${error.message}</p>`;
    }
});