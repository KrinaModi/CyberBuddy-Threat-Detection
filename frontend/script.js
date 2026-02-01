function scanThreat() {
    const input = document.getElementById("inputText").value;

    fetch("/scan", {
        method: "POST",
        headers: {
            "Content-Type": "application/json"
        },
        body: JSON.stringify({ input: input })
    })
    .then(res => res.json())
    .then(data => {
        const box = document.getElementById("resultBox");

        box.innerHTML = `
            <h3>Status: ${data.result}</h3>
            <p>Risk Score: ${data.risk}%</p>
        `;

        box.className = data.result === "PHISHING"
            ? "danger"
            : "safe";
    });
}
