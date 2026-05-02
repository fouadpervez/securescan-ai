exports.handler = async function(event, context) {
    // 1. THE BOUNCER: Security check
    const allowedOrigin = "https://secure-scan-ai.netlify.app"; // REPLACE THIS!
    const requestOrigin = event.headers.origin || event.headers.Origin;

    if (requestOrigin && requestOrigin !== allowedOrigin) {
        return { statusCode: 403, body: JSON.stringify({ error: "Access Denied" }) };
    }

    if (event.httpMethod !== "POST") {
        return { statusCode: 405, body: JSON.stringify({ error: "Method Not Allowed" }) };
    }

    try {
        const API_KEY = process.env.VIRUSTOTAL_API_KEY;
        
        // 2. Read the file string sent from the browser
        const body = JSON.parse(event.body);
        const fileName = body.fileName;
        
        // 3. Convert the text string back into a raw file buffer (held strictly in RAM)
        const fileBuffer = Buffer.from(body.fileBase64, 'base64');
        const fileBlob = new Blob([fileBuffer]);

        // 4. Package it up the exact way VirusTotal demands
        const formData = new FormData();
        formData.append("file", fileBlob, fileName);

        // 5. Send it to the Cloud Bomb Squad
        const response = await fetch("https://www.virustotal.com/api/v3/files", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY,
                "accept": "application/json"
            },
            body: formData
        });

        const data = await response.json();

        return {
            statusCode: 200,
            headers: { "Access-Control-Allow-Origin": allowedOrigin },
            body: JSON.stringify(data)
        };
    } catch (error) {
        return { statusCode: 500, body: JSON.stringify({ error: "File too large or database unreachable." }) };
    }
};
