exports.handler = async function(event, context) {
    const allowedOrigin = "https://securescan-ai.netlify.app";
    const requestOrigin = event.headers.origin || event.headers.Origin;

    if (requestOrigin && requestOrigin !== allowedOrigin) {
        return { statusCode: 403, body: JSON.stringify({ error: "Access Denied" }) };
    }

    try {
        const API_KEY = process.env.VIRUSTOTAL_API_KEY;
        const url = event.queryStringParameters.url;
        
        // 1. Send URL to VirusTotal
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY,
                "content-type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({ url })
        });

        const initialData = await response.json();
        
        // 2. THE FIX: Did VirusTotal reject us? If so, tell the frontend exactly why!
        if (initialData.error) {
            return {
                statusCode: 500,
                headers: { "Access-Control-Allow-Origin": allowedOrigin },
                body: JSON.stringify({ error: `VirusTotal Error: ${initialData.error.message}` })
            };
        }
        
        // 3. If no error, proceed as normal
        const analysisId = initialData.data.id;
        const resultResponse = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
            headers: { "x-apikey": API_KEY }
        });
        
        const data = await resultResponse.json();

        return {
            statusCode: 200,
            headers: { "Access-Control-Allow-Origin": allowedOrigin },
            body: JSON.stringify(data)
        };
        
    } catch (error) {
        // 4. THE FIX: Catch real server crashes and print the exact Javascript error
        return { 
            statusCode: 500, 
            headers: { "Access-Control-Allow-Origin": allowedOrigin },
            body: JSON.stringify({ error: `Code Crash: ${error.message}` }) 
        };
    }
};
