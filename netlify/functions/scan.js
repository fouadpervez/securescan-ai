exports.handler = async function(event, context) {
    // 1. THE BOUNCER: Security check
    const allowedOrigin = "https://securescan-ai.netlify.app";
    const requestOrigin = event.headers.origin || event.headers.Origin;

    if (requestOrigin !== allowedOrigin) {
        return { 
            statusCode: 403, 
            body: JSON.stringify({ error: "Access Denied" }) 
        };
    }

    try {
        const API_KEY = process.env.VIRUSTOTAL_API_KEY;
        const url = event.queryStringParameters.url;
        
        // 2. Send the URL to VirusTotal for analysis
        const response = await fetch("https://www.virustotal.com/api/v3/urls", {
            method: "POST",
            headers: {
                "x-apikey": API_KEY,
                "content-type": "application/x-www-form-urlencoded"
            },
            body: new URLSearchParams({ url })
        });

        const initialData = await response.json();
        
        // 3. Get the analysis results using the ID provided
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
        return { 
            statusCode: 500, 
            body: JSON.stringify({ error: "Cloud database unreachable." }) 
        };
    }
};