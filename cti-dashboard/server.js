const express = require('express');
const cors = require('cors');
const crypto = require('crypto');
const axios = require('axios');
const FormData = require('form-data');

const app = express();
app.use(cors());
app.use(express.json());

async function uploadToIPFS(payload) {
    const buffer = Buffer.from(JSON.stringify(payload));
    const formData = new FormData();
    formData.append('file', buffer, { 
        filename: 'cti_payload.json',
        contentType: 'application/json'
    });

    const response = await axios.post('http://127.0.0.1:5001/api/v0/add', formData, {
        headers: formData.getHeaders(),
        maxBodyLength: Infinity
    });
    return response.data.Hash;
}

app.post('/api/cti/submit', async (req, res) => {
    try {
        const { contributorId, category, rawLog } = req.body;

        const stixPayload = {
            type: "indicator",
            spec_version: "2.1",
            id: `indicator--${crypto.randomUUID()}`,
            created: new Date().toISOString(),
            contributor_id: contributorId || "SOC-Org-Alpha",
            labels: [category || "unauthorized-access"],
            pattern: rawLog || "suspicious-ip-behavior"
        };

        const payloadString = JSON.stringify(stixPayload);
        const sha256Hash = crypto.createHash('sha256').update(payloadString).digest('hex');
        
        // Upload off-chain to IPFS
        const cid = await uploadToIPFS(stixPayload);

        res.json({
            success: true,
            data: {
                id: stixPayload.id,
                cid: cid,
                sha256Hash: sha256Hash,
                contributorId: stixPayload.contributor_id,
                category: stixPayload.labels[0],
                timestamp: stixPayload.created
            }
        });
    } catch (error) {
        console.error("IPFS Upload Error:", error.response ? error.response.data : error.message);
        res.status(500).json({ success: false, error: error.message });
    }
});

app.listen(5000, () => console.log('CTI Ingestion API running on http://localhost:5000'));
