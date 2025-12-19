// Main application JavaScript for Digital Forensic Evidence Management System (Simplified)

// Login function with role-based authentication (MySQL)
async function login() {
    const userId = document.getElementById("userid").value.trim();
    const password = document.getElementById("password").value;
    const role = document.getElementById("role").value;

    // Clear previous errors
    document.getElementById("error").innerText = "";

    // Validation
    if (!userId || !password || !role) {
        document.getElementById("error").innerText = "Please fill all fields";
        return;
    }

    // Show loading state
    const loginButton = document.querySelector('button[onclick="login()"]');
    const originalText = loginButton.textContent;
    loginButton.disabled = true;
    loginButton.textContent = "Logging in...";

    try {
        // Verify credentials from MySQL database
        const verification = await UserManagement.verifyUser(userId, password, role);
        const loginSuccess = verification.valid === true;
        
        // Store login attempt in MySQL database via API
        Database.insertLoginLog(userId, role, loginSuccess).catch(err => {
            console.error('Failed to log login attempt:', err);
            // Continue even if logging fails
        });
        
        if (loginSuccess) {
            // Store user session
            Session.setCurrentUser({
                userId: userId,
                role: role,
                loginTime: new Date().toISOString()
            });

            // Redirect based on role
            redirectToDashboard(role);
        } else {
            document.getElementById("error").innerText = verification.error || "Invalid credentials or role mismatch";
        }
    } catch (error) {
        console.error('Login error:', error);
        document.getElementById("error").innerText = "Login failed. Please check your connection and try again.";
    } finally {
        // Restore button state
        loginButton.disabled = false;
        loginButton.textContent = originalText;
    }
}

// Redirect to appropriate dashboard based on role
function redirectToDashboard(role) {
    switch(role) {
        case CONFIG.ROLES.INVESTIGATOR:
            window.location.href = "investigator-dashboard.html";
            break;
        case CONFIG.ROLES.ANALYST:
            window.location.href = "analyst-dashboard.html";
            break;
        case CONFIG.ROLES.COURT:
            window.location.href = "court-dashboard.html";
            break;
        case CONFIG.ROLES.ADMIN:
            window.location.href = "admin-dashboard.html";
            break;
        default:
            alert("Unknown role");
    }
}

// Check authentication and redirect if not logged in
function checkAuth() {
    if (!Session.isAuthenticated()) {
        window.location.href = "login.html";
        return false;
    }
    return true;
}

// Logout function
function logout() {
    Session.clearSession();
    window.location.href = "login.html";
}

// Generate SHA-256 hash of file
async function generateHash(file) {
    try {
  const buffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest("SHA-256", buffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
        return hashHex;
    } catch (error) {
        console.error("Hash generation error:", error);
        throw error;
    }
}

// Upload file to IPFS and get real CID
async function uploadToIPFS(file) {
    try {
        const apiUrl = CONFIG.IPFS.API_URL;
        const isPinata = apiUrl.includes('pinata.cloud');
        const isWeb3Storage = apiUrl.includes('web3.storage');
        const isLocalIPFS = apiUrl.includes('localhost') || apiUrl.includes('127.0.0.1');
        
        let headers = {};
        let formData = new FormData();
        
        // Prepare request based on IPFS provider
        if (isPinata) {
            // Pinata IPFS
            if (!CONFIG.IPFS.PINATA_API_KEY || !CONFIG.IPFS.PINATA_SECRET_KEY) {
                throw new Error('Pinata API keys not configured. Please sign up at pinata.cloud and add your API keys in config.js');
            }
            formData.append('file', file);
            headers = {
                'pinata_api_key': CONFIG.IPFS.PINATA_API_KEY,
                'pinata_secret_api_key': CONFIG.IPFS.PINATA_SECRET_KEY
            };
        } else if (isWeb3Storage) {
            // Web3.Storage
            if (!CONFIG.IPFS.WEB3_STORAGE_TOKEN) {
                throw new Error('Web3.Storage token not configured. Please sign up at web3.storage and add your token in config.js');
            }
            formData.append('file', file);
            headers = {
                'Authorization': `Bearer ${CONFIG.IPFS.WEB3_STORAGE_TOKEN}`
            };
        } else {
            // Standard IPFS API (local node or public)
            formData.append('file', file);
            // No headers needed for standard IPFS API
            // IPFS Desktop should handle CORS automatically
        }

        // Upload file to IPFS
        // Note: IPFS Desktop should handle CORS automatically
        const response = await fetch(apiUrl, {
            method: 'POST',
            headers: headers,
            body: formData,
            mode: 'cors' // Explicitly set CORS mode
        });

        if (!response.ok) {
            const errorText = await response.text();
            
            // Provide helpful error messages
            if (response.status === 401) {
                if (isLocalIPFS) {
                    throw new Error('IPFS node not running. Please start IPFS Desktop or run "ipfs daemon" in terminal. Download IPFS Desktop from: https://github.com/ipfs/ipfs-desktop/releases');
                } else {
                    throw new Error('Authentication failed. Please check your API keys in config.js');
                }
            } else if (response.status === 0 || response.status === 503) {
                if (isLocalIPFS) {
                    throw new Error('Cannot connect to local IPFS node. Make sure IPFS Desktop is running or start IPFS daemon. Download from: https://github.com/ipfs/ipfs-desktop/releases');
                } else {
                    throw new Error('IPFS service unavailable. Please try again later or use local IPFS node.');
                }
            }
            
            throw new Error(`IPFS upload failed: ${response.status} - ${errorText}`);
        }

        const result = await response.json();
        
        // Extract CID from response (different providers return different formats)
        let cid = null;
        if (result.Hash) {
            cid = result.Hash; // Standard IPFS API
        } else if (result.IpfsHash) {
            cid = result.IpfsHash; // Pinata
        } else if (result.cid) {
            cid = result.cid; // Web3.Storage
        } else if (Array.isArray(result) && result[0] && result[0].Hash) {
            cid = result[0].Hash; // Some IPFS APIs return array
        }
        
        if (!cid) {
            console.error('IPFS response:', result);
            throw new Error('CID not found in IPFS response. Response: ' + JSON.stringify(result));
        }

        console.log('File uploaded to IPFS. CID:', cid);
        
        // Files are uploaded but not pinned
        // Users can access files via gateway links
        return cid;
        
    } catch (error) {
        console.error('IPFS upload error:', error);
        
        // Provide helpful error message
        if (error.message.includes('Failed to fetch') || error.message.includes('NetworkError') || error.message.includes('CORS')) {
            const isLocalIPFS = CONFIG.IPFS.API_URL.includes('localhost') || CONFIG.IPFS.API_URL.includes('127.0.0.1');
            if (isLocalIPFS) {
                throw new Error('CORS Error: Cannot connect to IPFS node. Please:\n1. Run enable-ipfs-cors.bat (in project root) to enable CORS\n2. Restart IPFS Desktop\n3. Try again\n\nOr enable CORS manually:\nipfs config --json API.HTTPHeaders.Access-Control-Allow-Origin \'["*"]\'');
            } else {
                throw new Error('Network error. Please check your internet connection or use local IPFS node.');
            }
        }
        
        throw error;
    }
}

// Upload evidence (simulated blockchain storage)
async function uploadEvidence() {
    const fileInput = document.getElementById("fileInput");
    const caseIdInput = document.getElementById("caseId");
    const statusDiv = document.getElementById("uploadStatus");
    const hashOutput = document.getElementById("hashOutput");
    const ipfsOutput = document.getElementById("ipfsOutput");
    const txOutput = document.getElementById("txOutput");

    // Clear previous outputs
    statusDiv.innerHTML = "";
    hashOutput.innerText = "";
    ipfsOutput.innerText = "";
    txOutput.innerText = "";

    const file = fileInput.files[0];
    const caseId = caseIdInput.value.trim();

    if (!file) {
        statusDiv.innerHTML = "<p class='error'>Please select a file</p>";
        return;
    }

    if (!caseId) {
        statusDiv.innerHTML = "<p class='error'>Please enter a case ID</p>";
        return;
    }

    // Check if Case ID already exists
    const existingEvidence = BlockchainStorage.getEvidenceByCaseId(caseId);
    if (existingEvidence && existingEvidence.length > 0) {
        statusDiv.innerHTML = `<p class='error'>Case ID "${caseId}" already exists! Please use a different Case ID or add evidence to the existing case.</p>`;
        return;
    }

    try {
        statusDiv.innerHTML = "<p class='info'>Processing evidence...</p>";

        // Step 1: Generate hash
        statusDiv.innerHTML = "<p class='info'>Step 1/4: Generating SHA-256 hash...</p>";
        const evidenceHash = await generateHash(file);
        hashOutput.innerText = evidenceHash;
        console.log("Evidence hash:", evidenceHash);

        // Step 2: Upload to IPFS and get real CID
        statusDiv.innerHTML = "<p class='info'>Step 2/4: Uploading file to IPFS...</p>";
        let ipfsCID;
        try {
            const uploadResult = await uploadToIPFS(file);
            // Handle both string CID and object with cid property
            ipfsCID = typeof uploadResult === 'string' ? uploadResult : (uploadResult.cid || uploadResult);
            
            // Create gateway link only
            const ipfsLinks = `
                <div style="margin-top: 10px;">
                    <a href="${CONFIG.IPFS.GATEWAY}${ipfsCID}" target="_blank" class="btn-secondary" style="display: inline-block; text-decoration: none; padding: 8px 15px;">🌐 View on Gateway</a>
                </div>
                <small style="display: block; margin-top: 5px; color: #9ca3af;">CID: ${ipfsCID}</small>
            `;
            
            ipfsOutput.innerHTML = `<span class="hash-display">${ipfsCID}</span>${ipfsLinks}`;
            console.log("IPFS CID:", ipfsCID);
        } catch (ipfsError) {
            console.error("IPFS upload failed:", ipfsError);
            statusDiv.innerHTML = `<p class='error'>IPFS upload failed: ${ipfsError.message}. Please check IPFS configuration or try again.</p>`;
            return;
        }

        // Step 3: Store in simulated blockchain
        statusDiv.innerHTML = "<p class='info'>Step 3/4: Storing evidence metadata...</p>";
        const user = Session.getCurrentUser();
        const investigator = user ? user.userId : 'Unknown';
        
        const evidence = BlockchainStorage.addEvidence(caseId, evidenceHash, ipfsCID, investigator);
        
        // Generate simulated transaction hash
        const txHash = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32)))
            .map(b => b.toString(16).padStart(2, "0"))
            .join("");
        
        txOutput.innerHTML = `<span class="hash-display">${txHash}</span>`;
        
        // Step 4: Complete
        statusDiv.innerHTML = "<p class='success'>✓ Evidence successfully uploaded to IPFS and stored!</p><p class='info'>File is now available on IPFS network. CID: " + ipfsCID + "</p>";
        
        // Store evidence info locally for verification
        const evidenceInfo = {
            caseId: caseId,
            hash: evidenceHash,
            ipfsCID: ipfsCID,
            fileName: file.name,
            fileSize: file.size,
            uploadTime: new Date().toISOString(),
            txHash: txHash,
            index: evidence.index
        };
        
        let evidenceList = JSON.parse(localStorage.getItem('evidenceList') || '[]');
        evidenceList.push(evidenceInfo);
        localStorage.setItem('evidenceList', JSON.stringify(evidenceList));

    } catch (error) {
        console.error("Upload error:", error);
        statusDiv.innerHTML = `<p class='error'>Error: ${error.message}</p>`;
    }
}

// Retrieve evidence from simulated blockchain
function retrieveEvidence(index) {
    const evidence = BlockchainStorage.getEvidence(index);
    if (!evidence) {
        throw new Error("Evidence not found");
    }
    return {
        caseId: evidence.caseId,
        evidenceHash: evidence.evidenceHash,
        ipfsCID: evidence.ipfsCID,
        timestamp: new Date(evidence.timestamp).toLocaleString(),
        investigator: evidence.investigator,
        index: evidence.index
    };
}

// Retrieve file from IPFS using CID
async function retrieveFileFromIPFS(cid) {
    try {
        // Construct IPFS gateway URL
        const ipfsUrl = `${CONFIG.IPFS.GATEWAY}${cid}`;
        
        // Fetch file from IPFS
        const response = await fetch(ipfsUrl);
        
        if (!response.ok) {
            throw new Error(`Failed to retrieve file from IPFS: ${response.status}`);
        }
        
        // Return file as blob
        const blob = await response.blob();
        return blob;
        
    } catch (error) {
        console.error("IPFS retrieval error:", error);
        throw new Error(`Failed to retrieve file from IPFS: ${error.message}`);
    }
}

// Verify evidence integrity
async function verifyEvidence(file, storedHash) {
    try {
        const computedHash = await generateHash(file);
        return {
            isValid: computedHash.toLowerCase() === storedHash.toLowerCase(),
            computedHash: computedHash,
            storedHash: storedHash
        };
    } catch (error) {
        console.error("Verification error:", error);
        throw error;
    }
}

// Get evidence count
function getEvidenceCount() {
    return BlockchainStorage.getEvidenceCount();
}

// Format timestamp
function formatTimestamp(timestamp) {
    return new Date(timestamp).toLocaleString();
}

// Display user info in dashboard
function displayUserInfo() {
    const user = Session.getCurrentUser();
    if (user) {
        const userInfoElement = document.getElementById('userInfo');
        if (userInfoElement) {
            userInfoElement.innerHTML = `
                <p><strong>User:</strong> ${user.userId}</p>
                <p><strong>Role:</strong> ${user.role.charAt(0).toUpperCase() + user.role.slice(1)}</p>
            `;
        }
    }
}

// Initialize page
document.addEventListener('DOMContentLoaded', function() {
    // Check authentication for protected pages
    const currentPage = window.location.pathname.split('/').pop();
    if (currentPage !== 'login.html' && !currentPage.includes('login')) {
        if (!checkAuth()) {
            return;
        }
        displayUserInfo();
    }
});
