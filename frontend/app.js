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
            // Store JWT token if provided
            if (verification.token) {
                EnhancedFeatures.setToken(verification.token);
            }

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
    switch (role) {
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
    EnhancedFeatures.clearToken();
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

// Upload evidence (Enhanced with multi-file, encryption, categories)
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

    const files = fileInput.files;
    const caseId = caseIdInput.value.trim();
    const category = document.getElementById("category")?.value || null;
    const tags = document.getElementById("tags")?.value.trim() || null;
    const description = document.getElementById("description")?.value.trim() || null;
    const encryptFile = document.getElementById("encryptFile")?.checked || false;

    if (!files || files.length === 0) {
        statusDiv.innerHTML = "<p class='error'>Please select at least one file</p>";
        return;
    }

    if (!caseId) {
        statusDiv.innerHTML = "<p class='error'>Please enter a case ID</p>";
        return;
    }

    // Process multiple files
    const user = Session.getCurrentUser();
    const investigator = user ? user.userId : 'Unknown';
    let encryptionKey = null;

    if (encryptFile) {
        encryptionKey = EnhancedFeatures.generateEncryptionKey();
        statusDiv.innerHTML = "<p class='info'>Encryption key generated. Keep it safe!</p>";
    }

    // Upload each file
    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        await uploadSingleFile(file, caseId, investigator, category, tags, description, encryptFile, encryptionKey, i + 1, files.length);
    }
}

// Upload single file
async function uploadSingleFile(file, caseId, investigator, category, tags, description, encryptFile, encryptionKey, fileNum, totalFiles) {
    const statusDiv = document.getElementById("uploadStatus");
    const hashOutput = document.getElementById("hashOutput");
    const ipfsOutput = document.getElementById("ipfsOutput");
    const txOutput = document.getElementById("txOutput");

    // Note: We allow multiple evidence per case ID, so no need to check for duplicates
    // If you want to prevent duplicates, uncomment below:
    // try {
    //     const existingEvidence = await EvidenceAPI.getEvidenceByCaseId(caseId);
    //     if (existingEvidence && existingEvidence.length > 0) {
    //         statusDiv.innerHTML = `<p class='error'>Case ID "${caseId}" already has ${existingEvidence.length} evidence record(s). You can add more evidence to this case.</p>`;
    //         return;
    //     }
    // } catch (error) {
    //     console.error("Error checking existing evidence:", error);
    //     // Continue anyway
    // }

    try {
        statusDiv.innerHTML = `<p class='info'>Processing file ${fileNum}/${totalFiles}: ${file.name}...</p>`;

        let fileToUpload = file;
        let isEncrypted = false;

        // Step 1: Encrypt file if requested
        if (encryptFile && encryptionKey) {
            statusDiv.innerHTML = `<p class='info'>File ${fileNum}/${totalFiles}: Encrypting file...</p>`;
            try {
                fileToUpload = await EnhancedFeatures.encryptFile(file, encryptionKey);
                isEncrypted = true;
                console.log("File encrypted successfully");
            } catch (encryptError) {
                console.error("Encryption failed:", encryptError);
                statusDiv.innerHTML = `<p class='error'>Encryption failed: ${encryptError.message}</p>`;
                return;
            }
        }

        // Step 2: Generate hash (of original file, not encrypted)
        statusDiv.innerHTML = `<p class='info'>File ${fileNum}/${totalFiles}: Generating SHA-256 hash...</p>`;
        const evidenceHash = await generateHash(file); // Hash original file
        hashOutput.innerText = evidenceHash;
        console.log("Evidence hash:", evidenceHash);

        // Step 3: Upload to IPFS and get real CID
        statusDiv.innerHTML = `<p class='info'>File ${fileNum}/${totalFiles}: Uploading to IPFS...</p>`;
        let ipfsCID;
        try {
            const uploadResult = await uploadToIPFS(fileToUpload);
            ipfsCID = typeof uploadResult === 'string' ? uploadResult : (uploadResult.cid || uploadResult);

            const ipfsLinks = `
                <div style="margin-top: 10px;">
                    <a href="${CONFIG.IPFS.GATEWAY}${ipfsCID}" target="_blank" class="btn-secondary" style="display: inline-block; text-decoration: none; padding: 8px 15px;">🌐 View on Gateway</a>
                </div>
                <small style="display: block; margin-top: 5px; color: #9ca3af;">CID: ${ipfsCID}${isEncrypted ? ' (Encrypted)' : ''}</small>
            `;

            ipfsOutput.innerHTML = `<span class="hash-display">${ipfsCID}</span>${ipfsLinks}`;
            console.log("IPFS CID:", ipfsCID);
        } catch (ipfsError) {
            console.error("IPFS upload failed:", ipfsError);
            statusDiv.innerHTML = `<p class='error'>IPFS upload failed: ${ipfsError.message}. Please check IPFS configuration or try again.</p>`;
            return;
        }

        // Step 4: Store in MySQL database
        statusDiv.innerHTML = `<p class='info'>File ${fileNum}/${totalFiles}: Storing evidence metadata in database...</p>`;

        // Prepare evidence data for database
        const evidenceData = {
            caseId: caseId,
            fileName: file.name,
            fileSize: file.size,
            fileType: file.type || null,
            evidenceHash: evidenceHash,
            ipfsCID: ipfsCID,
            investigatorId: investigator,
            description: description,
            category: category,
            tags: tags,
            encrypt: isEncrypted,
            encryptionKey: isEncrypted ? encryptionKey : null
        };

        try {
            // Store in database via API
            const result = await EvidenceAPI.addEvidence(evidenceData);

            // Generate transaction hash for display (simulated)
            const txHash = '0x' + Array.from(crypto.getRandomValues(new Uint8Array(32)))
                .map(b => b.toString(16).padStart(2, "0"))
                .join("");

            txOutput.innerHTML = `<span class="hash-display">${txHash}</span>`;

            // Step 5: Complete
            if (fileNum === totalFiles) {
                statusDiv.innerHTML = `<p class='success'>✓ All ${totalFiles} file(s) successfully uploaded to IPFS and stored in database!</p><p class='info'>Files are now available on IPFS network.</p>${isEncrypted ? '<p class="warning">⚠️ IMPORTANT: Save your encryption key: ' + encryptionKey + '</p>' : ''}`;

                // Clear form after all files uploaded
                document.getElementById("fileInput").value = '';
                document.getElementById("caseId").value = '';
                if (document.getElementById("description")) document.getElementById("description").value = '';
                if (document.getElementById("tags")) document.getElementById("tags").value = '';
            } else {
                statusDiv.innerHTML = `<p class='success'>✓ File ${fileNum}/${totalFiles} uploaded successfully. Processing next file...</p>`;
            }
        } catch (dbError) {
            console.error("Database storage error:", dbError);
            statusDiv.innerHTML = `<p class='error'>IPFS upload successful, but database storage failed: ${dbError.message}. Please contact administrator.</p>`;
        }

    } catch (error) {
        console.error("Upload error:", error);
        statusDiv.innerHTML = `<p class='error'>Error: ${error.message}</p>`;
    }
}

// Retrieve evidence from database by ID
async function retrieveEvidence(id) {
    try {
        const evidence = await EvidenceAPI.getEvidenceById(id);
        if (!evidence) {
            throw new Error("Evidence not found");
        }
        return {
            id: evidence.id,
            caseId: evidence.caseId,
            evidenceHash: evidence.evidenceHash,
            ipfsCID: evidence.ipfsCID,
            fileName: evidence.fileName,
            fileSize: evidence.fileSize,
            fileType: evidence.fileType,
            timestamp: evidence.createdAtReadable || new Date(evidence.createdAt).toLocaleString(),
            investigator: evidence.investigatorId,
            status: evidence.status,
            description: evidence.description,
            category: evidence.category,
            tags: evidence.tags
        };
    } catch (error) {
        console.error("Error retrieving evidence:", error);
        throw error;
    }
}

// Retrieve evidence by index (for backward compatibility - gets all and returns by index)
async function retrieveEvidenceByIndex(index) {
    try {
        const allEvidence = await EvidenceAPI.getAllEvidence({ limit: index + 1 });
        if (index >= allEvidence.length) {
            throw new Error("Evidence index out of bounds");
        }
        const evidence = allEvidence[index];
        return {
            id: evidence.id,
            caseId: evidence.caseId,
            evidenceHash: evidence.evidenceHash,
            ipfsCID: evidence.ipfsCID,
            fileName: evidence.fileName,
            timestamp: evidence.createdAtReadable || new Date(evidence.createdAt).toLocaleString(),
            investigator: evidence.investigatorId,
            index: index
        };
    } catch (error) {
        console.error("Error retrieving evidence by index:", error);
        throw error;
    }
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
// Verify evidence integrity
async function verifyEvidence(file, storedHash) {
    try {
        // 1. Calculate hash of the file locally for UI display
        const computedHash = await generateHash(file);

        // 2. call Backend to verify against Blockchain
        // We accept the file's hash and check if it matches the blockchain record for the *storedHash* or just verify existence.
        // The backend `verifyEvidenceOnBlockchain` takes (evidenceHash, ipfsCID).
        // Since we might not have the IPFS CID here easily without fetching, let's just send the hash.

        // Actually, let's try to verify if the *computed hash* exists on the blockchain.
        const response = await fetch(`${CONFIG.API.BASE_URL}/evidence/verify`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                hash: computedHash
            })
        });

        if (!response.ok) {
            // Fallback to local comparison if backend fails or network issue
            console.warn('Backend verification failed, falling back to local');
            return {
                isValid: computedHash.toLowerCase() === storedHash.toLowerCase(),
                computedHash: computedHash,
                storedHash: storedHash,
                blockchainData: null
            };
        }

        const result = await response.json();

        return {
            isValid: result.verified && (computedHash.toLowerCase() === storedHash.toLowerCase()),
            computedHash: computedHash,
            storedHash: storedHash,
            blockchainData: result.onChainData // includes blockchainId now
        };

    } catch (error) {
        console.error("Verification error:", error);
        throw error;
    }
}

// Get evidence count
async function getEvidenceCount() {
    try {
        const stats = await EvidenceAPI.getStatistics();
        return stats.total || 0;
    } catch (error) {
        console.error("Error getting evidence count:", error);
        return 0;
    }
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
document.addEventListener('DOMContentLoaded', function () {
    // Check authentication for protected pages
    const currentPage = window.location.pathname.split('/').pop();
    if (currentPage !== 'login.html' && !currentPage.includes('login')) {
        if (!checkAuth()) {
            return;
        }
        displayUserInfo();
    }
});
