// Example JavaScript file with multiple vulnerabilities

const fs = require('fs');
const { exec } = require('child_process');
const http = require('http');
const crypto = require('crypto');

// Hardcoded secret (bad practice)
const secretToken = "my-secret-token-123";

// SQL Injection (simulated)
function getUserInfo(username) {
    // Vulnerable: user input directly in query string
    const query = "SELECT * FROM users WHERE name = '" + username + "'";
    console.log("Running query:", query);
    // Imagine this is sent to a database...
}

// Command Injection
function runSystemCommand(userInput) {
    exec("ls " + userInput, (err, stdout, stderr) => {
        if (err) {
            console.error(err);
            return;
        }
        console.log(stdout);
    });
}

// Path Traversal
function readFile(filename) {
    fs.readFile("./data/" + filename, "utf8", (err, data) => {
        if (err) {
            console.error(err);
            return;
        }
        console.log(data);
    });
}

// 1. Cross-Site Scripting (XSS) - server-side rendering
function renderComment(userComment) {
    // Directly embedding user input into HTML
    const html = `<div>${userComment}</div>`;
    console.log(html);
}

// 2. Insecure Deserialization
function insecureDeserialize(serializedData) {
    // Using eval to deserialize user input
    const obj = eval('(' + serializedData + ')');
    console.log(obj);
}

// 3. Information Disclosure (stack trace leak)
function processRequest(req) {
    try {
        // Some processing...
        throw new Error("Something went wrong!");
    } catch (err) {
        // Leaking stack trace to user
        req.res.end(err.stack);
    }
}

// 4. Use of deprecated/insecure crypto algorithm
const bcrypt = require('bcrypt');
function hashPassword(password) {
    // Use bcrypt for secure password hashing
    const saltRounds = 10; // Adjust cost factor as needed
    return bcrypt.hashSync(password, bcrypt.genSaltSync(saltRounds));
}

// 5. Insecure HTTP (sensitive data sent over HTTP)
function sendSensitiveData(data) {
    const options = {
        hostname: 'example.com',
        port: 80,
        path: '/submit',
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        }
    };

    const req = http.request(options, (res) => {
        res.on('data', (d) => {
            process.stdout.write(d);
        });
    });

    req.write(JSON.stringify({ secret: data }));
    req.end();
}

// Example usage
getUserInfo("admin' OR '1'='1");
runSystemCommand("; rm -rf /");
readFile("../../etc/passwd");
renderComment("<img src=x onerror=alert(1)>");
insecureDeserialize("{ \"isAdmin\": true }");
processRequest({ res: { end: console.log } });
console.log(hashPassword("password123"));
sendSensitiveData("my-secret-data");
