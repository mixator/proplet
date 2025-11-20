# Security Examples - Vulnerable vs Secure Code

This document shows common vulnerability patterns that CodeQL detects and how to fix them.

## 🔴 SQL Injection

### ❌ Vulnerable Code
```javascript
// String concatenation with user input
app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  const query = `SELECT * FROM users WHERE id = ${userId}`;
  const result = await db.query(query);
  res.json(result);
});

// Template literal with user input
app.post('/search', async (req, res) => {
  const searchTerm = req.body.search;
  const query = `SELECT * FROM products WHERE name LIKE '%${searchTerm}%'`;
  const results = await db.query(query);
  res.json(results);
});
```

**Why it's vulnerable**: Attacker can inject malicious SQL code
- Input: `1 OR 1=1 --` returns all users
- Input: `'; DROP TABLE users; --` deletes the table

### ✅ Secure Code
```javascript
// Use parameterized queries (PostgreSQL example)
app.get('/user/:id', async (req, res) => {
  const userId = req.params.id;
  const query = 'SELECT * FROM users WHERE id = $1';
  const result = await db.query(query, [userId]);
  res.json(result);
});

// Use ORM with parameterized queries (Drizzle ORM)
import { eq } from 'drizzle-orm';

app.get('/user/:id', async (req, res) => {
  const userId = parseInt(req.params.id);
  const result = await db.select().from(users).where(eq(users.id, userId));
  res.json(result);
});

// Search with proper escaping
app.post('/search', async (req, res) => {
  const searchTerm = req.body.search;
  const query = 'SELECT * FROM products WHERE name ILIKE $1';
  const results = await db.query(query, [`%${searchTerm}%`]);
  res.json(results);
});
```

**CodeQL Query**: `sql-injection.ql`

---

## 🔴 Hardcoded Secrets

### ❌ Vulnerable Code
```javascript
// Hardcoded API keys
const STRIPE_SECRET_KEY = "sk_live_51JxK2jL3m4n5p6q7r8s9t0u1v2w3x4y5z";
const AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE";
const DATABASE_PASSWORD = "MySecretP@ssw0rd123";

// In configuration object
const config = {
  apiKey: "AIzaSyDx1234567890abcdefghijklmnopqrst",
  authDomain: "myapp.firebaseapp.com",
  databaseURL: "https://myapp.firebaseio.com"
};

// In connection string
const connectionString = "postgresql://admin:SuperSecret123@localhost:5432/mydb";
```

**Why it's vulnerable**:
- Secrets exposed in version control
- Easy to extract from deployed code
- Can't rotate credentials without code changes
- Anyone with code access has production credentials

### ✅ Secure Code
```javascript
// Use environment variables
const STRIPE_SECRET_KEY = process.env.STRIPE_SECRET_KEY;
const AWS_ACCESS_KEY = process.env.AWS_ACCESS_KEY;
const DATABASE_PASSWORD = process.env.DATABASE_PASSWORD;

// Validate environment variables at startup
if (!STRIPE_SECRET_KEY) {
  throw new Error('STRIPE_SECRET_KEY environment variable is required');
}

// In configuration with validation
const config = {
  apiKey: process.env.FIREBASE_API_KEY,
  authDomain: process.env.FIREBASE_AUTH_DOMAIN,
  databaseURL: process.env.FIREBASE_DATABASE_URL
};

// Connection string from environment
const connectionString = process.env.DATABASE_URL;
```

**Environment file** (`.env` - never commit this!):
```bash
STRIPE_SECRET_KEY=sk_live_actual_key_here
AWS_ACCESS_KEY=actual_access_key
DATABASE_PASSWORD=actual_password
FIREBASE_API_KEY=actual_api_key
```

**CodeQL Query**: `hardcoded-secrets.ql`

---

## 🟡 Unvalidated URL Redirect

### ❌ Vulnerable Code
```javascript
// Direct redirect from query parameter
app.get('/redirect', (req, res) => {
  const url = req.query.url;
  res.redirect(url);
});

// Redirect from POST body
app.post('/login', async (req, res) => {
  const { username, password, returnUrl } = req.body;
  
  if (await validateCredentials(username, password)) {
    res.redirect(returnUrl); // Dangerous!
  }
});

// Header-based redirect
app.get('/external', (req, res) => {
  const referer = req.headers.referer;
  res.redirect(referer);
});
```

**Why it's vulnerable**: Phishing attacks
- Attacker sends: `https://yoursite.com/redirect?url=https://evil.com`
- User clicks, sees your trusted domain
- Gets redirected to attacker's site
- Attacker harvests credentials on fake login page

### ✅ Secure Code
```javascript
// Validate against allowlist
const ALLOWED_DOMAINS = ['example.com', 'app.example.com'];

app.get('/redirect', (req, res) => {
  const url = req.query.url;
  
  try {
    const parsedUrl = new URL(url);
    
    if (ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
      res.redirect(url);
    } else {
      res.status(400).send('Invalid redirect URL');
    }
  } catch (error) {
    res.status(400).send('Invalid URL');
  }
});

// Allow only relative paths
app.post('/login', async (req, res) => {
  const { username, password, returnUrl } = req.body;
  
  if (await validateCredentials(username, password)) {
    // Only allow relative URLs (starts with /)
    if (returnUrl && returnUrl.startsWith('/') && !returnUrl.startsWith('//')) {
      res.redirect(returnUrl);
    } else {
      res.redirect('/dashboard');
    }
  }
});

// Validate and sanitize referer
app.get('/external', (req, res) => {
  const referer = req.headers.referer;
  
  if (referer) {
    const parsedUrl = new URL(referer);
    if (ALLOWED_DOMAINS.includes(parsedUrl.hostname)) {
      res.redirect(referer);
      return;
    }
  }
  
  res.redirect('/');
});
```

**CodeQL Query**: `unvalidated-redirect.ql`

---

## 🟡 Missing Error Handling

### ❌ Vulnerable Code
```javascript
// No try-catch in async function
async function fetchUserData(userId) {
  const user = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
  const orders = await db.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
  return { user, orders };
}

// Unhandled promise rejection
app.get('/data', (req, res) => {
  fetchData().then(data => {
    res.json(data);
  });
  // Missing .catch()
});

// Await without try-catch
app.get('/user/:id', async (req, res) => {
  const user = await getUserById(req.params.id);
  const profile = await getProfileById(user.profileId);
  res.json({ user, profile });
});
```

**Why it's problematic**:
- Crashes the application
- Exposes internal errors to users
- No logging of errors
- Poor user experience
- Can leak sensitive information in error messages

### ✅ Secure Code
```javascript
// Proper try-catch in async function
async function fetchUserData(userId) {
  try {
    const user = await db.query('SELECT * FROM users WHERE id = $1', [userId]);
    const orders = await db.query('SELECT * FROM orders WHERE user_id = $1', [userId]);
    return { user, orders };
  } catch (error) {
    logger.error('Error fetching user data:', { userId, error });
    throw new Error('Failed to fetch user data');
  }
}

// Promise with catch handler
app.get('/data', (req, res) => {
  fetchData()
    .then(data => {
      res.json(data);
    })
    .catch(error => {
      logger.error('Error fetching data:', error);
      res.status(500).json({ error: 'Internal server error' });
    });
});

// Await with try-catch
app.get('/user/:id', async (req, res) => {
  try {
    const user = await getUserById(req.params.id);
    const profile = await getProfileById(user.profileId);
    res.json({ user, profile });
  } catch (error) {
    logger.error('Error fetching user:', { userId: req.params.id, error });
    res.status(500).json({ error: 'Failed to fetch user data' });
  }
});

// Global error handler (Express)
app.use((error, req, res, next) => {
  logger.error('Unhandled error:', error);
  res.status(500).json({ error: 'Internal server error' });
});
```

**CodeQL Query**: `missing-error-handling.ql`

---

## 🔵 Console.log in Production

### ❌ Vulnerable Code
```javascript
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  console.log('Login attempt:', username, password); // Logs sensitive data!
  console.log('User object:', req.user);
  
  const result = await authenticateUser(username, password);
  console.log('Auth result:', result);
  
  res.json({ success: true });
});

// Debugging statements left in code
function processPayment(paymentData) {
  console.log('Payment data:', paymentData);
  console.log('API Key:', process.env.STRIPE_SECRET_KEY); // Leaks secrets!
  
  return stripe.charges.create(paymentData);
}
```

**Why it's problematic**:
- Logs sensitive data (passwords, tokens, PII)
- Performance impact
- Clutters production logs
- Can leak secrets to log aggregation services
- Not structured or searchable
- No log levels or filtering

### ✅ Secure Code
```javascript
// Use proper logging library
import { logger } from './logger'; // Winston, Pino, etc.

app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  
  logger.info('Login attempt', { username }); // Don't log password!
  
  try {
    const result = await authenticateUser(username, password);
    logger.info('Successful login', { username, userId: result.userId });
    res.json({ success: true });
  } catch (error) {
    logger.error('Login failed', { username, error: error.message });
    res.status(401).json({ error: 'Invalid credentials' });
  }
});

// Proper logging with sanitization
function processPayment(paymentData) {
  // Sanitize sensitive data
  const sanitizedData = {
    amount: paymentData.amount,
    currency: paymentData.currency,
    // Don't log full card number
    cardLast4: paymentData.card.last4
  };
  
  logger.info('Processing payment', sanitizedData);
  
  return stripe.charges.create(paymentData);
}

// Development-only logging
function debugLog(message, data) {
  if (process.env.NODE_ENV !== 'production') {
    console.log(message, data);
  }
}

// Conditional debug logging
if (process.env.DEBUG === 'true') {
  logger.debug('Debug info', { data });
}
```

**Logger Configuration Example**:
```javascript
import winston from 'winston';

export const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.json(),
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' })
  ]
});

// Don't log to console in production
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: winston.format.simple()
  }));
}
```

**CodeQL Query**: `console-log-in-production.ql`

---

## 🔴 Command Injection

### ❌ Vulnerable Code
```javascript
// Executing shell commands with user input
const exec = require('child_process').exec;

app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec(`ping -c 4 ${host}`, (error, stdout, stderr) => {
    res.send(stdout);
  });
});

// File operations with user input
app.get('/read', (req, res) => {
  const filename = req.query.file;
  exec(`cat /var/data/${filename}`, (error, stdout) => {
    res.send(stdout);
  });
});
```

**Why it's vulnerable**: Remote code execution
- Input: `example.com; rm -rf /` executes malicious command
- Input: `example.com && cat /etc/passwd` leaks system files
- Attacker gains full server control

### ✅ Secure Code
```javascript
// Use safe APIs instead of shell commands
const { ping } = require('net-ping');

app.get('/ping', async (req, res) => {
  const host = req.query.host;
  
  // Validate hostname format
  const hostnameRegex = /^[a-zA-Z0-9.-]+$/;
  if (!hostnameRegex.test(host)) {
    return res.status(400).json({ error: 'Invalid hostname' });
  }
  
  // Use safe ping library
  const session = ping.createSession();
  session.pingHost(host, (error, target, sent, rcvd) => {
    if (error) {
      res.status(500).json({ error: 'Ping failed' });
    } else {
      res.json({ host: target, latency: rcvd - sent });
    }
  });
});

// Use fs module instead of shell commands
const fs = require('fs').promises;
const path = require('path');

app.get('/read', async (req, res) => {
  const filename = req.query.file;
  
  // Validate filename (no path traversal)
  if (filename.includes('..') || filename.includes('/')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  const allowedFiles = ['data.txt', 'report.pdf', 'config.json'];
  if (!allowedFiles.includes(filename)) {
    return res.status(403).json({ error: 'File not allowed' });
  }
  
  try {
    const filePath = path.join('/var/data', filename);
    const content = await fs.readFile(filePath, 'utf-8');
    res.send(content);
  } catch (error) {
    res.status(500).json({ error: 'Failed to read file' });
  }
});

// If you MUST use exec, use execFile with array args
const { execFile } = require('child_process');

app.get('/convert', async (req, res) => {
  const inputFile = req.query.input;
  
  // Validate filename
  if (!/^[a-zA-Z0-9_-]+\.txt$/.test(inputFile)) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Use execFile with array (no shell interpretation)
  execFile('/usr/bin/convert', [inputFile, 'output.pdf'], (error, stdout) => {
    if (error) {
      return res.status(500).json({ error: 'Conversion failed' });
    }
    res.json({ success: true });
  });
});
```

**Built-in CodeQL Query**: `js/command-line-injection`

---

## 🔴 Path Traversal

### ❌ Vulnerable Code
```javascript
// Direct file access with user input
app.get('/download', (req, res) => {
  const filename = req.query.file;
  res.sendFile(`/var/www/uploads/${filename}`);
});

// Path concatenation
app.get('/image', (req, res) => {
  const imagePath = req.query.path;
  const fullPath = path.join(__dirname, 'public', imagePath);
  res.sendFile(fullPath);
});
```

**Why it's vulnerable**: Access unauthorized files
- Input: `../../../../etc/passwd` reads system files
- Input: `../../config/database.yml` exposes config
- Attacker can read any file the process can access

### ✅ Secure Code
```javascript
const path = require('path');
const fs = require('fs').promises;

app.get('/download', async (req, res) => {
  const filename = req.query.file;
  
  // Validate filename (basic check)
  if (!filename || filename.includes('..') || filename.includes('/')) {
    return res.status(400).json({ error: 'Invalid filename' });
  }
  
  // Whitelist allowed files
  const allowedFiles = await fs.readdir('/var/www/uploads');
  if (!allowedFiles.includes(filename)) {
    return res.status(404).json({ error: 'File not found' });
  }
  
  // Resolve and validate the path
  const uploadDir = path.resolve('/var/www/uploads');
  const filePath = path.resolve(uploadDir, filename);
  
  // Ensure resolved path is within upload directory
  if (!filePath.startsWith(uploadDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  res.sendFile(filePath);
});

// Secure image serving
app.get('/image', async (req, res) => {
  const imageName = req.query.name;
  
  // Only allow alphanumeric and specific characters
  const safePattern = /^[a-zA-Z0-9_-]+\.(jpg|jpeg|png|gif)$/;
  if (!safePattern.test(imageName)) {
    return res.status(400).json({ error: 'Invalid image name' });
  }
  
  const publicDir = path.resolve(__dirname, 'public', 'images');
  const imagePath = path.resolve(publicDir, imageName);
  
  // Verify path is within public directory
  if (!imagePath.startsWith(publicDir)) {
    return res.status(403).json({ error: 'Access denied' });
  }
  
  // Check file exists
  try {
    await fs.access(imagePath);
    res.sendFile(imagePath);
  } catch (error) {
    res.status(404).json({ error: 'Image not found' });
  }
});
```

**Built-in CodeQL Query**: `js/path-injection`

---

## 🔴 Cross-Site Scripting (XSS)

### ❌ Vulnerable Code
```javascript
// Direct HTML rendering with user input
app.get('/search', (req, res) => {
  const query = req.query.q;
  res.send(`<h1>Search Results for: ${query}</h1>`);
});

// Unescaped template rendering
app.get('/profile', (req, res) => {
  const username = req.query.name;
  const html = `
    <div class="profile">
      <h2>Welcome ${username}!</h2>
    </div>
  `;
  res.send(html);
});
```

**Why it's vulnerable**: Execute malicious scripts
- Input: `<script>alert('XSS')</script>` runs JavaScript
- Input: `<img src=x onerror=alert('XSS')>` runs on error
- Attacker can steal cookies, tokens, or modify page

### ✅ Secure Code
```javascript
// Use templating engine with auto-escaping (e.g., EJS, Pug)
import ejs from 'ejs';

app.get('/search', (req, res) => {
  const query = req.query.q;
  const template = '<h1>Search Results for: <%= query %></h1>';
  const html = ejs.render(template, { query }); // Auto-escapes
  res.send(html);
});

// Manual escaping if needed
function escapeHtml(text) {
  const map = {
    '&': '&amp;',
    '<': '&lt;',
    '>': '&gt;',
    '"': '&quot;',
    "'": '&#039;'
  };
  return text.replace(/[&<>"']/g, m => map[m]);
}

app.get('/profile', (req, res) => {
  const username = escapeHtml(req.query.name);
  const html = `
    <div class="profile">
      <h2>Welcome ${username}!</h2>
    </div>
  `;
  res.send(html);
});

// Best: Return JSON and render on client with framework
app.get('/search', (req, res) => {
  const query = req.query.q;
  // React/Vue/etc will handle escaping
  res.json({ query, results: [] });
});

// Set security headers
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Content-Security-Policy', "default-src 'self'");
  next();
});
```

**Built-in CodeQL Query**: `js/xss`

---

## Best Practices Summary

1. **Never trust user input** - Always validate and sanitize
2. **Use parameterized queries** - Never concatenate SQL
3. **Store secrets in environment variables** - Never hardcode
4. **Validate redirects** - Use allowlists or relative paths
5. **Handle errors properly** - Use try-catch and logging
6. **Use proper logging** - Not console.log in production
7. **Avoid shell commands** - Use safe APIs instead
8. **Validate file paths** - Prevent path traversal
9. **Escape output** - Prevent XSS attacks
10. **Keep dependencies updated** - Use `npm audit` regularly

## Running CodeQL to Find These Issues

```bash
# Create database
codeql database create codeql-db --language=javascript-typescript --source-root=./src

# Run all security checks
codeql database analyze codeql-db javascript-security-and-quality.qls --format=text

# Run only custom queries
codeql database analyze codeql-db ./codeql-custom-queries-javascript --format=text
```

## Additional Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [CWE Database](https://cwe.mitre.org/)
- [Node.js Security Best Practices](https://nodejs.org/en/docs/guides/security/)
- [CodeQL Documentation](https://codeql.github.com/docs/)