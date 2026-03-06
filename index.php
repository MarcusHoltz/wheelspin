<?php
/******************************************************************************
 * WHEELSPIN - Secure Self-Hosted Spinning Wheel Application
 *
 * Created with: https://github.com/CrazyTim/spin-wheel
 * Documentation: See README.md in github.com/MarcusHoltz/WheelSpin/
 *
 ******************************************************************************/

// Prevent file inclusion attacks
if (isset($_GET['file']) || isset($_POST['file']) || isset($_REQUEST['file'])) {
    http_response_code(403);
    die('Forbidden');
}

if (count(get_included_files()) > 1) {
    http_response_code(403);
    die('Forbidden');
}

/* Start session for token verification
 * PHP session_start(): https://www.php.net/manual/en/function.session-start.php
 */
session_start();

/* PHP __DIR__ magic constant
 * Reference: https://www.php.net/manual/en/language.constants.magic.php
 */
$dataDir = __DIR__ . '/data';
$wheelsFile = $dataDir . '/wheels.json';
$rateLimitDir = $dataDir . '/ratelimit';

/* Create directories with secure permissions
 * PHP mkdir(): https://www.php.net/manual/en/function.mkdir.php
 */
if (!is_dir($dataDir)) {
    @mkdir($dataDir, 0755, true);
}
if (!is_dir($rateLimitDir)) {
    @mkdir($rateLimitDir, 0755, true);
}

/* Initialize wheels file
 */
if (!file_exists($wheelsFile)) {
    @file_put_contents($wheelsFile, '{}');
    @chmod($wheelsFile, 0644);
}

/* Generate anti-bot token
 * PHP random_bytes(): https://www.php.net/manual/en/function.random-bytes.php
 * "Generates cryptographically secure pseudo-random bytes"
 * PHP bin2hex(): https://www.php.net/manual/en/function.bin2hex.php
 * "Convert binary data into hexadecimal representation"
 */
function generateBotToken() {
    $token = bin2hex(random_bytes(16));
    $_SESSION['bot_token'] = $token;
    $_SESSION['bot_token_time'] = time();
    return $token;
}

/* Verify anti-bot token
 * Checks: token match, not expired (5 min), honeypot not clicked
 */
function verifyBotToken($submittedToken, $honeypotValue) {
    // Check if honeypot was clicked (bot behavior)
    if (!empty($honeypotValue)) {
        return false; // Bot clicked invisible button
    }

    // Check token exists
    if (!isset($_SESSION['bot_token']) || !isset($_SESSION['bot_token_time'])) {
        return false;
    }

    // Check token matches
    if ($submittedToken !== $_SESSION['bot_token']) {
        return false;
    }

    // Check token not expired (5 minutes)
    if (time() - $_SESSION['bot_token_time'] > 300) {
        return false;
    }

    // Clear token after use (one-time use)
    unset($_SESSION['bot_token']);
    unset($_SESSION['bot_token_time']);

    return true;
}

/* IP-based rate limiting - ONLY for write operations
 * Read operations (load_all, load) are NOT rate limited
 * Accepts IP addresses or session-based identifiers
 * PHP filter_var(): https://www.php.net/manual/en/function.filter-var.php
 */
function checkRateLimit($identifier, $rateLimitDir, $actionType) {
    // Identifier should already be validated/sanitized by caller
    // Sanitize identifier for filename safety
    /* PHP preg_replace(): https://www.php.net/manual/en/function.preg-replace.php
     */
    $safeIdentifier = preg_replace('/[^a-zA-Z0-9\.\:_]/', '', $identifier);
    $rateLimitFile = $rateLimitDir . '/' . $safeIdentifier . '_' . $actionType;
    $now = time();

    // Check cooldown (1 second)
    if (file_exists($rateLimitFile)) {
        /* PHP filemtime(): https://www.php.net/manual/en/function.filemtime.php
         */
        $lastAction = @filemtime($rateLimitFile);
        if ($now - $lastAction < 1) {
            return false; // Too fast
        }
    }

    // Mark this action
    /* PHP touch(): https://www.php.net/manual/en/function.touch.php
     */
    @touch($rateLimitFile);

    // Cleanup old files (Optimization: Only run 5% of the time)
    if (rand(1, 20) === 1) {
        $files = @glob($rateLimitDir . '/*');
        if (is_array($files)) {
            foreach ($files as $file) {
                if (is_file($file) && $now - @filemtime($file) > 3600) {
                    @unlink($file);
                }
            }
        }
    }

    return true;
}

/* Validate wheel item structure
 */
function validateItems($items) {
    if (!is_array($items)) {
        return false;
    }

    if (count($items) > 50) {
        return false;
    }

    foreach ($items as $item) {
        if (!is_array($item)) {
            return false;
        }

        if (!isset($item['label'])) {
            return false;
        }

        if (!is_string($item['label']) || strlen($item['label']) > 200) {
            return false;
        }

        /* Accept both hex and rgb color formats
         * PHP preg_match(): https://www.php.net/manual/en/function.preg-match.php
         */
        if (isset($item['backgroundColor'])) {
            $color = $item['backgroundColor'];
            $isHex = preg_match('/^#[0-9A-Fa-f]{6}$/', $color);
            $isRgb = preg_match('/^rgb\(\d{1,3},\s*\d{1,3},\s*\d{1,3}\)$/', $color);

            if (!$isHex && !$isRgb) {
                return false;
            }
        }

        if (isset($item['weight']) && (!is_numeric($item['weight']) || $item['weight'] < 0 || $item['weight'] > 100)) {
            return false;
        }
    }

    return true;
}

/* Validate wheel ID format
 */
function validateWheelId($id) {
    return preg_match('/^wheel_[a-z0-9\.]+$/i', $id) === 1;
}

// Handle API requests
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action'])) {
    /* Set security headers
     * X-Content-Type-Options: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
     */
    header('Content-Type: application/json');
    header('X-Content-Type-Options: nosniff');

    /* Validate action against whitelist
     */
    $allowedActions = ['save', 'load_all', 'load', 'delete'];
    $action = $_POST['action'] ?? '';

    if (!in_array($action, $allowedActions, true)) {
        http_response_code(400);
        echo json_encode(['success' => false, 'message' => 'Invalid action']);
        exit;
    }

    /* Rate limit check - ONLY for write operations
     * This protects against DoS attacks by limiting save/delete requests
     * Read operations (load_all, load) are excluded to prevent page load errors
     */
    $writeActions = ['save', 'delete'];
    if (in_array($action, $writeActions, true)) {
        // Get IP address with proper handling
        /* PHP $_SERVER documentation: https://www.php.net/manual/en/reserved.variables.server.php
         */
        $clientIP = $_SERVER['REMOTE_ADDR'] ?? 'unknown';

        // Handle X-Forwarded-For (can contain multiple IPs: "client, proxy1, proxy2")
        if (isset($_SERVER['HTTP_X_FORWARDED_FOR'])) {
            $forwardedIPs = explode(',', $_SERVER['HTTP_X_FORWARDED_FOR']);
            $firstIP = trim($forwardedIPs[0]);
            if (filter_var($firstIP, FILTER_VALIDATE_IP)) {
                $clientIP = $firstIP;
            }
        }

        // Fallback to session ID if no valid IP (e.g., localhost, invalid IP)
        if (!filter_var($clientIP, FILTER_VALIDATE_IP)) {
            $clientIP = 'session_' . session_id();
        }

        // Run rate limit check
        if (!checkRateLimit($clientIP, $rateLimitDir, $action)) {
            http_response_code(429);
            echo json_encode(['success' => false, 'message' => 'Too many requests. Please wait a moment.']);
            exit;
        }
    }

    /* Verify bot token for write operations
     * Read operations (load_all, load) don't require token
     */
    if (in_array($action, $writeActions, true)) {
        $token = $_POST['bot_token'] ?? '';
        $honeypot = $_POST['confirm_action'] ?? ''; // Honeypot field

        if (!verifyBotToken($token, $honeypot)) {
            http_response_code(403);
            echo json_encode(['success' => false, 'message' => 'Security verification failed']);
            exit;
        }
    }

    /* Load wheels
     * PHP file_get_contents(): https://www.php.net/manual/en/function.file-get-contents.php
     * PHP json_decode(): https://www.php.net/manual/en/function.json-decode.php
     */
    $wheels = [];
    if (file_exists($wheelsFile)) {
        $content = @file_get_contents($wheelsFile);
        if ($content !== false) {
            $decoded = @json_decode($content, true);
            if (is_array($decoded)) {
                $wheels = $decoded;
            }
        }
    }

    if ($action === 'save') {
        /* Enforce maximum wheels limit
         */
        if (count($wheels) >= 200) {
            http_response_code(507);
            echo json_encode(['success' => false, 'message' => 'Maximum wheel limit reached (200).']);
            exit;
        }

        /* PHP htmlspecialchars() for XSS prevention
         * Reference: https://www.php.net/manual/en/function.htmlspecialchars.php
         */
        $name = htmlspecialchars(trim($_POST['name'] ?? ''), ENT_QUOTES, 'UTF-8');
        $items = json_decode($_POST['items'] ?? '[]', true);

        if (empty($name)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Name is required']);
            exit;
        }

        if (!validateItems($items)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid items format']);
            exit;
        }

        if (strlen(json_encode($items)) > 50000) {
            http_response_code(413);
            echo json_encode(['success' => false, 'message' => 'Wheel data too large']);
            exit;
        }

        /* PHP uniqid(): https://www.php.net/manual/en/function.uniqid.php
         */
        $id = uniqid('wheel_', true);

        $wheels[$id] = [
            'id' => $id,
            'name' => substr($name, 0, 100),
            'items' => $items,
            'created' => time()
        ];

        /* PHP json_encode()
         * Reference: https://www.php.net/manual/en/function.json-encode.php
         */
        $jsonData = json_encode($wheels, JSON_UNESCAPED_UNICODE);
        if ($jsonData === false) {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Encoding error']);
            exit;
        }

        /* PHP file_put_contents()
         * Reference: https://www.php.net/manual/en/function.file-put-contents.php
         */
        $bytesWritten = @file_put_contents($wheelsFile, $jsonData, LOCK_EX);

        if ($bytesWritten !== false) {
            @chmod($wheelsFile, 0644);
            echo json_encode(['success' => true, 'message' => 'Wheel saved', 'id' => $id]);
            flush();
        } else {
            http_response_code(500);
            echo json_encode(['success' => false, 'message' => 'Save failed']);
        }
        exit;
    }

    if ($action === 'load_all') {
        /* PHP array_values(): https://www.php.net/manual/en/function.array-values.php
         */
        echo json_encode(['success' => true, 'wheels' => array_values($wheels)]);
        exit;
    }

    if ($action === 'load') {
        $id = $_POST['id'] ?? '';https://github.com/CrazyTim/spin-wheel

        if (!validateWheelId($id)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid wheel ID']);
            exit;
        }

        if (isset($wheels[$id])) {
            echo json_encode(['success' => true, 'wheel' => $wheels[$id]]);
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Wheel not found']);
        }
        exit;
    }

    if ($action === 'delete') {
        $id = $_POST['id'] ?? '';

        if (!validateWheelId($id)) {
            http_response_code(400);
            echo json_encode(['success' => false, 'message' => 'Invalid wheel ID']);
            exit;
        }

        if (isset($wheels[$id])) {
            /* PHP unset(): https://www.php.net/manual/en/function.unset.php
             */
            unset($wheels[$id]);

            $jsonData = json_encode($wheels, JSON_UNESCAPED_UNICODE);
            if (@file_put_contents($wheelsFile, $jsonData, LOCK_EX) !== false) {
                @chmod($wheelsFile, 0644);
                echo json_encode(['success' => true, 'message' => 'Wheel deleted']);
                flush();
            } else {
                http_response_code(500);
                echo json_encode(['success' => false, 'message' => 'Delete failed']);
            }
        } else {
            http_response_code(404);
            echo json_encode(['success' => false, 'message' => 'Wheel not found']);
        }
        exit;
    }
}

if ($_SERVER['REQUEST_METHOD'] !== 'GET') {
    http_response_code(405);
    die('Method Not Allowed');
}

/* Generate token for page load
 */
$botToken = generateBotToken();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>Holtzweb - WheelSpin</title>
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" />
  <!-- <link rel="stylesheet" href="./inc/bootstrap.min.css" /> -->
  <link rel="shortcut icon" href="favicon.ico" type="image/x-icon">
  <style>
/* ============================= */
/* FLOATING BALLOON BACKGROUND  */
/* ============================= */

.wheel-container, .spin-btn, .text-center { z-index: 1; }
.col-lg-4 { z-index: 3; }


.text-center small { background-color: white; padding 1px; }

.balloon-background {
  position: fixed;
  inset: 0;
  overflow: hidden;
  z-index: -1; /* Behind content but above body background */
  pointer-events: none; /* Never block interaction */
}

.balloon-foreground {
  position: fixed;
  inset: 0;
  overflow: hidden;
  z-index: 1; /* Behind content but above body background */
  pointer-events: none; /* Never block interaction */
}

.balloon {
  position: absolute;
  bottom: -160px;
  width: 70px;
  opacity: 0.85;
  animation: floatUp linear infinite;
}

/* Horizontal placement */
.b1 { left: 8%; animation-duration: 18s; }
.b2 { left: 30%; animation-duration: 22s; }
.b3 { left: 60%; animation-duration: 20s; }
.b4 { left: 85%; animation-duration: 25s; }

/* Add slight animation offsets */
.b2 { animation-delay: 5s; }
.b3 { animation-delay: 9s; }
.b4 { animation-delay: 13s; }

/* Floating motion */
@keyframes floatUp {
  0% {
    transform: translateY(0) translateX(0);
  }
  25% {
    transform: translateY(-25vh) translateX(15px);
  }
  50% {
    transform: translateY(-50vh) translateX(-15px);
  }
  75% {
    transform: translateY(-75vh) translateX(10px);
  }
  100% {
    transform: translateY(-120vh) translateX(-10px);
  }
}

    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      min-height: 100vh;
      padding: 20px;
      padding-bottom: 80px;
    }

    .container {
      max-width: 1400px;
    }

    .header {
      text-align: center;
      color: white;
      margin-bottom: 30px;
    }

    .card {
      border-radius: 15px;
      box-shadow: 0 10px 30px rgba(0,0,0,0.2);
    }

    .wheel-container {
      width: 100%;
      max-width: 500px;
      height: 500px;
      margin: 0 auto;
      position: relative;
    }

    /* CSS Triangle Pointer
     * Reference: https://css-tricks.com/snippets/css/css-triangle/
     */
    .wheel-container::before {
      content: '';
      position: absolute;
      top: -35px;
      left: 50%;
      transform: translateX(-50%);
      width: 0;
      height: 0;
      border-left: 36px solid transparent;
      border-right: 36px solid transparent;
      border-top: 73px solid rgba(36, 12, 52, .7);
      z-index: 10;
    }

    /* CSS Animation Keyframes
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/@keyframes
     */
    @keyframes wiggle {
      0% { transform: translateX(-50%) rotate(0deg); }
      10% { transform: translateX(-50%) rotate(-15deg); }
      20% { transform: translateX(-50%) rotate(15deg); }
      30% { transform: translateX(-50%) rotate(-12deg); }
      40% { transform: translateX(-50%) rotate(12deg); }
      50% { transform: translateX(-50%) rotate(-18deg); }
      60% { transform: translateX(-50%) rotate(18deg); }
      70% { transform: translateX(-50%) rotate(-10deg); }
      80% { transform: translateX(-50%) rotate(10deg); }
      90% { transform: translateX(-50%) rotate(-5deg); }
      100% { transform: translateX(-50%) rotate(0deg); }
    }

    .wheel-container.spinning::before {
      animation: wiggle 0.3s ease-in-out infinite;
    }

    .spin-btn {
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      padding: 15px 40px;
      font-size: 1.2rem;
      font-weight: bold;
      border-radius: 50px;
      margin: 20px auto;
      display: block;
      cursor: pointer;
    }

    .spin-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    }

    .item-row {
      display: flex;
      gap: 10px;
      margin-bottom: 10px;
      align-items: center;
    }

    .color-dot {
      width: 40px;
      height: 40px;
      border-radius: 50%;
      cursor: pointer;
      border: 3px solid white;
      flex-shrink: 0;
    }

    .winner-modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.8);
      z-index: 9999;
      justify-content: center;
      align-items: center;
    }

    .winner-content {
      background: white;
      padding: 50px;
      border-radius: 20px;
      text-align: center;
    }

    .winner-content h2 {
      font-size: 2.5rem;
      color: #667eea;
    }

    .winner-name {
      font-size: 3rem;
      font-weight: bold;
      color: #764ba2;
      margin: 20px 0;
    }

    /* Bot detection modal styles
     */
    .bot-check-modal {
      display: none;
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      background: rgba(0,0,0,0.85);
      z-index: 10000;
      justify-content: center;
      align-items: center;
    }

    .bot-check-content {
      background: white;
      padding: 40px;
      border-radius: 15px;
      text-align: center;
      position: relative;
      max-width: 400px;
      width: 90%;
    }

    .bot-check-content h3 {
      font-size: 1.5rem;
      color: #333;
      margin-bottom: 20px;
    }

    .bot-check-content p {
      color: #666;
      margin-bottom: 30px;
    }

    /* Real confirm button - position randomizes
     * CSS position absolute for flexible placement
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/position
     */
    .bot-check-buttons {
      position: relative;
      height: 200px;
      width: 100%;
    }

    .real-confirm-btn {
      position: absolute;
      background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
      color: white;
      border: none;
      padding: 12px 40px;
      font-size: 1.1rem;
      font-weight: bold;
      border-radius: 25px;
      cursor: pointer;
      transition: all 0.3s;
      z-index: 20092;
    }

    .real-confirm-btn:hover {
      transform: scale(1.05);
      box-shadow: 0 5px 20px rgba(102, 126, 234, 0.4);
    }

    /* Honeypot buttons - invisible to humans, visible to bots
     * CSS opacity 0 makes invisible
     * CSS pointer-events none prevents accidental clicks
     * Position absolute overlays them
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/opacity
     */
    .honeypot-btn {
      position: absolute;
      opacity: 0;
      pointer-events: auto;
      background: #4CAF50;
      color: white;
      border: none;
      padding: 12px 40px;
      font-size: 1.1rem;
      border-radius: 25px;
      cursor: pointer;
    }

    /* Accessibility: screen readers should ignore honeypots
     * aria-hidden handled in HTML
     */

    footer {
      position: fixed;
      bottom: 0;
      left: 0;
      width: 100%;
      background: #16161D;
      color: white;
      text-align: center;
      padding: 15px;
      z-index: 22345;
    }

    footer img {
        width: auto;
        height: 50px;
    /* display: inline-block; */
    /* background-color : white; */
}

    footer a {
      color: white;
      text-decoration: none;
    }

    @media (max-width: 768px) {
      .wheel-container {
        height: 350px;
        max-width: 350px;
      }
    }
  </style>
</head>
<body>
<!-- Floating Balloon Background -->
<div class="balloon-background">
  <div class="balloon b1">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#FF6B6B"/>
      <polygon points="45,95 55,95 50,105" fill="#d94c4c"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>

  <div class="balloon b2">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#4ECDC4"/>
      <polygon points="45,95 55,95 50,105" fill="#36b3ab"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>

  <div class="balloon b3">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#F7DC6F"/>
      <polygon points="45,95 55,95 50,105" fill="#e6c22f"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>

  <div class="balloon b4">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#BB8FCE"/>
      <polygon points="45,95 55,95 50,105" fill="#9b59b6"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>
</div>




<div class="balloon-foreground">
  <div class="balloon b1">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#FF6B6B"/>
      <polygon points="45,95 55,95 50,105" fill="#d94c4c"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>

  <div class="balloon b2">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#4ECDC4"/>
      <polygon points="45,95 55,95 50,105" fill="#36b3ab"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>

  <div class="balloon b3">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#F7DC6F"/>
      <polygon points="45,95 55,95 50,105" fill="#e6c22f"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>

  <div class="balloon b4">
    <svg viewBox="0 0 100 140">
      <ellipse cx="50" cy="50" rx="35" ry="45" fill="#BB8FCE"/>
      <polygon points="45,95 55,95 50,105" fill="#9b59b6"/>
      <line x1="50" y1="105" x2="50" y2="140" stroke="#999" stroke-width="2"/>
    </svg>
  </div>
</div>





  <div class="container">
    <div class="header">
      <h1>🎡 WheelSpin </h1>
      <p>Add items and spin to pick a winner!</p>
    </div>

    <div class="row g-4">
      <div class="col-lg-8">
        <div class="card p-4">
          <div class="wheel-container" id="wheel-container"></div>
          <button class="spin-btn" id="spin-btn">SPIN THE WHEEL</button>
          <p class="text-center text-muted"><small>Drag the wheel or click the button!</small></p>
        </div>
      </div>

      <div class="col-lg-4">
        <div class="card p-4">
          <h5>Saved Wheels</h5>
          <div class="input-group mb-3">
            <select id="saved-wheels" class="form-select">
              <option value="">-- Select --</option>
            </select>
            <button class="btn btn-danger" id="delete-wheel-btn">🗑️</button>
          </div>

          <h5>Save Current</h5>
          <div class="input-group mb-3">
            <input type="text" id="wheel-name" class="form-control" placeholder="Wheel name..." maxlength="100" />
            <button class="btn btn-success" id="save-wheel-btn">💾</button>
          </div>

          <hr />

          <h5>Items</h5>
          <div id="items-list"></div>
          <button class="btn btn-primary w-100 mt-3" id="add-item-btn">+ Add Item</button>
        </div>
      </div>
    </div>
  </div>

  <div class="winner-modal" id="winner-modal">
    <div class="winner-content">
      <h2>🎉 Winner! 🎉</h2>
      <div class="winner-name" id="winner-name"></div>
      <button class="btn btn-primary" onclick="document.getElementById('winner-modal').style.display='none'">Close</button>
    </div>
  </div>

  <!-- Bot detection modal -->
  <div class="bot-check-modal" id="bot-check-modal">
    <div class="bot-check-content">
      <h3>🔒 Security Check</h3>
      <p id="bot-check-message">Please confirm you want to save this wheel</p>

      <div class="bot-check-buttons" id="bot-check-buttons">
        <!-- Real button position randomized by JavaScript -->
        <button class="real-confirm-btn" id="real-confirm-btn">Confirm</button>

        <!-- Honeypot buttons - invisible to humans, bots click these -->
        <button class="honeypot-btn" id="honeypot-1" aria-hidden="true" tabindex="-1" style="top: 20px; left: 50px;">OK</button>
        <button class="honeypot-btn" id="honeypot-2" aria-hidden="true" tabindex="-1" style="top: 80px; right: 60px;">Continue</button>
        <button class="honeypot-btn" id="honeypot-3" aria-hidden="true" tabindex="-1" style="bottom: 30px; left: 70px;">Submit</button>
      </div>
    </div>
  </div>

  <footer>
    <a href="https://www.holtzweb.com">
      <img src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBzdGFuZGFsb25lPSJubyI/Pgo8IURPQ1RZUEUgc3ZnIFBVQkxJQyAiLS8vVzNDLy9EVEQgU1ZHIDIwMDEwOTA0Ly9FTiIKICJodHRwOi8vd3d3LnczLm9yZy9UUi8yMDAxL1JFQy1TVkctMjAwMTA5MDQvRFREL3N2ZzEwLmR0ZCI+CjxzdmcgdmVyc2lvbj0iMS4wIiB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciCiB3aWR0aD0iMjMwLjAwMDAwMHB0IiBoZWlnaHQ9IjE2Mi4wMDAwMDBwdCIgdmlld0JveD0iMCAwIDIzMC4wMDAwMDAgMTYyLjAwMDAwMCIKIHByZXNlcnZlQXNwZWN0UmF0aW89InhNaWRZTWlkIG1lZXQiPgoKPGcgdHJhbnNmb3JtPSJ0cmFuc2xhdGUoMC4wMDAwMDAsMTYyLjAwMDAwMCkgc2NhbGUoMC4xMDAwMDAsLTAuMTAwMDAwKSIKZmlsbD0iIzAwMDAwMCIgc3Ryb2tlPSJub25lIj4KPHBhdGggZD0iTTE5MCAxMDcwIGwwIC00MDAgLTQwIDAgLTQwIDAgMCA4NSBjMCA4NCAwIDg1IC0yNSA4NSBsLTI1IDAgMCAtMTk1CjAgLTE5NSAyNSAwIGMyNSAwIDI1IDEgMjUgODUgbDAgODUgNDAgMCA0MCAwIDAgLTIzNSAwIC0yMzUgMTAzMCAwIDEwMzAgMCAwCjY2MCAwIDY2MCAtMTAzMCAwIC0xMDMwIDAgMCAtNDAweiBtMjAxMCAtMjYwIGwwIC02MTAgLTk4MCAwIC05ODAgMCAwIDEyNSBjMAo3NyA0IDEyNSAxMCAxMjUgNiAwIDEwIDcyIDEwIDE5NSAwIDEyMyAtNCAxOTUgLTEwIDE5NSAtNiAwIC0xMCAxMDMgLTEwIDI5MApsMCAyOTAgOTgwIDAgOTgwIDAgMCAtNjEweiIvPgo8cGF0aCBkPSJNMzczIDgxNiBjLTI3IC0yNCAtMjggLTI3IC0zMSAtMTQ2IC00IC0xNDIgMCAtMTYzIDM1IC0xOTYgMzggLTM1Cjk1IC0zMyAxMzQgNSBsMjkgMjkgMCAxMzcgMCAxMzcgLTI5IDI5IGMtMzkgMzggLTk3IDQwIC0xMzggNXogbTEwMSAtNDggYzIzCi0zMiAyMyAtMjE0IDAgLTI0NiAtMTcgLTI0IC00MyAtMjkgLTYyIC0xMCAtMTcgMTcgLTE3IDI0OSAwIDI2NiAxOSAxOSA0NSAxNAo2MiAtMTB6Ii8+CjxwYXRoIGQ9Ik02MjAgNjQ1IGwwIC0xOTUgNzAgMCBjNjggMCA3MCAxIDcwIDI1IDAgMjMgLTQgMjUgLTQwIDI1IGwtNDAgMCAwCjE3MCAwIDE3MCAtMzAgMCAtMzAgMCAwIC0xOTV6Ii8+CjxwYXRoIGQ9Ik04NTAgODE1IGMwIC0yMiA0IC0yNSAzNSAtMjUgbDM1IDAgMCAtMTcwIDAgLTE3MCAyNSAwIDI1IDAgMCAxNzAgMAoxNzAgNDAgMCBjMzYgMCA0MCAzIDQwIDI1IGwwIDI1IC0xMDAgMCAtMTAwIDAgMCAtMjV6Ii8+CjxwYXRoIGQ9Ik0xMTMwIDgxNSBjMCAtMjIgNCAtMjUgNDAgLTI1IDIyIDAgNDAgLTMgNDAgLTYgMCAtMyAtMTggLTY1IC00MAotMTM5IC0yMiAtNzQgLTQwIC0xNDggLTQwIC0xNjQgbDAgLTMxIDcwIDAgYzY4IDAgNzAgMSA3MCAyNSAwIDIzIC00IDI1IC00MAoyNSAtMjIgMCAtNDAgMyAtNDAgOCAwIDQgMTggNjggNDAgMTQyIDIyIDc0IDQwIDE0NyA0MCAxNjIgMCAyOCAwIDI4IC03MCAyOAotNjggMCAtNzAgLTEgLTcwIC0yNXoiLz4KPC9nPgo8L3N2Zz4K" alt="Holtzweb.com">
      <span><a href="https://www.holtzweb.com/spin">www.holtzweb.com/spin</a></span>
    </a>
  </footer>

  <script src="https://cdn.jsdelivr.net/npm/spin-wheel@5.0.2/dist/spin-wheel-iife.js"></script>
  <!-- <script src="./inc/spin-wheel-iife.js"></script> -->
  <script>
    console.log('Script loaded');

    /* Bot token from PHP session
     */
    const BOT_TOKEN = '<?php echo $botToken; ?>';

    let wheel = null;
    let items = [
      { label: 'Option 1', backgroundColor: '#FF6B6B', weight: 1 },
      { label: 'Option 2', backgroundColor: '#4ECDC4', weight: 1 },
      { label: 'Option 3', backgroundColor: '#45B7D1', weight: 1 },
      { label: 'Option 4', backgroundColor: '#FFA07A', weight: 1 }
    ];

    const colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#FFA07A', '#98D8C8', '#F7DC6F', '#BB8FCE', '#85C1E2'];

    /* Track pending action for bot check modal
     */
    let pendingAction = null;
    let honeypotClicked = false;

    function getContrastColor(hex) {
      const r = parseInt(hex.substr(1, 2), 16);
      const g = parseInt(hex.substr(3, 2), 16);
      const b = parseInt(hex.substr(5, 2), 16);
      return (r * 299 + g * 587 + b * 114) / 1000 > 155 ? '#000' : '#FFF';
    }

    /* Show bot check modal with randomized button position
     * Math.random(): https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Math/random
     * "Returns a floating-point, pseudo-random number in the range 0 to less than 1"
     */
    function showBotCheckModal(message, callback) {
      honeypotClicked = false;
      pendingAction = callback;

      const modal = document.getElementById('bot-check-modal');
      const messageEl = document.getElementById('bot-check-message');
      const realBtn = document.getElementById('real-confirm-btn');
      const container = document.getElementById('bot-check-buttons');

      messageEl.textContent = message;

      // FIX 1: Show modal FIRST so we can calculate the width correctly
      modal.style.display = 'flex';

      const containerHeight = 200;
      // Now this will get the actual width instead of 0
      const containerWidth = container.offsetWidth;
      const btnWidth = 120;
      const btnHeight = 40;

      // Ensure we don't get negative numbers if container is narrow
      const maxTop = Math.max(0, containerHeight - btnHeight);
      const maxLeft = Math.max(0, containerWidth - btnWidth);

      const randomTop = Math.floor(Math.random() * maxTop);
      const randomLeft = Math.floor(Math.random() * maxLeft);

      realBtn.style.top = randomTop + 'px';
      realBtn.style.left = randomLeft + 'px';
    }

    function hideBotCheckModal() {
      document.getElementById('bot-check-modal').style.display = 'none';
      pendingAction = null;
    }

    /* Honeypot button handlers - mark as bot if clicked
     */
    document.getElementById('honeypot-1').onclick = () => {
      console.log('Honeypot 1 clicked - bot detected');
      honeypotClicked = true;
      hideBotCheckModal();https://github.com/CrazyTim/spin-wheel
      alert('Security verification failed. Please try again.');
    };

    document.getElementById('honeypot-2').onclick = () => {
      console.log('Honeypot 2 clicked - bot detected');
      honeypotClicked = true;
      hideBotCheckModal();
      alert('Security verification failed. Please try again.');
    };

    document.getElementById('honeypot-3').onclick = () => {
      console.log('Honeypot 3 clicked - bot detected');
      honeypotClicked = true;
      hideBotCheckModal();
      alert('Security verification failed. Please try again.');
    };

/* Real confirm button handler */
document.getElementById('real-confirm-btn').onclick = () => {
  if (honeypotClicked) {
    alert('Security verification failed.');
    hideBotCheckModal();
    return;
  }

  // FIX: Save the action to a local variable BEFORE hiding the modal
  const actionToExecute = pendingAction;

  // This will clear the global 'pendingAction' variable
  hideBotCheckModal();

  // Now execute the saved action
  if (actionToExecute) {
    actionToExecute();
  }
};

    function createWheel() {
      console.log('Creating wheel with items:', items);
      const container = document.getElementById('wheel-container');

      if (wheel) {
        /* Spin Wheel Documentation: "remove()"
         * https://github.com/CrazyTim/spin-wheel#methods-for-wheel
         */
        wheel.remove();
      }

      try {
        /* Spin Wheel Documentation: "constructor(container, props = {})"
         * https://github.com/CrazyTim/spin-wheel#methods-for-wheel
         */
        wheel = new spinWheel.Wheel(container, {
          items: items.map(item => ({
            label: item.label,
            backgroundColor: item.backgroundColor,
            labelColor: getContrastColor(item.backgroundColor)
          })),
          radius: 0.9,
          itemLabelRadius: 0.9,
          itemLabelRadiusMax: 0.3,
          itemLabelRotation: 180,
          itemLabelAlign: 'left',
          itemLabelFontSizeMax: 50,
          rotationSpeedMax: 500,
          rotationResistance: -100,
          lineWidth: 2,
          lineColor: '#fff',
          isInteractive: true,
          onRest: (e) => {
            /* Spin Wheel Documentation: "onRest(event = {})"
             * https://github.com/CrazyTim/spin-wheel#events-for-wheel
             */
            console.log('Wheel stopped at index:', e.currentIndex);
            showWinner(items[e.currentIndex].label);
            document.getElementById('spin-btn').disabled = false;

            /* DOM classList API: https://developer.mozilla.org/en-US/docs/Web/API/Element/classList
             */
            container.classList.remove('spinning');
          }
        });
        console.log('Wheel created successfully');
      } catch (error) {
        console.error('Error creating wheel:', error);
        alert('Error creating wheel: ' + error.message);
      }
    }

    function renderItems() {
      const container = document.getElementById('items-list');
      container.innerHTML = '';

      items.forEach((item, i) => {
        const row = document.createElement('div');
        row.className = 'item-row';

        const dot = document.createElement('div');
        dot.className = 'color-dot';
        dot.style.backgroundColor = item.backgroundColor;
        dot.onclick = () => {
          const newColor = prompt('Enter hex color (e.g., #FF6B6B):', item.backgroundColor);
          if (newColor && /^#[0-9A-F]{6}$/i.test(newColor)) {
            items[i].backgroundColor = newColor;
            createWheel();
            renderItems();
          }
        };

        const input = document.createElement('input');
        input.type = 'text';
        input.className = 'form-control';
        input.value = item.label;
        input.maxLength = 200;
        input.onchange = (e) => {
          items[i].label = e.target.value;
          createWheel();
        };

        const removeBtn = document.createElement('button');
        removeBtn.className = 'btn btn-danger btn-sm';
        removeBtn.textContent = '✕';
        removeBtn.onclick = () => {
          if (items.length <= 2) {
            alert('Need at least 2 items!');
            return;
          }
          items.splice(i, 1);
          createWheel();
          renderItems();
        };

        row.appendChild(dot);
        row.appendChild(input);
        row.appendChild(removeBtn);
        container.appendChild(row);
      });
    }

    function showWinner(name) {
      /* textContent for XSS prevention
       * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent
       */
      document.getElementById('winner-name').textContent = name;
      document.getElementById('winner-modal').style.display = 'flex';
    }

    document.getElementById('add-item-btn').onclick = () => {
      console.log('Add item clicked');

      if (items.length >= 50) {
        alert('Maximum 50 items per wheel');
        return;
      }

      items.push({
        label: `Option ${items.length + 1}`,
        backgroundColor: colors[items.length % colors.length],
        weight: 1
      });
      createWheel();
      renderItems();
    };

    document.getElementById('spin-btn').onclick = () => {
      console.log('Spin clicked');
      if (items.length < 2) {
        alert('Add at least 2 items!');
        return;
      }
      document.getElementById('spin-btn').disabled = true;

      /* DOM classList API: https://developer.mozilla.org/en-US/docs/Web/API/Element/classList
       */
      const container = document.getElementById('wheel-container');
      container.classList.add('spinning');

      /* Spin Wheel Documentation: "spinToItem(itemIndex, duration, spinToCenter, numberOfRevolutions, direction, easingFunction)"
       * https://github.com/CrazyTim/spin-wheel#methods-for-wheel
       */
      const randomIndex = Math.floor(Math.random() * items.length);
      wheel.spinToItem(randomIndex, 4000, true, 3 + Math.floor(Math.random() * 3), 1);
    };

    /* Save with bot check
     */
    /* Save with bot check */
    document.getElementById('save-wheel-btn').onclick = () => {
      const name = document.getElementById('wheel-name').value.trim();
      if (!name) {
        alert('Enter a name!');
        return;
      }

      /* Show bot check modal before save */
      showBotCheckModal('Please confirm you want to save this wheel', async () => {
        const formData = new FormData();
        formData.append('action', 'save');
        formData.append('name', name);
        formData.append('items', JSON.stringify(items));
        formData.append('bot_token', BOT_TOKEN);
        formData.append('confirm_action', honeypotClicked ? 'clicked' : '');

        try {
          const response = await fetch(window.location.href, { method: 'POST', body: formData });

          if (response.status === 403) {
            // FIX 2: Text is on one line to prevent syntax error
            alert('Security check failed. Please refresh the page and try again.');
            return;
          }

          if (response.status === 429) {
            alert('Too many requests. Please wait a moment and try again.');
            return;
          }

          if (response.status === 507) {
            alert('Server is full (max 200 wheels). Try again later.');
            return;
          }

          if (!response.ok) {
            // FIX 3: Text is on one line
            alert('Server error. Save might have worked - refresh to check.');
            loadSavedWheels();
            return;
          }

          const contentType = response.headers.get('content-type');
          if (!contentType || !contentType.includes('application/json')) {
            alert('Saved! (Non-JSON response)');
            document.getElementById('wheel-name').value = '';
            loadSavedWheels();
            return;
          }

          const result = await response.json();
          if (result.success) {
            alert('Saved!');
            document.getElementById('wheel-name').value = '';
            loadSavedWheels();
            // Refresh page to get new token
            setTimeout(() => location.reload(), 500);
          } else {
            alert('Error: ' + result.message);
          }
        } catch (error) {
          console.error('Save error:', error);
          alert('Network error. Save might have worked - refresh to check.');
          loadSavedWheels();
        }
      });
    };

    async function loadSavedWheels() {
      const formData = new FormData();
      formData.append('action', 'load_all');

      try {
        const response = await fetch(window.location.href, { method: 'POST', body: formData });

        if (!response.ok) {
          console.error('Load failed with status:', response.status);
          return;
        }

        const result = await response.json();
        if (result.success) {
          const select = document.getElementById('saved-wheels');
          select.innerHTML = '<option value="">-- Select --</option>';
          result.wheels.forEach(w => {
            const option = document.createElement('option');
            option.value = w.id;
            /* textContent for XSS prevention
             * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent
             */
            option.textContent = w.name;
            select.appendChild(option);
          });
        }
      } catch (error) {
        console.error('Error loading wheels:', error);
      }
    }

    document.getElementById('saved-wheels').onchange = async (e) => {
      const id = e.target.value;
      if (!id) return;

      const formData = new FormData();
      formData.append('action', 'load');
      formData.append('id', id);

      try {
        const response = await fetch(window.location.href, { method: 'POST', body: formData });
        const result = await response.json();
        if (result.success) {
          items = result.wheel.items;
          createWheel();
          renderItems();
        }
      } catch (error) {
        alert('Error: ' + error.message);
      }
    };

    /* Delete with bot check
     */
    document.getElementById('delete-wheel-btn').onclick = () => {
      const id = document.getElementById('saved-wheels').value;
      if (!id) {
        alert('Select a wheel first!');
        return;
      }
      if (!confirm('Delete this wheel?')) return;

      /* Show bot check modal before delete
       */
      showBotCheckModal('Please confirm you want to delete this wheel', async () => {
        const formData = new FormData();
        formData.append('action', 'delete');
        formData.append('id', id);
        formData.append('bot_token', BOT_TOKEN);
        formData.append('confirm_action', honeypotClicked ? 'clicked' : '');

        try {
          const response = await fetch(window.location.href, { method: 'POST', body: formData });

          if (response.status === 403) {
            alert('Security check failed. Please refresh the page and try again.');
            return;
          }

          if (response.status === 429) {
            alert('Too many requests. Please wait a moment and try again.');
            return;
          }

          if (!response.ok) {
            alert('Deleted! (Server timeout, but delete might have worked)');
            document.getElementById('saved-wheels').value = '';
            loadSavedWheels();
            return;
          }

          const result = await response.json();
          if (result.success) {
            alert('Deleted!');
            document.getElementById('saved-wheels').value = '';
            loadSavedWheels();
            // Refresh page to get new token
            setTimeout(() => location.reload(), 500);
          }
        } catch (error) {
          alert('Network error. Refresh to see if delete worked.');
          loadSavedWheels();
        }
      });
    };

    /* Window load event: https://developer.mozilla.org/en-US/docs/Web/API/Window/load_event
     */
    window.addEventListener('load', () => {
      console.log('Page loaded, checking spinWheel:', typeof spinWheel);
      if (typeof spinWheel === 'undefined') {
        alert('ERROR: Spin Wheel library failed to load!');
        return;
      }
      createWheel();
      renderItems();
      loadSavedWheels();
    });
  </script>




</body>
</html>
