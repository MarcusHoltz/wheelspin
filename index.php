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
        $id = $_POST['id'] ?? '';

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
      position: relative;
      overflow: hidden;
      transition: transform 0.15s ease, box-shadow 0.15s ease;
    }

    .spin-btn:hover {
      transform: translateY(-2px);
      box-shadow: 0 5px 15px rgba(0,0,0,0.3);
    }

    /* === Button press animations ===
     *
     * Three layered effects all driven by CSS, triggered by adding .btn-fired via JS.
     *
     * 1. btn-pop: scale down then spring back (physical press feel)
     *    Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/animation
     *
     * 2. btn-glow: outer glow pulse radiating outward from the button
     *    Uses box-shadow expansion + opacity fade.
     *
     * 3. .ripple span: strong white radial burst from the exact click point,
     *    larger and more opaque than before, clipped by overflow:hidden.
     *
     * The .btn-fired class is added on click and removed by animationend (JS).
     */
    .spin-btn.btn-fired {
      animation: btn-pop 0.4s cubic-bezier(0.36, 0.07, 0.19, 0.97) both,
                 btn-glow 0.5s ease-out both;
    }

    @keyframes btn-pop {
      0%   { transform: scale(1); }
      20%  { transform: scale(0.91); }
      55%  { transform: scale(1.06); }
      80%  { transform: scale(0.97); }
      100% { transform: scale(1); }
    }

    @keyframes btn-glow {
      0%   { box-shadow: 0 0 0 0 rgba(255,255,255,0.85); }
      40%  { box-shadow: 0 0 0 18px rgba(255,255,255,0.25); }
      100% { box-shadow: 0 0 0 36px rgba(255,255,255,0); }
    }

    /* Shine sweep — a white diagonal highlight that slides across the button.
     * Implemented via a ::before pseudo-element on .btn-fired.
     * skewX(-20deg) gives the angled edge; translateX(-150%) to translateX(250%)
     * moves it fully across the button width.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/transform-function/skewX
     */
    .spin-btn::before {
      content: '';
      position: absolute;
      top: 0; left: 0;
      width: 60%;
      height: 100%;
      background: linear-gradient(120deg, rgba(255,255,255,0) 30%, rgba(255,255,255,0.55) 50%, rgba(255,255,255,0) 70%);
      transform: skewX(-20deg) translateX(-150%);
      pointer-events: none;
    }
    .spin-btn.btn-fired::before {
      animation: btn-shine 0.45s ease-out forwards;
    }
    @keyframes btn-shine {
      to { transform: skewX(-20deg) translateX(250%); }
    }

    /* Ripple: strong white burst from click point */
    .spin-btn .ripple {
      position: absolute;
      border-radius: 50%;
      transform: scale(0);
      background: rgba(255, 255, 255, 0.75);
      animation: ripple-fade 0.6s linear;
      pointer-events: none;
    }
    @keyframes ripple-fade {
      to {
        transform: scale(4);
        opacity: 0;
      }
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

    /* Bezier particle burst canvas — fires on winner Close button click.
     * Fixed full-screen so particle coordinates map directly to screen pixels.
     * pointer-events:none — must never block interaction with the page underneath.
     * z-index 10002: above confetti (10001) so both can coexist without clipping.
     * Canvas is resized to match the viewport on each trigger call.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D
     */
    #drawing_canvas {
      position: fixed;
      top: 0;
      left: 0;
      width: 100%;
      height: 100%;
      pointer-events: none;
      z-index: 10002;
    }

    /* Confetti overlay — sits above winner-modal (z-index:9999) and bot-check-modal (z-index:10000)
     * pointer-events:none lets the Close button remain clickable through the canvas.
     * No display:none used — a hidden div has offsetWidth/Height of 0, which would
     * cause the canvas to initialize at 0x0 pixels and never size correctly.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/pointer-events
     */
    #confetti {
      height: 100%;
      left: 0;
      position: fixed;
      top: 0;
      width: 100%;
      z-index: 10001;
      pointer-events: none;
    }

    /* =====================================================
     * DARK MODE
     * Applied by adding .dark-mode to <body>.
     * CSS custom properties cascade so Bootstrap components
     * and our own card/input styles all pick up the overrides.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/Using_CSS_custom_properties
     * ===================================================== */
    body.dark-mode {
      background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
    }
    body.dark-mode .card {
      background-color: #1e1e2e;
      color: #e0e0e0;
      box-shadow: 0 10px 30px rgba(0,0,0,0.5);
    }
    body.dark-mode .card h5,
    body.dark-mode .card p,
    body.dark-mode .card small,
    body.dark-mode .card label {
      color: #c0c0d0;
    }
    body.dark-mode .form-control,
    body.dark-mode .form-select {
      background-color: #2a2a3e;
      color: #e0e0e0;
      border-color: #444466;
    }
    body.dark-mode .form-control::placeholder {
      color: #8888aa;
    }
    body.dark-mode .text-muted {
      color: #8888aa !important;
    }
    body.dark-mode .text-center small {
      background-color: transparent;
      color: #8888aa;
    }
    body.dark-mode .winner-content,
    body.dark-mode .bot-check-content {
      background: #1e1e2e;
      color: #e0e0e0;
    }
    body.dark-mode .winner-content h2 {
      color: #a78bfa;
    }
    body.dark-mode .winner-name {
      color: #c4b5fd;
    }
    body.dark-mode .bot-check-content h3 {
      color: #e0e0e0;
    }
    body.dark-mode .bot-check-content p {
      color: #a0a0b8;
    }
    body.dark-mode footer {
      background: #0d0d1a;
    }

    /* Dark mode toggle button — fixed upper-right, always accessible.
     * Uses a sun/moon icon that swaps via CSS content based on body class.
     * z-index above page content but below modals (9999).
     * Reference: https://developer.mozilla.org/en-US/docs/Web/CSS/position
     */
    #dark-mode-toggle {
      position: fixed;
      top: 16px;
      right: 20px;
      z-index: 9000;
      width: 42px;
      height: 42px;
      border-radius: 50%;
      border: 2px solid rgba(255,255,255,0.6);
      background: rgba(255,255,255,0.15);
      backdrop-filter: blur(6px);
      cursor: pointer;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 1.3rem;
      transition: background 0.3s, border-color 0.3s, transform 0.2s;
      user-select: none;
    }
    #dark-mode-toggle:hover {
      background: rgba(255,255,255,0.28);
      transform: scale(1.1);
    }
    body.dark-mode #dark-mode-toggle {
      border-color: rgba(180,160,255,0.6);
      background: rgba(30,30,60,0.7);
    }
    body.dark-mode #dark-mode-toggle:hover {
      background: rgba(60,60,100,0.85);
    }
  </style>
</head>
<body>

<!-- Dark mode toggle — fixed upper-right corner.
     Icon swaps between moon (light mode) and sun (dark mode) via JS.
     aria-label provides accessibility for screen readers.
     Reference: https://developer.mozilla.org/en-US/docs/Web/Accessibility/ARIA/Attributes/aria-label -->
<button id="dark-mode-toggle" aria-label="Toggle dark mode" title="Toggle dark mode">🌙</button>

<!-- Confetti canvas target — populated by confetti script on jQuery ready -->
<div id="confetti"></div>

<!-- Bezier particle burst canvas — populated by closeWinner() on Close click -->
<canvas id="drawing_canvas"></canvas>

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
      <button class="btn btn-primary" onclick="closeWinner(this)">Close</button>
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
      hideBotCheckModal();
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

    /* closeWinner — hides the winner modal then fires the bezier particle burst
     * from the screen position of the Close button that was clicked.
     * window.triggerBezierBurst is assigned by the canvas particle script below.
     */
    function closeWinner(btn) {
      /* Capture rect BEFORE hiding the modal.
       * getBoundingClientRect() returns all zeros once display:none is applied —
       * that was causing the burst to originate from (0,0), i.e. the top-left corner.
       * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Element/getBoundingClientRect
       */
      if (typeof window.triggerBezierBurst === 'function') {
        var rect = btn.getBoundingClientRect();
        window.triggerBezierBurst(
          rect.left + rect.width  * 0.5,
          rect.top  + rect.height * 0.5
        );
      }
      document.getElementById('winner-modal').style.display = 'none';
    }

    function showWinner(name) {
      /* textContent for XSS prevention
       * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Node/textContent
       */
      document.getElementById('winner-name').textContent = name;
      document.getElementById('winner-modal').style.display = 'flex';

      /* CONFETTI_SPAWN_MS: how long the whole animation runs before draining.
       * One timer, one variable. When it fires, papers stop spawning normally.
       * Ribbons that are still above the viewport get moved to y=0 so they
       * enter and exit quickly rather than taking 20+ seconds off-screen.
       * Ribbons already visible on screen finish falling naturally.
       */
      var CONFETTI_SPAWN_MS = 2500;

      if (window.confettiAnim) {
        window.confettiAnim.start();
        setTimeout(function () {
          window.confettiAnim.drain();
        }, CONFETTI_SPAWN_MS);
      }
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

    document.getElementById('spin-btn').onclick = (event) => {
      /* Three CSS animations fire via .btn-fired class (pop, glow, shine).
       * Ripple span is still injected for the click-point burst.
       * .btn-fired is removed once the longest animation (glow, 0.5s) ends.
       * Reference: https://developer.mozilla.org/en-US/docs/Web/API/Element/classList
       */
      const btn  = document.getElementById('spin-btn');
      const rect = btn.getBoundingClientRect();

      btn.classList.remove('btn-fired');
      void btn.offsetWidth; /* force reflow so re-clicking restarts the animation */
      btn.classList.add('btn-fired');
      btn.addEventListener('animationend', () => btn.classList.remove('btn-fired'), { once: true });

      const circle = document.createElement('span');
      const size   = Math.max(rect.width, rect.height);
      circle.className    = 'ripple';
      circle.style.width  = circle.style.height = size + 'px';
      circle.style.left   = (event.clientX - rect.left - size / 2) + 'px';
      circle.style.top    = (event.clientY - rect.top  - size / 2) + 'px';
      btn.appendChild(circle);
      circle.addEventListener('animationend', () => circle.remove());

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

  <!-- Bezier particle burst — adapted from original by Tom Patricio / Codepen.
       Modifications from the source:
         1. Phase 0 (Loader circle) removed entirely — we go straight to particles.
         2. Phase 1 (Exploader shrink) removed entirely — same reason.
         3. Canvas is sized to the full viewport on each trigger call so screen-space
            coordinates from getBoundingClientRect() map 1:1 to canvas pixels.
         4. Particle origin is passed in as (originX, originY) from closeWinner()
            instead of always using the canvas centre.
         5. Animation loop stops and clears the canvas once all particles complete
            rather than looping forever.
         6. window.triggerBezierBurst() exposes the trigger to closeWinner() above.
       Easing equations from http://gizma.com/easing/ — included verbatim. -->
  <script>
  (function () {

    var TWO_PI  = Math.PI * 2;
    var HALF_PI = Math.PI * 0.5;
    var timeStep = 1 / 60;

    var drawingCanvas = document.getElementById('drawing_canvas');
    var ctx;
    var viewWidth, viewHeight;
    var particles = [];
    var rafId     = null;  /* requestAnimationFrame handle for cancellation */

    function Point(x, y) {
      this.x = x || 0;
      this.y = y || 0;
    }

    /* Particle travels along a cubic bezier path with a wobble (sy) on the minor axis.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/API/CanvasRenderingContext2D/fillRect
     */
    function Particle(p0, p1, p2, p3) {
      this.p0 = p0; this.p1 = p1; this.p2 = p2; this.p3 = p3;
      this.time     = 0;
      this.duration = 3 + Math.random() * 2;
      this.color    = '#' + Math.floor(Math.random() * 0xffffff).toString(16).padStart(6, '0');
      this.w        = 8;
      this.h        = 6;
      this.complete = false;
    }

    Particle.prototype = {
      update: function () {
        this.time = Math.min(this.duration, this.time + timeStep);
        var f  = Ease.outCubic(this.time, 0, 1, this.duration);
        var p  = cubeBezier(this.p0, this.p1, this.p2, this.p3, f);
        var dx = p.x - this.x;
        var dy = p.y - this.y;
        this.r    = Math.atan2(dy, dx) + HALF_PI;
        this.sy   = Math.sin(Math.PI * f * 10);
        this.x    = p.x;
        this.y    = p.y;
        this.complete = (this.time === this.duration);
      },
      draw: function () {
        ctx.save();
        ctx.translate(this.x, this.y);
        ctx.rotate(this.r);
        ctx.scale(1, this.sy);
        ctx.fillStyle = this.color;
        ctx.fillRect(-this.w * 0.5, -this.h * 0.5, this.w, this.h);
        ctx.restore();
      }
    };

    var Ease = {
      outCubic: function (t, b, c, d) {
        t /= d; t--;
        return c * (t * t * t + 1) + b;
      }
    };

    /* Cubic bezier interpolation
     * Reference: https://en.wikipedia.org/wiki/B%C3%A9zier_curve#Cubic_B%C3%A9zier_curves
     */
    function cubeBezier(p0, c0, c1, p1, t) {
      var p  = new Point();
      var nt = 1 - t;
      p.x = nt*nt*nt*p0.x + 3*nt*nt*t*c0.x + 3*nt*t*t*c1.x + t*t*t*p1.x;
      p.y = nt*nt*nt*p0.y + 3*nt*nt*t*c0.y + 3*nt*t*t*c1.y + t*t*t*p1.y;
      return p;
    }

    function checkParticlesComplete() {
      for (var i = 0; i < particles.length; i++) {
        if (!particles[i].complete) return false;
      }
      return true;
    }

    function createParticles(originX, originY) {
      particles.length = 0;
      for (var i = 0; i < 128; i++) {
        var p0 = new Point(originX, originY);
        var p1 = new Point(Math.random() * viewWidth,  Math.random() * viewHeight);
        var p2 = new Point(Math.random() * viewWidth,  Math.random() * viewHeight);
        /* End point below the viewport so particles always fall off-screen */
        var p3 = new Point(Math.random() * viewWidth,  viewHeight + 64);
        particles.push(new Particle(p0, p1, p2, p3));
      }
    }

    function loop() {
      ctx.clearRect(0, 0, viewWidth, viewHeight);

      particles.forEach(function (p) { p.update(); });
      particles.forEach(function (p) { p.draw();   });

      if (checkParticlesComplete()) {
        /* All particles finished — clear canvas and stop the loop */
        ctx.clearRect(0, 0, viewWidth, viewHeight);
        rafId = null;
        return;
      }

      /* requestAnimationFrame reference:
       * https://developer.mozilla.org/en-US/docs/Web/API/Window/requestAnimationFrame
       */
      rafId = requestAnimationFrame(loop);
    }

    /* Public trigger — called by closeWinner() with the button's screen-space centre.
     * Canvas is resized to the current viewport each call so coordinates stay accurate
     * if the window has been resized since the page loaded.
     * If a previous burst is still running, cancel it cleanly before starting a new one.
     */
    window.triggerBezierBurst = function (originX, originY) {
      if (rafId !== null) {
        cancelAnimationFrame(rafId);
        rafId = null;
      }

      viewWidth  = window.innerWidth;
      viewHeight = window.innerHeight;
      drawingCanvas.width  = viewWidth;
      drawingCanvas.height = viewHeight;
      ctx = drawingCanvas.getContext('2d');

      createParticles(originX, originY);
      rafId = requestAnimationFrame(loop);
    };

  }());
  </script>

  <!-- jQuery required by confetti script below
       Reference: https://api.jquery.com/ready/ -->
  <script src="https://code.jquery.com/jquery-1.11.0.js"></script>

  <!-- Confetti — adapted from Patrik Svensson (http://metervara.net)
       Two modifications from the original source:
         1. Instance stored on window.confettiAnim instead of a closure-local var
            so showWinner() (vanilla JS, outside this jQuery scope) can call
            .start() and .stop() on demand.
         2. Auto-start removed — confetti only runs when showWinner() triggers it. -->
  <script>
  $(document).ready(function () {
    var frameRate = 30;
    var dt = 1.0 / frameRate;
    var DEG_TO_RAD = Math.PI / 180;
    var colors = [
      ['#df0049', '#660671'],
      ['#00e857', '#005291'],
      ['#2bebbc', '#05798a'],
      ['#ffd200', '#b06c00']
    ];

    function Vector2(_x, _y) {
      this.x = _x; this.y = _y;
      this.Length = function () { return Math.sqrt(this.x * this.x + this.y * this.y); };
      this.Add = function (_v) { this.x += _v.x; this.y += _v.y; };
      this.Sub = function (_v) { this.x -= _v.x; this.y -= _v.y; };
      this.Div = function (_f) { this.x /= _f; this.y /= _f; };
      this.Mul = function (_f) { this.x *= _f; this.y *= _f; };
      this.Normalized = function () {
        var sq = this.x * this.x + this.y * this.y;
        if (sq !== 0) { var f = 1.0 / Math.sqrt(sq); return new Vector2(this.x * f, this.y * f); }
        return new Vector2(0, 0);
      };
    }
    Vector2.Sub = function (_a, _b) { return new Vector2(_a.x - _b.x, _a.y - _b.y); };

    function EulerMass(_x, _y, _mass, _drag) {
      this.position = new Vector2(_x, _y);
      this.mass = _mass; this.drag = _drag;
      this.force = new Vector2(0, 0);
      this.velocity = new Vector2(0, 0);
      this.AddForce = function (_f) { this.force.Add(_f); };
      this.Integrate = function (_dt) {
        var acc = new Vector2(this.force.x, this.force.y);
        var speed = Math.sqrt(this.velocity.x * this.velocity.x + this.velocity.y * this.velocity.y);
        var drag = new Vector2(this.velocity.x, this.velocity.y);
        drag.Mul(this.drag * this.mass * speed);
        acc.Sub(drag);
        acc.Div(this.mass);
        var pos = new Vector2(this.velocity.x, this.velocity.y);
        pos.Mul(_dt);
        this.position.Add(pos);
        acc.Mul(_dt);
        this.velocity.Add(acc);
        this.force = new Vector2(0, 0);
      };
    }

    function ConfettiPaper(_x, _y) {
      this.pos = new Vector2(_x, _y);
      this.rotationSpeed = Math.random() * 600 + 800;
      this.angle = DEG_TO_RAD * Math.random() * 360;
      this.rotation = DEG_TO_RAD * Math.random() * 360;
      this.cosA = 1.0;
      this.size = 5.0;
      this.oscillationSpeed = Math.random() * 1.5 + 0.5;
      this.xSpeed = 40.0;
      this.ySpeed = Math.random() * 60 + 50.0;
      this.corners = [];
      this.time = Math.random();
      var ci = Math.round(Math.random() * (colors.length - 1));
      this.frontColor = colors[ci][0];
      this.backColor = colors[ci][1];
      for (var i = 0; i < 4; i++) {
        this.corners[i] = new Vector2(
          Math.cos(this.angle + DEG_TO_RAD * (i * 90 + 45)),
          Math.sin(this.angle + DEG_TO_RAD * (i * 90 + 45))
        );
      }
      this.Update = function (_dt) {
        this.time += _dt;
        this.rotation += this.rotationSpeed * _dt;
        this.cosA = Math.cos(DEG_TO_RAD * this.rotation);
        this.pos.x += Math.cos(this.time * this.oscillationSpeed) * this.xSpeed * _dt;
        this.pos.y += this.ySpeed * _dt;
        if (this.pos.y > ConfettiPaper.bounds.y) {
          /* Only respawn if spawning is active.
           * When draining, let pieces fall off and stay off.
           */
          if (ConfettiPaper.spawning) {
            this.pos.x = Math.random() * ConfettiPaper.bounds.x;
            this.pos.y = 0;
          }
        }
      };
      this.Draw = function (_g) {
        _g.fillStyle = this.cosA > 0 ? this.frontColor : this.backColor;
        _g.beginPath();
        _g.moveTo(this.pos.x + this.corners[0].x * this.size, this.pos.y + this.corners[0].y * this.size * this.cosA);
        for (var i = 1; i < 4; i++) {
          _g.lineTo(this.pos.x + this.corners[i].x * this.size, this.pos.y + this.corners[i].y * this.size * this.cosA);
        }
        _g.closePath();
        _g.fill();
      };
    }
    ConfettiPaper.bounds = new Vector2(0, 0);
    /* spawning flag checked in Update() — false means pieces are not reset when they fall off.
     * Declared as a property on the constructor (static) so all instances share one value.
     */
    ConfettiPaper.spawning = false;

    function ConfettiRibbon(_x, _y, _count, _dist, _thick, _angle, _mass, _drag) {
      this.particleDist = _dist; this.particleCount = _count;
      this.particleMass = _mass; this.particleDrag = _drag;
      this.particles = [];
      var ci = Math.round(Math.random() * (colors.length - 1));
      this.frontColor = colors[ci][0]; this.backColor = colors[ci][1];
      this.xOff = Math.cos(DEG_TO_RAD * _angle) * _thick;
      this.yOff = Math.sin(DEG_TO_RAD * _angle) * _thick;
      this.position = new Vector2(_x, _y);
      this.prevPosition = new Vector2(_x, _y);
      this.velocityInherit = Math.random() * 2 + 4;
      this.time = Math.random() * 100;
      this.oscillationSpeed = Math.random() * 2 + 2;
      this.oscillationDistance = Math.random() * 40 + 40;
      this.ySpeed = Math.random() * 80 + 160; /* 2x original 80-120 range */
      for (var i = 0; i < _count; i++) {
        this.particles[i] = new EulerMass(_x, _y - i * _dist, _mass, _drag);
      }
      this.Reset = function () {
        this.done = false;
        this.position.y = -Math.random() * ConfettiRibbon.bounds.y;
        this.position.x = Math.random() * ConfettiRibbon.bounds.x;
        this.prevPosition = new Vector2(this.position.x, this.position.y);
        this.velocityInherit = Math.random() * 2 + 4;
        this.time = Math.random() * 100;
        this.oscillationSpeed = Math.random() * 2.0 + 1.5;
        this.oscillationDistance = Math.random() * 40 + 40;
        this.ySpeed = Math.random() * 80 + 160; /* 2x original 80-120 range */
        var ci2 = Math.round(Math.random() * (colors.length - 1));
        this.frontColor = colors[ci2][0]; this.backColor = colors[ci2][1];
        this.particles = [];
        for (var i = 0; i < this.particleCount; i++) {
          this.particles[i] = new EulerMass(this.position.x, this.position.y - i * this.particleDist, this.particleMass, this.particleDrag);
        }
      };
      this.Update = function (_dt) {
        var i;
        this.time += _dt * this.oscillationSpeed;
        this.position.y += this.ySpeed * _dt;
        this.position.x += Math.cos(this.time) * this.oscillationDistance * _dt;
        this.particles[0].position = this.position;
        var dX = this.prevPosition.x - this.position.x;
        var dY = this.prevPosition.y - this.position.y;
        var delta = Math.sqrt(dX * dX + dY * dY);
        this.prevPosition = new Vector2(this.position.x, this.position.y);
        for (i = 1; i < this.particleCount; i++) {
          var dirP = Vector2.Sub(this.particles[i - 1].position, this.particles[i].position);
          dirP = dirP.Normalized();
          dirP.Mul((delta / _dt) * this.velocityInherit);
          this.particles[i].AddForce(dirP);
        }
        for (i = 1; i < this.particleCount; i++) { this.particles[i].Integrate(_dt); }
        for (i = 1; i < this.particleCount; i++) {
          var rp2 = new Vector2(this.particles[i].position.x, this.particles[i].position.y);
          rp2.Sub(this.particles[i - 1].position);
          var n = rp2.Normalized(); n.Mul(this.particleDist); n.Add(this.particles[i - 1].position);
          this.particles[i].position = n;
        }
        if (this.position.y > ConfettiRibbon.bounds.y + this.particleDist * this.particleCount) {
          if (ConfettiRibbon.spawning) {
            this.Reset();
          } else {
            /* Drain mode: lead has exited. Mark done so the context skips
             * Update and Draw for this ribbon, stopping the tail particles
             * from continuing to render on-screen due to physics lag.
             */
            this.done = true;
          }
        }
      };
      this.Side = function (x1, y1, x2, y2, x3, y3) {
        return (x1 - x2) * (y3 - y2) - (y1 - y2) * (x3 - x2);
      };
      this.Draw = function (_g) {
        for (var i = 0; i < this.particleCount - 1; i++) {
          var p0 = new Vector2(this.particles[i].position.x + this.xOff, this.particles[i].position.y + this.yOff);
          var p1 = new Vector2(this.particles[i + 1].position.x + this.xOff, this.particles[i + 1].position.y + this.yOff);
          var color = this.Side(
            this.particles[i].position.x, this.particles[i].position.y,
            this.particles[i + 1].position.x, this.particles[i + 1].position.y,
            p1.x, p1.y
          ) < 0 ? this.frontColor : this.backColor;
          _g.fillStyle = color; _g.strokeStyle = color;
          _g.beginPath();
          if (i === 0) {
            _g.moveTo(this.particles[i].position.x, this.particles[i].position.y);
            _g.lineTo(this.particles[i + 1].position.x, this.particles[i + 1].position.y);
            _g.lineTo((this.particles[i + 1].position.x + p1.x) * 0.5, (this.particles[i + 1].position.y + p1.y) * 0.5);
          } else if (i === this.particleCount - 2) {
            _g.moveTo(this.particles[i].position.x, this.particles[i].position.y);
            _g.lineTo(this.particles[i + 1].position.x, this.particles[i + 1].position.y);
            _g.lineTo((this.particles[i].position.x + p0.x) * 0.5, (this.particles[i].position.y + p0.y) * 0.5);
          } else {
            _g.moveTo(this.particles[i].position.x, this.particles[i].position.y);
            _g.lineTo(this.particles[i + 1].position.x, this.particles[i + 1].position.y);
            _g.lineTo(p1.x, p1.y); _g.lineTo(p0.x, p0.y);
          }
          _g.closePath(); _g.stroke(); _g.fill();
        }
      };
    }
    ConfettiRibbon.bounds = new Vector2(0, 0);
    ConfettiRibbon.spawning = false;

    var ConfettiContext = function (parent) {
      var i;
      var canvasParent = document.getElementById(parent);
      var canvas = document.createElement('canvas');
      canvas.width = canvasParent.offsetWidth;
      canvas.height = canvasParent.offsetHeight;
      canvasParent.appendChild(canvas);
      var context = canvas.getContext('2d');
      var confettiRibbonCount = 7;
      var rpCount = 30, rpDist = 8.0, rpThick = 8.0;
      var confettiRibbons = [];
      ConfettiRibbon.bounds = new Vector2(canvas.width, canvas.height);
      for (i = 0; i < confettiRibbonCount; i++) {
        confettiRibbons[i] = new ConfettiRibbon(
          Math.random() * canvas.width, -Math.random() * canvas.height * 2,
          rpCount, rpDist, rpThick, 45, 1, 0.05
        );
      }
      var confettiPaperCount = 25;
      var confettiPapers = [];
      ConfettiPaper.bounds = new Vector2(canvas.width, canvas.height);
      for (i = 0; i < confettiPaperCount; i++) {
        confettiPapers[i] = new ConfettiPaper(Math.random() * canvas.width, Math.random() * canvas.height);
      }
      this.resize = function () {
        canvas.width = canvasParent.offsetWidth;
        canvas.height = canvasParent.offsetHeight;
        ConfettiPaper.bounds = new Vector2(canvas.width, canvas.height);
        ConfettiRibbon.bounds = new Vector2(canvas.width, canvas.height);
      };
      this.start = function () {
        this.stop();
        /* Enable respawning and clear any done flags from a previous drain run. */
        ConfettiPaper.spawning  = true;
        ConfettiRibbon.spawning = true;
        for (var r = 0; r < confettiRibbonCount; r++) { confettiRibbons[r].done = false; }
        var self = this;
        /* setInterval reference: https://developer.mozilla.org/en-US/docs/Web/API/Window/setInterval */
        this.interval = setInterval(function () { self.update(); }, 1000.0 / frameRate);
      };
      this.stop = function () { clearInterval(this.interval); };
      /* drain() — stop spawning everything. Papers fall off naturally (fast).
       * Ribbons that are still entirely above the viewport (position.y < 0)
       * would take 20+ seconds to naturally arrive and exit, so we move them
       * to y=0 — they fall through and off-screen in a few seconds at normal
       * speed, with no jarring instant disappearance.
       */
      this.drain = function () {
        ConfettiPaper.spawning  = false;
        ConfettiRibbon.spawning = false;
        for (var r = 0; r < confettiRibbonCount; r++) {
          if (confettiRibbons[r].position.y < 0) {
            confettiRibbons[r].position.y = 0;
            confettiRibbons[r].prevPosition.y = 0;
            for (var p = 0; p < confettiRibbons[r].particles.length; p++) {
              confettiRibbons[r].particles[p].position.y = 0 - p * confettiRibbons[r].particleDist;
            }
          }
        }
      };
      this.update = function () {
        var j, allGone;
        context.clearRect(0, 0, canvas.width, canvas.height);
        for (j = 0; j < confettiPaperCount; j++) { confettiPapers[j].Update(dt); confettiPapers[j].Draw(context); }
        for (j = 0; j < confettiRibbonCount; j++) {
          /* Skip ribbons that have exited in drain mode — stops tail particles rendering. */
          if (!confettiRibbons[j].done) {
            confettiRibbons[j].Update(dt);
            confettiRibbons[j].Draw(context);
          }
        }

        /* When both spawning flags are off, stop the loop once every piece
         * has left the canvas.
         */
        if (!ConfettiPaper.spawning && !ConfettiRibbon.spawning) {
          allGone = true;
          for (j = 0; j < confettiPaperCount; j++) {
            if (confettiPapers[j].pos.y <= canvas.height) { allGone = false; break; }
          }
          if (allGone) {
            for (j = 0; j < confettiRibbonCount; j++) {
              if (!confettiRibbons[j].done) { allGone = false; break; }
            }
          }
          if (allGone) {
            this.stop();
            context.clearRect(0, 0, canvas.width, canvas.height);
          }
        }
      };
    };

    /* Assign to window so showWinner() can call .start() / .stop() across scopes.
     * Reference: https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Operators/Property_accessors
     */
    window.confettiAnim = new ConfettiContext('confetti');
    /* No auto-start — triggered on demand by showWinner() only. */

    /* $(window).resize: https://api.jquery.com/resize/ */
    $(window).resize(function () { window.confettiAnim.resize(); });
  });
  </script>
  <!-- Dark mode — reads/writes a cookie so preference survives page reloads
       and token refreshes (the page reloads after save/delete).
       Cookie max-age: 1 year (31536000 seconds).
       document.cookie reference: https://developer.mozilla.org/en-US/docs/Web/API/Document/cookie -->
  <script>
  (function () {
    var COOKIE = 'wheelspin_darkmode';

    function getCookie(name) {
      var match = document.cookie.match(new RegExp('(?:^|; )' + name + '=([^;]*)'));
      return match ? match[1] : null;
    }

    function setCookie(name, value) {
      document.cookie = name + '=' + value + '; max-age=31536000; path=/; SameSite=Lax';
    }

    function applyDark(on) {
      document.body.classList.toggle('dark-mode', on);
      document.getElementById('dark-mode-toggle').textContent = on ? '☀️' : '🌙';
    }

    /* Apply saved preference immediately on load. */
    var saved = getCookie(COOKIE);
    if (saved === '1') { applyDark(true); }

    document.getElementById('dark-mode-toggle').addEventListener('click', function () {
      var isDark = document.body.classList.contains('dark-mode');
      applyDark(!isDark);
      setCookie(COOKIE, isDark ? '0' : '1');
    });
  }());
  </script>

</body>
</html>
