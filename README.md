# 🎡 WheelSpin

A self-hosted spinning wheel application with save capabilities, bot protection, and rate limiting.

For 🎈 and 🎉🎊 see the [balloon](../../tree/balloon) branch.

---

![Spin a wheel, make a choice - Wheelspin app](https://raw.githubusercontent.com/MarcusHoltz/marcusholtz.github.io/refs/heads/main/assets/img/posts/wheelspin-spin-a-wheel-to-make-a-choice.png "Click all you want, you cant spin this wheel - this is an image")

---

## ⚙️ How It Works

1. **Save/Delete** → Requires bot check modal + rate limit check (1 second cooldown)
2. **Load/Browse** → No restrictions, instant access
3. **Rate Limiting** → Tracks by IP address (or session ID on localhost)
4. **Bot Protection** → One-time tokens + invisible honeypot buttons

---

## 🧇 What You Can Customize

### index.php:

**Maximum Wheels Limit**
```php
if (count($wheels) >= 200) {  // Change 200 to your limit
```

**Rate Limit Cooldown**
```php
if ($now - $lastAction < 1) {  // Change 1 to seconds (default: 1 second)
```

**Token Expiry Time**
```php
if (time() - $_SESSION['bot_token_time'] > 300) {  // Change 300 (5 minutes)
```

**Max Items Per Wheel**
```php
if (count($items) > 50) {  // Change 50 to your limit
```

**Item Label Max Length**
```php
if (strlen($item['label']) > 200) {  // Change 200 characters
```

**Cleanup Frequency**
```php
if (rand(1, 20) === 1) {  // Change 20 = 5% of requests trigger cleanup
```

---

## 📂 File Structure (Auto-Created)

```
your-web-directory/
├── index.php           (your main file)
└── data/              (created automatically)
    ├── wheels.json    (saved wheels database)
    └── ratelimit/     (temporary rate limit tracking files)
```

**All directories are created automatically with secure permissions (0755).**

> Please adjust permissions!


---

## 🚀 Quick Start

### Requirements
- Docker with docker-compose
- Nginx + PHP-FPM container: `tangramor/nginx-php8-fpm`

### Installation

1. **Create directory structure:**
```bash
mkdir -p /mnt/user/appdata/wheelspin/www/data
cd /mnt/user/appdata/wheelspin
```

2. **Create `docker-compose.yml`:**
```yaml
services:
  wheelspin:
    container_name: wheelspin
    image: tangramor/nginx-php8-fpm:latest
    network_mode: bridge  # or your custom network
    ports:
      - "8080:80"
    volumes:
      - '/mnt/user/appdata/wheelspin/www:/var/www/html/:ro'
      - '/mnt/user/appdata/wheelspin/www/data/:/var/www/html/data:rw'
    restart: unless-stopped
```

3. **Place `index.php` in the www directory:**
```bash
# Copy the index.php file to:
/mnt/user/appdata/wheelspin/www/index.php
```

4. **Start the container:**
```bash
docker-compose up -d
```

5. **Access your map:**
```
http://YOUR_SERVER_IP:8080
```




## 📝 License & Credits

Built for fun. Feel free to modify and use for your projects.

**Powered by:** [Spin Wheel JS Library](https://github.com/CrazyTim/spin-wheel) by CrazyTim
