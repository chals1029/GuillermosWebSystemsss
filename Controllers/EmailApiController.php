<?php

use PHPMailer\PHPMailer\Exception as PHPMailerException;
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\SMTP;

require_once __DIR__ . '/../vendor/autoload.php';

class EmailApiController
{
    private const SMTP_HOST = 'smtp.gmail.com';
    private const SMTP_PORT = 587;
    private const SMTP_USERNAME = '';
    private const SMTP_PASSWORD = '';
    private const SMTP_ENCRYPTION = PHPMailer::ENCRYPTION_STARTTLS;
    private const SMTP_DEBUG_LEVEL = SMTP::DEBUG_OFF;
    private const FROM_EMAIL = '';
    private const FROM_NAME = "Guillermo's Web System";

    private static function env(string $key, ?string $default = null): ?string
    {
        $value = getenv($key);
        if ($value === false || $value === '') {
            return $default;
        }

        return (string)$value;
    }

    /** @return array{host:string,port:int,username:string,password:string,encryption:string,from_email:string,from_name:string,debug:int} */
    private static function mailConfig(): array
    {
        $encryptionRaw = strtolower((string)self::env('MAIL_ENCRYPTION', 'tls'));
        $encryption = $encryptionRaw === 'ssl'
            ? PHPMailer::ENCRYPTION_SMTPS
            : PHPMailer::ENCRYPTION_STARTTLS;

        $username = (string)self::env('MAIL_USERNAME', self::SMTP_USERNAME);
        $fromEmail = (string)self::env('MAIL_FROM_ADDRESS', self::FROM_EMAIL ?: $username);

        return [
            'host' => (string)self::env('MAIL_HOST', self::SMTP_HOST),
            'port' => (int)self::env('MAIL_PORT', (string)self::SMTP_PORT),
            'username' => $username,
            'password' => (string)self::env('MAIL_PASSWORD', self::SMTP_PASSWORD),
            'encryption' => $encryption,
            'from_email' => $fromEmail,
            'from_name' => (string)self::env('MAIL_FROM_NAME', self::FROM_NAME),
            'debug' => self::SMTP_DEBUG_LEVEL,
        ];
    }

    private static function buildMailer(array $mailConfig): PHPMailer
    {
        $mail = new PHPMailer(true);
        $mail->SMTPDebug = $mailConfig['debug'];
        $mail->Debugoutput = static function ($str) {
            self::logEvent('SMTP DEBUG: ' . trim($str));
        };
        $mail->isSMTP();
        $mail->Host = $mailConfig['host'];
        $mail->SMTPAuth = true;
        $mail->Username = $mailConfig['username'];
        $mail->Password = $mailConfig['password'];
        $mail->SMTPSecure = $mailConfig['encryption'];
        $mail->Port = $mailConfig['port'];
        $mail->CharSet = 'UTF-8';
        $mail->setFrom($mailConfig['from_email'], $mailConfig['from_name']);
        $mail->addReplyTo($mailConfig['from_email'], $mailConfig['from_name']);

        return $mail;
    }

    /**
     * Send a verification email via Gmail SMTP + app password.
     *
     * @param string $email
     * @param string $name
     * @param string $code
    * @return bool|string
     */
    public static function sendVerificationEmail(string $email, string $name, string $code): bool|string
    {
        $sanitizedEmail = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        if (!filter_var($sanitizedEmail, FILTER_VALIDATE_EMAIL)) {
            self::logEvent('Invalid recipient email: ' . $email);
            return 'Invalid recipient email address.';
        }

        $normalizedName = trim($name);
        if ($normalizedName === '') {
            $normalizedName = 'Customer';
        }

        $normalizedCode = trim($code);

        $mailConfig = self::mailConfig();
        $mail = self::buildMailer($mailConfig);

        try {
            // --- Recipients ---
            $mail->addAddress($sanitizedEmail, $normalizedName);

            // --- Content ---
            $mail->isHTML(true);
            $mail->Subject = "Your Guillermo's Verification Code";
            $mail->Body = "Hi {$normalizedName},<br><br>Thank you for registering. Your verification code is: <b>{$normalizedCode}</b><br><br>This code will expire in 10 minutes.<br><br>Best regards,<br>Guillermo's Team";
            $mail->AltBody = "Your verification code is: {$normalizedCode}.";

            self::logEvent(sprintf('Attempting to send verification email to %s', $sanitizedEmail));
            $mail->send();
            self::logEvent(sprintf('Verification email sent successfully to %s', $sanitizedEmail));
            return true;
        } catch (PHPMailerException $e) {
            $errorMessage = 'Failed to send verification email. ' . $e->getMessage();
            if (!empty($mail->ErrorInfo)) {
                $errorMessage .= ' | Mailer error: ' . $mail->ErrorInfo;
            }

            self::logEvent($errorMessage);
            return $errorMessage;
        }
    }

    public static function sendPasswordResetEmail(string $email, string $name, string $code)
    {
        $sanitizedEmail = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        if (!filter_var($sanitizedEmail, FILTER_VALIDATE_EMAIL)) {
            self::logEvent('Invalid recipient email for password reset: ' . $email);
            return 'Invalid recipient email address.';
        }

        $normalizedName = trim($name);
        if ($normalizedName === '') {
            $normalizedName = 'Customer';
        }

        $normalizedCode = trim($code);

        $mailConfig = self::mailConfig();
        $mail = self::buildMailer($mailConfig);

        try {
            $mail->addAddress($sanitizedEmail, $normalizedName);

            $mail->isHTML(true);
            $mail->Subject = "Reset your Guillermo's password";
            $mail->Body = "Hi {$normalizedName},<br><br>We received a request to reset your password. Your reset code is: <b>{$normalizedCode}</b><br><br>This code will expire in 10 minutes. If you did not request a password reset, you can safely ignore this message.<br><br>Best regards,<br>Guillermo's Team";
            $mail->AltBody = "Your password reset code is: {$normalizedCode}.";

            self::logEvent(sprintf('Attempting to send password reset email to %s', $sanitizedEmail));
            $mail->send();
            self::logEvent(sprintf('Password reset email sent successfully to %s', $sanitizedEmail));
            return true;
        } catch (PHPMailerException $e) {
            $errorMessage = 'Failed to send password reset email. ' . $e->getMessage();
            if (!empty($mail->ErrorInfo)) {
                $errorMessage .= ' | Mailer error: ' . $mail->ErrorInfo;
            }

            self::logEvent($errorMessage);
            return $errorMessage;
        }
    }

    /**
     * Send receipt email with order details
     */
    public static function sendReceiptEmail(string $email, string $name, array $orderDetails): bool|string
    {
        $sanitizedEmail = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        if (!filter_var($sanitizedEmail, FILTER_VALIDATE_EMAIL)) {
            self::logEvent('Invalid recipient email for receipt: ' . $email);
            return 'Invalid recipient email address.';
        }

        $normalizedName = trim($name);
        if ($normalizedName === '') {
            $normalizedName = 'Customer';
        }

        $orderId = $orderDetails['order_id'] ?? '';
        $orderDate = $orderDetails['order_date'] ?? '';
        $paymentMethod = $orderDetails['payment_method'] ?? '';
        $status = $orderDetails['status'] ?? '';
        $totalAmount = $orderDetails['total_amount'] ?? 0;
        $change = $orderDetails['change'] ?? 0;
        $items = $orderDetails['items'] ?? [];

        // Defensive logging: if items are missing product names, log for later diagnostics
        if (!empty($items) && is_array($items)) {
            foreach ($items as $i => $it) {
                $pname = $it['Product_Name'] ?? $it['name'] ?? '';
                if (trim($pname) === '' || stripos((string)$pname, 'unknown') !== false) {
                    self::logEvent("Receipt email payload contains item with missing/unknown name for order {$orderId}: index {$i}; item: " . json_encode($it));
                }
            }
        }

        $mailConfig = self::mailConfig();

        // Generate modern HTML receipt content for email
        $htmlBody = "
        <!DOCTYPE html>
        <html lang='en'>
        <head>
            <meta charset='UTF-8'>
            <meta name='viewport' content='width=device-width, initial-scale=1.0'>
            <title>Order Receipt #$orderId</title>
            <style>
                /* Reset and base styles */
                body, table, td, p, a, li, blockquote {
                    -webkit-text-size-adjust: 100%;
                    -ms-text-size-adjust: 100%;
                }
                table, td {
                    mso-table-lspace: 0pt;
                    mso-table-rspace: 0pt;
                }
                img {
                    -ms-interpolation-mode: bicubic;
                }

                /* Base styles */
                body {
                    margin: 0 !important;
                    padding: 0 !important;
                    background-color: #f8f9fa;
                    font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                }

                /* Container */
                .email-container {
                    max-width: 600px;
                    margin: 0 auto;
                    background-color: #ffffff;
                    border-radius: 16px;
                    overflow: hidden;
                    box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                }

                /* Header */
                .header {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 40px 30px;
                    text-align: center;
                    position: relative;
                }

                .header::before {
                    content: '🧾';
                    font-size: 3rem;
                    display: block;
                    margin-bottom: 15px;
                }

                .header h1 {
                    margin: 0;
                    font-size: 2.2rem;
                    font-weight: 700;
                    letter-spacing: -0.5px;
                }

                .header p {
                    margin: 8px 0 0;
                    opacity: 0.9;
                    font-size: 1.1rem;
                }

                .order-badge {
                    position: absolute;
                    top: 20px;
                    right: 20px;
                    background: rgba(255,255,255,0.2);
                    padding: 8px 16px;
                    border-radius: 20px;
                    font-size: 0.9rem;
                    font-weight: 600;
                    backdrop-filter: blur(10px);
                }

                /* Progress Tracker */
                .progress-section {
                    padding: 30px;
                    background: #f8f9fa;
                    border-bottom: 1px solid #e9ecef;
                }

                .progress-header {
                    text-align: center;
                    margin-bottom: 20px;
                }

                .progress-header h3 {
                    margin: 0;
                    color: #2c3e50;
                    font-size: 1.2rem;
                    font-weight: 600;
                }

                .progress-steps {
                    display: flex;
                    justify-content: space-between;
                    position: relative;
                    margin-bottom: 15px;
                }

                .progress-steps::before {
                    content: '';
                    position: absolute;
                    top: 15px;
                    left: 0;
                    right: 0;
                    height: 3px;
                    background: #e9ecef;
                    z-index: 1;
                }

                .step {
                    background: #e9ecef;
                    border: 3px solid #e9ecef;
                    border-radius: 50%;
                    width: 30px;
                    height: 30px;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-size: 0.8rem;
                    font-weight: 600;
                    color: #6c757d;
                    position: relative;
                    z-index: 2;
                }

                .step.active {
                    background: #28a745;
                    border-color: #28a745;
                    color: white;
                }

                .step.completed {
                    background: #28a745;
                    border-color: #28a745;
                    color: white;
                }

                .step-labels {
                    display: flex;
                    justify-content: space-between;
                }

                .step-label {
                    font-size: 0.75rem;
                    color: #6c757d;
                    text-align: center;
                    flex: 1;
                }

                .step-label.active {
                    color: #28a745;
                    font-weight: 600;
                }

                /* Info Grid */
                .info-grid {
                    display: flex;
                    flex-wrap: wrap;
                    gap: 20px;
                    padding: 30px;
                    background: white;
                }

                .info-card {
                    flex: 1;
                    min-width: 250px;
                    background: #f8f9fa;
                    border-radius: 12px;
                    padding: 20px;
                    border-left: 4px solid #667eea;
                }

                .info-card h3 {
                    margin: 0 0 8px;
                    font-size: 0.85rem;
                    color: #6c757d;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    font-weight: 600;
                }

                .info-card p {
                    margin: 0;
                    font-size: 1rem;
                    font-weight: 500;
                    color: #2c3e50;
                }

                /* Items Section */
                .items-section {
                    padding: 30px;
                    background: #f8f9fa;
                }

                .section-header {
                    display: flex;
                    align-items: center;
                    margin-bottom: 20px;
                }

                .section-header h2 {
                    margin: 0;
                    font-size: 1.3rem;
                    font-weight: 600;
                    color: #2c3e50;
                }

                .section-icon {
                    margin-right: 12px;
                    font-size: 1.5rem;
                }

                .items-table {
                    width: 100%;
                    border-collapse: collapse;
                    border-radius: 8px;
                    overflow: hidden;
                    box-shadow: 0 4px 6px rgba(0,0,0,0.05);
                }

                .items-table th {
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    padding: 15px;
                    text-align: left;
                    font-weight: 600;
                    font-size: 0.9rem;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                }

                .items-table td {
                    padding: 15px;
                    border-bottom: 1px solid #e9ecef;
                    background: white;
                }

                .item-name {
                    font-weight: 600;
                    color: #2c3e50;
                }

                .item-qty {
                    background: #e9ecef;
                    padding: 4px 8px;
                    border-radius: 6px;
                    font-size: 0.85rem;
                    font-weight: 600;
                    color: #495057;
                    display: inline-block;
                }

                .price {
                    font-weight: 600;
                    color: #28a745;
                }

                .subtotal {
                    font-weight: 700;
                    color: #2c3e50;
                }

                /* Totals Section */
                .totals-section {
                    background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);
                    color: white;
                    padding: 30px;
                }

                .totals-grid {
                    display: flex;
                    justify-content: space-between;
                    align-items: center;
                }

                .total-row {
                    font-size: 1.3rem;
                    font-weight: 700;
                }

                .change-row {
                    background: rgba(255,255,255,0.1);
                    padding: 15px;
                    border-radius: 8px;
                    margin-top: 15px;
                }

                /* CTA Section */
                .cta-section {
                    padding: 30px;
                    text-align: center;
                    background: white;
                }

                .cta-buttons {
                    display: flex;
                    justify-content: center;
                    gap: 15px;
                    margin-top: 20px;
                }

                .cta-button {
                    display: inline-block;
                    padding: 12px 24px;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    text-decoration: none;
                    border-radius: 8px;
                    font-weight: 600;
                    text-transform: uppercase;
                    letter-spacing: 0.5px;
                    font-size: 0.9rem;
                    transition: all 0.3s;
                }

                .cta-button:hover {
                    transform: translateY(-2px);
                    box-shadow: 0 8px 25px rgba(102,126,234,0.4);
                }

                .cta-button.secondary {
                    background: #6c757d;
                }

                .cta-button.secondary:hover {
                    background: #5a6268;
                }

                /* Footer */
                .footer {
                    padding: 30px;
                    text-align: center;
                    background: #f8f9fa;
                    border-top: 1px solid #e9ecef;
                }

                .footer h3 {
                    margin: 0 0 10px;
                    color: #2c3e50;
                    font-size: 1.4rem;
                }

                .footer p {
                    margin: 5px 0;
                    color: #6c757d;
                }

                /* Responsive */
                @media only screen and (max-width: 600px) {
                    .email-container { margin: 0; border-radius: 0; }
                    .header { padding: 30px 20px; }
                    .info-grid { padding: 20px; }
                    .info-card { min-width: 100%; }
                    .items-section { padding: 20px; }
                    .totals-section { padding: 20px; }
                    .cta-section { padding: 20px; }
                    .footer { padding: 20px; }
                    .progress-steps { flex-wrap: wrap; gap: 10px; }
                    .cta-buttons { flex-direction: column; }
                }
            </style>
        </head>
        <body>
            <div class='email-container'>
                <!-- Header -->
                <div class='header'>
                    <div class='order-badge'>#$orderId</div>
                    <h1>Order Receipt</h1>
                    <p>Guillermo's Restaurant</p>
                </div>

                <!-- Progress Tracker -->
                <div class='progress-section'>
                    <div class='progress-header'>
                        <h3>📍 Order Status</h3>
                    </div>
                    <div class='progress-steps'>
                        <div class='step " . ($status === 'Pending' || $status === 'Completed' || $status === 'Cancelled' ? 'completed' : '') . "'>1</div>
                        <div class='step " . ($status === 'Completed' ? 'completed' : ($status === 'Pending' ? 'active' : '')) . "'>2</div>
                        <div class='step " . ($status === 'Completed' ? 'completed' : '') . "'>3</div>
                    </div>
                    <div class='step-labels'>
                        <div class='step-label " . ($status === 'Pending' || $status === 'Completed' || $status === 'Cancelled' ? 'active' : '') . "'>Order Placed</div>
                        <div class='step-label " . ($status === 'Completed' ? 'active' : ($status === 'Pending' ? 'active' : '')) . "'>Preparing</div>
                        <div class='step-label " . ($status === 'Completed' ? 'active' : '') . "'>Delivered</div>
                    </div>
                </div>

                <!-- Order Information -->
                <div class='info-grid'>
                    <div class='info-card'>
                        <h3>👤 Customer</h3>
                        <p>" . htmlspecialchars($normalizedName) . "</p>
                    </div>
                    <div class='info-card'>
                        <h3>📅 Order Date</h3>
                            <p>" . (function($raw) {
                                if (!$raw) return '';
                                try {
                                    // If the incoming date string has an explicit timezone, parse as-is.
                                    $hasTz = preg_match('/[Zz]|[+\-]\d{2}(:?\d{2})?$/', trim($raw));
                                    if ($hasTz) {
                                        $dt = new \DateTimeImmutable($raw);
                                    } else {
                                        $dt = new \DateTimeImmutable($raw, new \DateTimeZone('UTC'));
                                    }
                                    return $dt->setTimezone(new \DateTimeZone('Asia/Manila'))->format('M d, Y g:i A');
                                } catch (\Throwable $e) {
                                    return date('M d, Y g:i A', strtotime($raw));
                                }
                            })($orderDate) . "</p>
                    </div>
                    <div class='info-card'>
                        <h3>💳 Payment</h3>
                        <p>" . htmlspecialchars($paymentMethod) . "</p>
                    </div>
                    <div class='info-card'>
                        <h3>📊 Status</h3>
                        <p><span style='display: inline-block; padding: 6px 14px; border-radius: 20px; font-size: 0.85rem; font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; background-color: " . ($status === 'Completed' ? '#d4edda; color: #155724;' : ($status === 'Pending' ? '#fff3cd; color: #856404;' : '#f8d7da; color: #721c24;')) . "'>" . htmlspecialchars($status) . "</span></p>
                    </div>
                </div>

                <!-- Order Items -->
                <div class='items-section'>
                    <div class='section-header'>
                        <span class='section-icon'>🛒</span>
                        <h2>Order Items</h2>
                    </div>
                    <table class='items-table'>
                        <thead>
                            <tr>
                                <th>Item</th>
                                <th>Quantity</th>
                                <th>Unit Price</th>
                                <th>Subtotal</th>
                            </tr>
                        </thead>
                        <tbody>";

        foreach ($items as $item) {
            $productName = htmlspecialchars($item['Product_Name'] ?? $item['name'] ?? 'Unknown Item');
            $quantity = $item['Quantity'] ?? $item['quantity'] ?? 0;
            $price = $item['Price'] ?? $item['price'] ?? 0;
            $subtotal = $item['Subtotal'] ?? ($price * $quantity) ?? 0;

            $htmlBody .= "<tr>
                            <td><span class='item-name'>{$productName}</span></td>
                            <td><span class='item-qty'>{$quantity}</span></td>
                            <td><span class='price'>₱" . number_format($price, 2) . "</span></td>
                            <td><span class='subtotal'>₱" . number_format($subtotal, 2) . "</span></td>
                        </tr>";
        }

        $htmlBody .= "</tbody>
                    </table>
                </div>

                <!-- Order Totals -->
                <div class='totals-section'>
                    <div class='totals-grid'>
                        <div></div>
                        <div class='total-row'>
                            Total Amount: ₱" . number_format($totalAmount, 2) . "
                        </div>
                    </div>";

        if ($change > 0) {
            $htmlBody .= "<div class='change-row'>
                        <div class='total-row'>
                            Change: ₱" . number_format($change, 2) . "
                        </div>
                    </div>";
        }

        $htmlBody .= "</div>

                <!-- Call to Action -->
                <div class='cta-section'>
                    <h3>Need to make changes to your order?</h3>
                    <p>Contact us if you need to modify or cancel your order</p>
                    <div class='cta-buttons'>
                        <a href='mailto:" . htmlspecialchars((string)$mailConfig['from_email']) . "?subject=Order #$orderId Inquiry' class='cta-button'>📧 Contact Support</a>
                        <a href='#' class='cta-button secondary'>📱 Call Us</a>
                    </div>
                </div>

                <!-- Footer -->
                <div class='footer'>
                    <h3>Thank You! 🎉</h3>
                    <p>We hope you enjoy your meal from Guillermo's Restaurant</p>
                    <p>For any questions or concerns, please contact our support team</p>
                </div>
            </div>
        </body>
        </html>";

        $mail = self::buildMailer($mailConfig);

        try {
            $mail->addAddress($sanitizedEmail, $normalizedName);

            $mail->isHTML(true);
            $mail->Subject = "Your Guillermo's Order Receipt - Order #$orderId";
            $mail->Body = $htmlBody;
            $mail->AltBody = "Your order #$orderId has been placed successfully. Total: ₱" . number_format($totalAmount, 2);

            self::logEvent(sprintf('Attempting to send receipt email to %s for order %s', $sanitizedEmail, $orderId));
            $mail->send();
            self::logEvent(sprintf('Receipt email sent successfully to %s for order %s', $sanitizedEmail, $orderId));
            return true;
        } catch (PHPMailerException $e) {
            $errorMessage = 'Failed to send receipt email. ' . $e->getMessage();
            if (!empty($mail->ErrorInfo)) {
                $errorMessage .= ' | Mailer error: ' . $mail->ErrorInfo;
            }

            self::logEvent($errorMessage);
            return $errorMessage;
        }
    }

    public static function sendOrderStatusEmail(string $email, string $name, array $orderDetails): bool|string
    {
        $sanitizedEmail = filter_var(trim($email), FILTER_SANITIZE_EMAIL);
        if (!filter_var($sanitizedEmail, FILTER_VALIDATE_EMAIL)) {
            self::logEvent('Invalid recipient email for order status: ' . $email);
            return 'Invalid recipient email address.';
        }

        $normalizedName = trim($name);
        if ($normalizedName === '') {
            $normalizedName = 'Customer';
        }

        $orderId = $orderDetails['order_id'] ?? '';
        $orderDate = $orderDetails['order_date'] ?? '';
        $paymentMethod = $orderDetails['payment_method'] ?? '';
        $status = $orderDetails['status'] ?? 'Pending';
        $additionalMessage = $orderDetails['message'] ?? '';
        $items = $orderDetails['items'] ?? [];
        $totalAmount = $orderDetails['total_amount'] ?? 0;

        $statusHeadline = sprintf('Your order #%s is now %s', $orderId, strtolower($status));
        $orderDateDisplay = $orderDate ? (function($raw) {
            if (!$raw) return 'recently';
            try {
                $hasTz = preg_match('/[Zz]|[+\-]\d{2}(:?\d{2})?$/', trim($raw));
                if ($hasTz) {
                    $dt = new \DateTimeImmutable($raw);
                } else {
                    $dt = new \DateTimeImmutable($raw, new \DateTimeZone('UTC'));
                }
                return $dt->setTimezone(new \DateTimeZone('Asia/Manila'))->format('M d, Y g:i A');
            } catch (\Throwable $e) {
                return date('M d, Y g:i A', strtotime($raw));
            }
        })($orderDate) : 'recently';

        $itemsMarkup = '';
        if (!empty($items)) {
            $rows = '';
            foreach ($items as $item) {
                $productName = htmlspecialchars($item['Product_Name'] ?? $item['name'] ?? 'Item');
                $quantity = (int)($item['Quantity'] ?? $item['quantity'] ?? 0);
                $price = (float)($item['Price'] ?? $item['price'] ?? 0);
                $subtotal = (float)($item['Subtotal'] ?? ($price * $quantity));

                $rows .= '<tr>' .
                    '<td style="padding:8px 12px;border-bottom:1px solid #eee;">' . $productName . '</td>' .
                    '<td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:center;">' . $quantity . '</td>' .
                    '<td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:right;">₱' . number_format($price, 2) . '</td>' .
                    '<td style="padding:8px 12px;border-bottom:1px solid #eee;text-align:right;">₱' . number_format($subtotal, 2) . '</td>' .
                '</tr>';
            }

            $itemsMarkup = '<table style="width:100%;border-collapse:collapse;margin-top:16px;font-size:14px;">' .
                '<thead>' .
                    '<tr>' .
                        '<th style="text-align:left;padding:10px 12px;background:#f1f3f5;border-bottom:1px solid #dee2e6;">Item</th>' .
                        '<th style="text-align:center;padding:10px 12px;background:#f1f3f5;border-bottom:1px solid #dee2e6;">Qty</th>' .
                        '<th style="text-align:right;padding:10px 12px;background:#f1f3f5;border-bottom:1px solid #dee2e6;">Price</th>' .
                        '<th style="text-align:right;padding:10px 12px;background:#f1f3f5;border-bottom:1px solid #dee2e6;">Subtotal</th>' .
                    '</tr>' .
                '</thead>' .
                '<tbody>' . $rows . '</tbody>' .
            '</table>';
        }

        $summaryRow = $totalAmount ? '<p style="margin:12px 0 0;font-weight:600;">Order Total: ₱' . number_format((float)$totalAmount, 2) . '</p>' : '';
        $paymentRow = $paymentMethod ? '<p style="margin:0;color:#6c757d;">Payment Method: ' . htmlspecialchars($paymentMethod) . '</p>' : '';
        $extraMessage = $additionalMessage ? '<p style="margin:16px 0 0;">' . nl2br(htmlspecialchars($additionalMessage)) . '</p>' : '';

        $htmlBody = '<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>Order Update</title></head><body style="background:#f8f9fa;font-family:Segoe UI,Tahoma,Geneva,Verdana,sans-serif;margin:0;padding:24px;">' .
            '<div style="max-width:600px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;box-shadow:0 10px 30px rgba(0,0,0,0.08);">' .
                '<div style="background:linear-gradient(135deg,#4c6ef5,#7950f2);color:#fff;padding:28px 24px;">' .
                    '<p style="margin:0 0 8px;font-size:16px;">Hi ' . htmlspecialchars($normalizedName) . ',</p>' .
                    '<h1 style="margin:0;font-size:22px;font-weight:700;">' . htmlspecialchars($statusHeadline) . '</h1>' .
                    '<p style="margin:12px 0 0;font-size:14px;opacity:0.9;">Order placed on ' . htmlspecialchars($orderDateDisplay) . '</p>' .
                '</div>' .
                '<div style="padding:24px;">' .
                    '<p style="margin:0 0 12px;">We have reviewed your order and confirmed that everything is good to proceed. We will let you know once you order has been delivered.</p>' .
                    '<p style="margin:0 0 12px;">Order Reference: <strong>#' . htmlspecialchars((string)$orderId) . '</strong></p>' .
                    $paymentRow .
                    $summaryRow .
                    $itemsMarkup .
                    $extraMessage .
                    '<p style="margin:24px 0 0">If you have any questions, feel free to reply to this email or contact us directly.</p>' .
                    '<p style="margin:12px 0 0;">Warm regards,<br><strong>Guillermo\'s Team</strong></p>' .
                '</div>' .
            '</div>' .
        '</body></html>';

        $altBody = "Order #$orderId is now $status. Placed on $orderDateDisplay.";

        $mailConfig = self::mailConfig();
        $mail = self::buildMailer($mailConfig);

        try {
            $mail->addAddress($sanitizedEmail, $normalizedName);

            $mail->isHTML(true);
            $mail->Subject = "Update on your Guillermo's order #$orderId";
            $mail->Body = $htmlBody;
            $mail->AltBody = $altBody;

            self::logEvent(sprintf('Attempting to send %s status email to %s for order %s', $status, $sanitizedEmail, $orderId));
            $mail->send();
            self::logEvent(sprintf('Order status email sent successfully to %s for order %s', $sanitizedEmail, $orderId));
            return true;
        } catch (PHPMailerException $e) {
            $errorMessage = 'Failed to send order status email. ' . $e->getMessage();
            if (!empty($mail->ErrorInfo)) {
                $errorMessage .= ' | Mailer error: ' . $mail->ErrorInfo;
            }

            self::logEvent($errorMessage);
            return $errorMessage;
        }
    }

    private static function logEvent(...$args): void
    {
        $logMessage = (string)($args[0] ?? '');
        // Use system temp dir to avoid collisions with project files that may be regular files.
        $logDir = rtrim(sys_get_temp_dir(), '\\/') . DIRECTORY_SEPARATOR . 'guillermos_logs';
        if (!is_dir($logDir)) {
            @mkdir($logDir, 0777, true);
        }

        $logFile = $logDir . DIRECTORY_SEPARATOR . 'email.log';
        $timestamp = (new \DateTimeImmutable('now'))->format('Y-m-d H:i:s');
        @file_put_contents($logFile, sprintf("[%s] %s%s", $timestamp, $logMessage, PHP_EOL), FILE_APPEND);
    }
}
