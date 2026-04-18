<?php
session_start();

// Check if user is logged in as customer
if (!isset($_SESSION['user_role']) || strtolower($_SESSION['user_role']) !== 'customer') {
    // Redirect to landing page if not authenticated
    header('Location: ../../Views/landing/index.php');
    exit;
}

require_once __DIR__ . '/../../Controllers/CustomerController.php';
require_once __DIR__ . '/../../Controllers/Security/DdosGuard.php';

$isRateLimitedRequest = (($_SERVER['REQUEST_METHOD'] ?? 'GET') === 'POST') || isset($_GET['action']);
if ($isRateLimitedRequest && !DdosGuard::protect([
    'scope' => 'customer_dashboard',
    'max_requests' => (int)(getenv('CUSTOMER_DDOS_MAX_REQUESTS') ?: 120),
    'window_seconds' => (int)(getenv('CUSTOMER_DDOS_WINDOW_SECONDS') ?: 60),
    'block_seconds' => (int)(getenv('CUSTOMER_DDOS_BLOCK_SECONDS') ?: 180),
    'request_methods' => ['GET', 'POST'],
    'response_type' => 'json',
    'message' => 'Too many requests detected. Please wait before trying again.',
    'exit_on_block' => false,
])) {
    exit;
}

$controller = new CustomerController();

// Route feedback GET actions directly to controller
// Add 'get_feedback' so the AJAX endpoint returns JSON rather than the full HTML page
if (isset($_GET['action']) && in_array($_GET['action'], ['check_feedback', 'get_feedback'])) {
    $controller->handleAjax();
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Route feedback actions directly to controller
    if (isset($_POST['action']) && in_array($_POST['action'], ['submit_feedback'])) {
        $controller->handleAjax();
        exit;
    }
    
    if (isset($_POST['action']) && $_POST['action'] === 'update_profile') {
        require_once __DIR__ . '/../../Config.php';
        global $conn;
        $userId = $_SESSION['user']['user_id'] ?? null;
        if (!$userId) {
            echo json_encode(['success' => false, 'message' => 'Not logged in']);
            exit;
        }
        $username = trim($_POST['username'] ?? '');
        $name = trim($_POST['name'] ?? '');
        // Email and phone number are read-only, so we don't update them
        // $email = trim($_POST['email'] ?? '');
        // $phonenumber = trim($_POST['phonenumber'] ?? '');

        // Basic validation for username and name
        if ($username === '' || $name === '') {
            echo json_encode(['success' => false, 'message' => 'Username and name are required']);
            exit;
        }

        // Check if username is already taken by another user
        if ($username !== $_SESSION['user']['Username']) {
            $stmt = $conn->prepare('SELECT user_id FROM users WHERE username = ?');
            $stmt->bind_param('s', $username);
            $stmt->execute();
            $result = $stmt->get_result();
            $existing = $result->fetch_assoc();
            $stmt->close();

            if ($existing && $existing['user_id'] != $userId) {
                echo json_encode(['success' => false, 'message' => 'Username already in use by another account']);
                exit;
            }
        }

        $sql = 'UPDATE users SET username = ?, name = ? WHERE user_id = ?';
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('ssi', $username, $name, $userId);
        if ($stmt->execute()) {
            $_SESSION['user']['Username'] = $username;
            $_SESSION['user']['Name'] = $name;
            // Don't update email and phone in session since they're read-only
            echo json_encode(['success' => true, 'name' => $name, 'email' => $_SESSION['user']['Email']]);
        } else {
            echo json_encode(['success' => false, 'message' => 'Update failed']);
        }
        exit;
    }

    // Reorder entire previous order
   if (isset($_POST['reorder'])) {
        header('Content-Type: application/json');

        require_once __DIR__ . '/../../Config.php';
        global $conn;

        if (!$conn || !($conn instanceof \mysqli)) {
            echo json_encode(['success' => false, 'message' => 'Database connection unavailable']);
            exit;
        }

        $orderId = (int)$_POST['reorder'];
        $userId = (int)($_SESSION['user']['user_id']
            ?? $_SESSION['user']['User_ID']
            ?? $_SESSION['user_id']
            ?? $_SESSION['User_ID']
            ?? 0);

        if ($orderId <= 0 || $userId <= 0) {
            echo json_encode(['success' => false, 'message' => 'Invalid request']);
            exit;
        }

        $orderSql = 'SELECT Status FROM orders WHERE OrderID = ? AND User_ID = ?';
        $orderStmt = $conn->prepare($orderSql);
        if (!$orderStmt) {
            echo json_encode(['success' => false, 'message' => 'Unable to verify order ownership']);
            exit;
        }

        $orderStmt->bind_param('ii', $orderId, $userId);
        if (!$orderStmt->execute()) {
            $orderStmt->close();
            echo json_encode(['success' => false, 'message' => 'Failed to verify order']);
            exit;
        }

        $orderResult = $orderStmt->get_result();
        $orderRow = $orderResult ? $orderResult->fetch_assoc() : null;
        $orderStmt->close();

        if (!$orderRow) {
            echo json_encode(['success' => false, 'message' => 'Order not found']);
            exit;
        }

        $rawStatus = $orderRow['Status'] ?? '';
        $normalizedStatus = strtoupper(trim((string)$rawStatus));
        if (in_array($normalizedStatus, ['PENDING', 'CANCELLED', 'REJECTED'], true)) {
            $humanStatus = $normalizedStatus !== '' ? ucfirst(strtolower($normalizedStatus)) : 'Pending';
            echo json_encode([
                'success' => false,
                'message' => "This order is still {$humanStatus}. You can only reorder fulfilled orders."
            ]);
            exit;
        }

        $sql = "SELECT 
                    od.Product_ID AS product_id,
                    COALESCE(p.Product_Name, CONCAT('Product ', od.Product_ID)) AS name,
                    COALESCE(p.Price, od.Price, 0) AS price,
                    p.Image AS image,
                    od.Quantity AS quantity,
                    CASE WHEN p.Product_ID IS NULL THEN 0 ELSE 1 END AS is_available
                FROM order_detail od
                LEFT JOIN product p ON od.Product_ID = p.Product_ID
                WHERE od.Order_ID = ?";

        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            echo json_encode(['success' => false, 'message' => 'Server error preparing reorder query']);
            exit;
        }

        $stmt->bind_param('i', $orderId);
        if (!$stmt->execute()) {
            $stmt->close();
            echo json_encode(['success' => false, 'message' => 'Failed to load order items']);
            exit;
        }

        $result = $stmt->get_result();
        $items = $result ? $result->fetch_all(MYSQLI_ASSOC) : [];
        $stmt->close();

        if (empty($items)) {
            echo json_encode(['success' => false, 'message' => 'No items were recorded for this order.']);
            exit;
        }

        if (!isset($_SESSION['cart']) || !is_array($_SESSION['cart'])) {
            $_SESSION['cart'] = [];
        }

        $addedCount = 0;
        $skippedNames = [];

        foreach ($items as $item) {
            if (!(int)$item['is_available']) {
                $skippedNames[] = $item['name'] ?? ('Product ' . (int)$item['product_id']);
                continue;
            }

            $productName = trim((string)$item['name']);
            if ($productName === '') {
                $productName = 'Product ' . (int)$item['product_id'];
            }

            $quantity = max(1, (int)$item['quantity']);
            $price = (float)$item['price'];
            $productId = (int)$item['product_id'];
            $imageData = $item['image'];

            if (!isset($_SESSION['cart'][$productName])) {
                $_SESSION['cart'][$productName] = [
                    'price' => $price,
                    'quantity' => 0,
                    'image' => $imageData ? 'data:image/jpeg;base64,' . base64_encode($imageData) : null,
                    'product_id' => $productId,
                ];
            } else {
                $_SESSION['cart'][$productName]['price'] = $price;
                if (!isset($_SESSION['cart'][$productName]['product_id'])) {
                    $_SESSION['cart'][$productName]['product_id'] = $productId;
                }
            }

            $_SESSION['cart'][$productName]['quantity'] += $quantity;
            $addedCount += $quantity;
        }

        if ($addedCount === 0) {
            $message = !empty($skippedNames)
                ? 'All items in this order are no longer available for reorder.'
                : 'This order does not contain any eligible items.';
            echo json_encode(['success' => false, 'message' => $message]);
            exit;
        }

        $responseMessage = 'Added ' . $addedCount . ' item(s) to your cart.';
        if (!empty($skippedNames)) {
            $responseMessage .= ' Skipped unavailable item(s): ' . implode(', ', $skippedNames) . '.';
        }

        echo json_encode(['success' => true, 'message' => $responseMessage]);
        exit;
    }
    // === NEW CHECKOUT HANDLER ===
    // Handle reservation actions
    if (isset($_POST['action']) && $_POST['action'] === 'create_reservation') {
        // Suppress PHP errors to prevent JSON corruption
        error_reporting(0);
        ini_set('display_errors', 0);
        header('Content-Type: application/json');

        require_once __DIR__ . '/../../Config.php';
        global $conn;

        // Check if database connection exists
        if (!$conn) {
            echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
            exit;
        }

        // Resolve user id from multiple possible session keys
        $userId = 0;
        if (isset($_SESSION['user_id'])) $userId = (int)$_SESSION['user_id'];
        elseif (isset($_SESSION['User_ID'])) $userId = (int)$_SESSION['User_ID'];
        elseif (isset($_SESSION['user']['user_id'])) $userId = (int)$_SESSION['user']['user_id'];
        elseif (isset($_SESSION['user']['User_ID'])) $userId = (int)$_SESSION['user']['User_ID'];

        if (!$userId) {
            echo json_encode(['status' => 'error', 'message' => 'Not logged in']);
            exit;
        }

        $reservationDate = $_POST['reservation_date'] ?? '';
        $productIds = $_POST['product_id'] ?? [];

        if (empty($reservationDate)) {
            echo json_encode(['status' => 'error', 'message' => 'Reservation date is required']);
            exit;
        }

        if (empty($productIds) || !is_array($productIds)) {
            echo json_encode(['status' => 'error', 'message' => 'Please select at least one product to reserve']);
            exit;
        }

        $successCount = 0;
        foreach ($productIds as $productId) {
            $productId = (int)$productId;
            if ($productId <= 0) continue;

            $sql = "INSERT INTO reservation (User_ID, Product_ID, Reservation_Date, Payment_Status) VALUES (?, ?, ?, 'Pending')";
            $stmt = $conn->prepare($sql);
            if (!$stmt) {
                continue;
            }

            $stmt->bind_param('iis', $userId, $productId, $reservationDate);

            if ($stmt->execute()) {
                $successCount++;
            }
            $stmt->close();
        }

        if ($successCount > 0) {
            echo json_encode(['status' => 'success', 'message' => 'Reservation created successfully for ' . $successCount . ' product(s)']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Failed to create reservation']);
        }
        exit;
    }
    
    if (isset($_POST['action']) && $_POST['action'] === 'get_reservations') {
        // Suppress PHP errors to prevent JSON corruption
        error_reporting(0);
        ini_set('display_errors', 0);
        
        // Clear any output buffers that might have accidental content
        while (ob_get_level()) {
            ob_end_clean();
        }
        
        header('Content-Type: application/json');

        require_once __DIR__ . '/../../Config.php';
        global $conn;

        // Check if database connection exists
        if (!$conn) {
            echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
            exit;
        }

        // Resolve user id from multiple possible session keys
        $userId = 0;
        if (isset($_SESSION['user_id'])) $userId = (int)$_SESSION['user_id'];
        elseif (isset($_SESSION['User_ID'])) $userId = (int)$_SESSION['User_ID'];
        elseif (isset($_SESSION['user']['user_id'])) $userId = (int)$_SESSION['user']['user_id'];
        elseif (isset($_SESSION['user']['User_ID'])) $userId = (int)$_SESSION['user']['User_ID'];

        if (!$userId) {
            echo json_encode(['status' => 'error', 'message' => 'Not logged in']);
            exit;
        }

        // Automatically cancel expired pending reservations
        $cancelSql = "UPDATE reservation SET Payment_Status = 'Cancelled' WHERE User_ID = ? AND Payment_Status = 'Pending' AND Reservation_Date < NOW()";
        $cancelStmt = $conn->prepare($cancelSql);
        if ($cancelStmt) {
            $cancelStmt->bind_param('i', $userId);
            $cancelStmt->execute();
            $cancelStmt->close();
        }

        $sql = "SELECT r.Reservation_ID, r.Reservation_Date, r.Payment_Status, r.Product_ID,
                       COALESCE(p.Product_Name, 'Unknown Product') as Product_Name,
                       COALESCE(p.Price, 0) as Price
                FROM reservation r
                LEFT JOIN product p ON r.Product_ID = p.Product_ID
                WHERE r.User_ID = ?
                ORDER BY r.Reservation_Date DESC";        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            echo json_encode(['status' => 'error', 'message' => 'Failed to prepare statement: ' . $conn->error]);
            exit;
        }

        $stmt->bind_param('i', $userId);
        if (!$stmt->execute()) {
            echo json_encode(['status' => 'error', 'message' => 'Failed to execute query: ' . $stmt->error]);
            exit;
        }

        $result = $stmt->get_result();
        if (!$result) {
            echo json_encode(['status' => 'error', 'message' => 'Failed to get result: ' . $stmt->error]);
            exit;
        }

        $reservations = [];
        while ($row = $result->fetch_assoc()) {
            $raw = $row['Reservation_Date'] ?? null;
            $converted = '';
            if ($raw) {
                try {
                    $dt = new \DateTimeImmutable($raw, new \DateTimeZone('UTC'));
                    $converted = $dt->setTimezone(new \DateTimeZone('Asia/Manila'))->format(DATE_ATOM);
                } catch (\Throwable $e) {
                    $converted = (string)$raw;
                }
            }
            $row['Reservation_Date'] = $converted;
            $reservations[] = $row;
        }

        echo json_encode(['status' => 'success', 'reservations' => $reservations]);
        exit;
    }
    
    if (isset($_POST['action']) && $_POST['action'] === 'cancel_reservation') {
        // Suppress PHP errors to prevent JSON corruption
        error_reporting(0);
        ini_set('display_errors', 0);
        header('Content-Type: application/json');

        require_once __DIR__ . '/../../Config.php';
        global $conn;

        // Check if database connection exists
        if (!$conn) {
            echo json_encode(['status' => 'error', 'message' => 'Database connection failed']);
            exit;
        }

        // Resolve user id from multiple possible session keys
        $userId = 0;
        if (isset($_SESSION['user_id'])) $userId = (int)$_SESSION['user_id'];
        elseif (isset($_SESSION['User_ID'])) $userId = (int)$_SESSION['User_ID'];
        elseif (isset($_SESSION['user']['user_id'])) $userId = (int)$_SESSION['user']['user_id'];
        elseif (isset($_SESSION['user']['User_ID'])) $userId = (int)$_SESSION['user']['User_ID'];

        $reservationId = (int)($_POST['reservation_id'] ?? 0);

        if (!$userId || !$reservationId) {
            echo json_encode(['status' => 'error', 'message' => 'Invalid request']);
            exit;
        }

        $sql = "UPDATE reservation SET Payment_Status = 'Cancelled' WHERE Reservation_ID = ? AND User_ID = ? AND Payment_Status = 'Pending'";
        $stmt = $conn->prepare($sql);
        if (!$stmt) {
            echo json_encode(['status' => 'error', 'message' => 'Failed to prepare statement: ' . $conn->error]);
            exit;
        }

        $stmt->bind_param('ii', $reservationId, $userId);

        if ($stmt->execute() && $stmt->affected_rows > 0) {
            echo json_encode(['status' => 'success', 'message' => 'Reservation cancelled successfully']);
        } else {
            echo json_encode(['status' => 'error', 'message' => 'Failed to cancel reservation or reservation already processed: ' . $stmt->error]);
        }
        exit;
    }

    if (isset($_POST['checkout'])) {
        $orderData = json_decode($_POST['order_data'], true);
        $userId = $_SESSION['user']['user_id'] ?? null;
        if (!$userId) {
            echo json_encode(['status' => 'error', 'message' => 'Not logged in']);
            exit;
        }

        // Validate stock before placing order
        foreach ($orderData['items'] as $item) {
            $sql = "SELECT Stock_Quantity FROM product WHERE Product_Name = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('s', $item['name']);
            $stmt->execute();
            $result = $stmt->get_result();
            $prod = $result->fetch_assoc();
            if (!$prod || $prod['Stock_Quantity'] < $item['quantity']) {
                echo json_encode(['status' => 'error', 'message' => "Insufficient stock for {$item['name']}"]);
                exit;
            }
        }

        $total = $orderData['subtotal'] + $orderData['delivery_fee'];

        // Insert order
        $sql = "INSERT INTO orders (User_ID, Order_Date, Status, Total_Amount) VALUES (?, NOW(), 'Pending', ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('id', $userId, $total);
        if (!$stmt->execute()) {
            echo json_encode(['status' => 'error', 'message' => $conn->error]);
            exit;
        }
        $orderId = $conn->insert_id;

        // Insert order details + deduct stock
        foreach ($orderData['items'] as $item) {
            $subtotal = $item['price'] * $item['quantity'];

            // Get product ID
            $sql = "SELECT Product_ID FROM product WHERE Product_Name = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('s', $item['name']);
            $stmt->execute();
            $result = $stmt->get_result();
            $prod = $result->fetch_assoc();
            $productId = $prod['Product_ID'];

            // Insert detail
            $sql = "INSERT INTO order_detail (Order_ID, Product_ID, Quantity, unitprice, Subtotal) VALUES (?, ?, ?, ?, ?)";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('iiidd', $orderId, $productId, $item['quantity'], $item['price'], $subtotal);
            $stmt->execute();

            // Deduct stock
            $sql = "UPDATE product SET Stock_Quantity = Stock_Quantity - ? WHERE Product_ID = ?";
            $stmt = $conn->prepare($sql);
            $stmt->bind_param('ii', $item['quantity'], $productId);
            $stmt->execute();

            // Attempt to log inventory change in inventory_log table if it exists
            $logStmt = $conn->prepare('SELECT COUNT(*) AS cnt FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = "inventory_log" AND column_name = "User_ID" LIMIT 1');
            if ($logStmt) {
                $logStmt->execute();
                $res = $logStmt->get_result();
                $hasUserId = ($res && ($row = $res->fetch_assoc()) && (int)$row['cnt'] > 0);
                $logStmt->close();
                if ($hasUserId) {
                    $stmt2 = $conn->prepare('INSERT INTO inventory_log (Product_ID, User_ID, Action_Type, Quantity_Changed, Log_Date) VALUES (?, ?, "Remove", ?, NOW())');
                    if ($stmt2) {
                        $userIdParam = (int)($userId ?? 0);
                        $qty = (int)$item['quantity'];
                        $stmt2->bind_param('iii', $productId, $userIdParam, $qty);
                        $stmt2->execute();
                        $stmt2->close();
                    }
                }
            }
        }

        // Insert payment
        $paymentAmount = $orderData['amount_tendered'] ?? $total; // For GCash, use total
        $change = $orderData['change'] ?? 0;
        $method = $orderData['payment_method'];
        $sql = "INSERT INTO payment (User_ID, Payment_Method, Payment_Amount, Customer_Change) VALUES (?, ?, ?, ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('isdd', $userId, $method, $paymentAmount, $change);
        $stmt->execute();

        // Insert invoice
        $sql = "INSERT INTO invoice (User_ID, Invoice_Date, Total, Customer_Change, Invoice_Status, Mode_Payment) VALUES (?, NOW(), ?, ?, 'Completed', ?)";
        $stmt = $conn->prepare($sql);
        $stmt->bind_param('iids', $userId, $total, $change, $method);
        $stmt->execute();

        // Clear cart
        unset($_SESSION['cart']);

        // Return structured JSON including order id, status and change amount for the client to render
        echo json_encode([
            'status' => 'success',
            'order_id' => (int)$orderId,
            'order_status' => 'Pending',
            'change' => (float)$change
        ]);
        exit;
    }
    $controller->handleAjax();
    exit;
}

$selectedCategory = $_GET['category'] ?? 'all';
$products = $controller->getProductsByCategory($selectedCategory);
$cart = $controller->getCart();
$cart_count = $controller->countCartItems($cart);
$current_user = $_SESSION['user'] ?? [];
$showPurchaseHistory = isset($_GET['view']) && $_GET['view'] === 'history';
$purchaseOrders = [];

$recentOrders = [];
$userId = 0;

if (isset($current_user['user_id'])) {
    $userId = (int)$current_user['user_id'];
} elseif (isset($current_user['User_ID'])) {
    $userId = (int)$current_user['User_ID'];
} elseif (isset($_SESSION['user_id'])) {
    $userId = (int)$_SESSION['user_id'];
} elseif (isset($_SESSION['User_ID'])) {
    $userId = (int)$_SESSION['User_ID'];
}

if ($userId > 0) {
    try {
        $recentOrders = $controller->getRecentOrders($userId, 3);
    } catch (\Throwable $e) {
        error_log('Failed to load recent orders: ' . $e->getMessage());
    }
}

$announcements = [];
try {
    if (method_exists($controller, 'getActiveAnnouncements')) {
        $announcements = $controller->getActiveAnnouncements(5);
    }
} catch (\Throwable $e) {
    $announcements = [];
}

if ($showPurchaseHistory) {
    $userId = $_SESSION['user']['user_id'];

    // query: Use orders table, correct columns, show all orders with status
    $ordersQuery = "SELECT o.OrderID AS order_id, o.Order_Date AS order_date, o.Total_Amount AS total_amount, o.Status AS status 
                    FROM orders o 
                    WHERE o.User_ID = ? 
                    ORDER BY o.Order_Date DESC";
    $stmt = $conn->prepare($ordersQuery);
    $stmt->bind_param('i', $userId);
    $stmt->execute();
    $result = $stmt->get_result();
    $orders = $result->fetch_all(MYSQLI_ASSOC);

    // Fetch details for each order (since no 'items' column)
    foreach ($orders as &$order) {
        $detailsQuery = "SELECT p.Product_Name AS name, od.unitprice AS price, od.Quantity AS quantity
                         FROM order_detail od
                         JOIN product p ON od.Product_ID = p.Product_ID
                         WHERE od.Order_ID = ?";
        $detailStmt = $conn->prepare($detailsQuery);
        $detailStmt->bind_param('i', $order['order_id']);
        $detailStmt->execute();
        $detailResult = $detailStmt->get_result();
        $order['items'] = $detailResult->fetch_all(MYSQLI_ASSOC);
    }
    $purchaseOrders = $orders;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Guillermo’s Café</title>
<link rel="icon" type="image/x-icon" href="../../guillermos.ico">
  <link rel="shortcut icon" type="image/x-icon" href="../../guillermos.ico">

  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Pacifico&display=swap" rel="stylesheet">

<style>
    body{font-family:'Poppins',sans-serif;background:#fefcf7;margin:0;padding:0;}
    header{background:#6B4F3F;color:#fff;display:flex;justify-content:space-between;align-items:center;padding:15px 30px;position:relative;}
    .logo{font-size:1.8rem;font-weight:700;cursor:pointer;}
    .icon-btn{background:transparent;border:none;cursor:pointer;position:relative;}
.container{max-width:1200px;margin:0 auto;padding:20px 20px;}
    h2{margin-bottom:10px;color:#4d2e00;}
    .filter{margin-bottom:20px;}

    .announcement-banner{display:flex;gap:16px;align-items:flex-start;background:linear-gradient(135deg,#fff5e6,#fde3c7);border-radius:16px;padding:16px 20px;margin:18px 0;box-shadow:0 10px 25px rgba(77,46,0,0.12);}
    .announcement-icon{font-size:1.8rem;line-height:1;}
    .announcement-content{flex:1;display:flex;flex-direction:column;gap:12px;}
    .announcement-item{background:rgba(255,255,255,0.85);border-radius:12px;padding:10px 14px;box-shadow:0 4px 12px rgba(77,46,0,0.08);}
    .announcement-text{margin:0;color:#4d2e00;font-weight:600;line-height:1.4;}
    .announcement-meta{color:#8b6f58;font-size:0.85rem;margin-top:6px;display:flex;gap:16px;flex-wrap:wrap;}
    .announcement-dismiss{border:none;background:transparent;color:#6B4F3F;font-size:1.5rem;cursor:pointer;align-self:flex-start;}
    .announcement-dismiss:hover{color:#4d2e00;}

    /* ==== NEW SEARCH BAR STYLES ==== */
    .search-container {
        margin: 20px 0;
        display: flex;
        gap: 10px;
        align-items: center;
        flex-wrap: wrap;
    }
    .search-input {
        padding: 10px 14px;
        border: 1.5px solid #d4bca7;
        border-radius: 8px;
        font-size: 15px;
        width: 280px;
        max-width: 100%;
    
    }
   
    .search-input {
        width: auto;
        min-width: 180px;
    }


    .filter{margin-bottom:20px;}
    select{padding:8px;border:1px solid #d4bca7;border-radius:5px;background:#fff;}
    .product-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:20px;}
    .product{background:#fff;border-radius:10px;box-shadow:0 2px 6px rgba(0,0,0,.1);padding:18px;text-align:center;height:auto;min-height:200px;display:flex;flex-direction:column;justify-content:space-between;}
    .product-name{font-size:16px;font-weight:600;color:#3b2a19;}
    .product-desc{font-size:11px;color:#666;margin:5px 0;}
    .product-bottom{display:flex;justify-content:space-between;align-items:center;}
    /* Stock badges on product cards removed — stock shown in modal only */
    .price{color:#000;font-weight:600;font-size:15px;}
    .add-btn{background:#b57b46;color:#fff;border:none;border-radius:5px;padding:6px 10px;cursor:pointer;}
    .add-btn:hover{background:#a66d3d;}
    #cart-count{position:absolute;top:-8px;right:-10px;color:#d2232a;font-size:0.85rem;font-weight:700;padding:0;line-height:1;display:<?= $cart_count>0?'inline':'none' ?>;}
    
    

        /* ---- ORDER AGAIN STRIP ---- */
        .order-again-section{margin:10px 0 30px;padding:20px;border-radius:14px;background:linear-gradient(135deg,#fff8ef 0%,#fdeedc 100%);box-shadow:0 10px 25px rgba(79,46,10,0.12);}    
        .order-again-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:14px;flex-wrap:wrap;}
        .order-again-title{margin:0;font-size:1.35rem;font-weight:700;color:#4d2e00;}
        .order-again-subtitle{margin:2px 0 0;font-size:.9rem;color:#7b6654;}
        .order-again-view{border:none;background:#6B4F3F;color:#fff;padding:10px 20px;border-radius:999px;font-weight:600;cursor:pointer;transition:all .25s ease;}
        .order-again-view:hover{background:#5a3e30;}
        .order-again-cards{display:flex;gap:16px;overflow-x:auto;padding-bottom:6px;scrollbar-width:thin;}
        .order-again-cards::-webkit-scrollbar{height:8px;}
        .order-again-cards::-webkit-scrollbar-track{background:#f4e6d7;border-radius:10px;}
        .order-again-cards::-webkit-scrollbar-thumb{background:#d1a57a;border-radius:10px;}
        .order-again-card{flex:0 0 260px;background:#fff;border-radius:12px;padding:16px;display:flex;flex-direction:column;gap:12px;box-shadow:0 4px 16px rgba(0,0,0,0.08);border:2px solid transparent;transition:all .25s ease;}
        .order-again-card:hover{transform:translateY(-4px);border-color:#d1a57a;box-shadow:0 12px 26px rgba(79,46,10,0.18);}
        .order-card-date{font-size:.87rem;color:#856d58;display:flex;align-items:center;gap:6px;}
        .order-card-items{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:10px;}
        .order-card-item{display:flex;align-items:center;gap:10px;}
        .order-card-item img{width:44px;height:44px;border-radius:8px;object-fit:cover;box-shadow:0 2px 6px rgba(0,0,0,0.12);}
        .order-card-placeholder{width:44px;height:44px;border-radius:8px;background:#f0dec9;display:flex;align-items:center;justify-content:center;font-size:1.1rem;}
        .order-card-item-name{margin:0;font-size:.95rem;font-weight:600;color:#4d2e00;}
        .order-card-item-meta{margin:2px 0 0;font-size:.8rem;color:#8b7a6c;}
        .order-card-more{font-size:.82rem;color:#8b7a6c;font-style:italic;}
        .order-card-empty{font-size:.85rem;color:#8b7a6c;font-style:italic;}
        .order-card-total{font-size:1rem;font-weight:700;color:#6B4F3F;}
        .order-card-btn{display:flex;align-items:center;justify-content:center;gap:8px;border:none;background:#6B4F3F;color:#fff;padding:10px 0;border-radius:10px;font-weight:600;cursor:pointer;transition:all .25s ease;}
        .order-card-btn:hover{background:#5a3e30;transform:translateY(-1px);}
        .order-card-btn i{font-size:1.05rem;}


    /* ---------- OVERLAYS ---------- */
    .overlay{position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,.6);z-index:9998;display:none;align-items:center;justify-content:center;}
    .overlay-content{background:#f9f1e8;width:90%;max-width:800px;max-height:90vh;overflow-y:auto;padding:30px;border-radius:12px;box-shadow:0 4px 20px rgba(0,0,0,.2);position:relative;}
    .close-btn{position:absolute;top:15px;right:15px;background:none;border:none;font-size:24px;color:#666;cursor:pointer;}

    /* ---------- CART OVERLAY ---------- */
    .overlay-header h2{font-size:22px;color:#4d2e00;margin:0;}
    .overlay-header p{font-size:14px;color:#666;margin:5px 0 20px;}
    .cart-item{display:flex;align-items:center;gap:15px;padding:15px 0;border-bottom:1px solid #eee;animation: fadeInUp 0.5s ease forwards;opacity:0;animation-delay: calc(var(--item-index) * 0.1s);}
    .cart-item {
    display: flex;
    align-items: center;
    gap: 15px;
    padding: 15px 0;
    border-bottom: 1px solid #eee;
    opacity: 0;
}

@keyframes fadeInUp {
    from {
        opacity: 0;
        
    }
    to {
        opacity: 1;
        
    }
}
    .cart-item-img{width:60px;height:60px;border-radius:50%;overflow:hidden;background:#eee;}
    .cart-item-img img{width:100%;height:100%;object-fit:cover;}
    .cart-item-details{flex:1;}
    .cart-item-name{font-weight:600;color:#3b2a19;font-size:16px;}
    .cart-item-price{font-size:13px;color:#666;margin-top:2px;}
    .quantity-controls{display:flex;align-items:center;gap:8px;font-weight:bold;}
    .quantity-btn{background:#e6d5c3;color:#5b3a1e;padding:4px 10px;border-radius:5px;text-decoration:none;font-size:14px;cursor:pointer;}
    .quantity{display:inline-block;min-width:30px;text-align:center;}
    .line-total{font-weight:600;color:#3b2a19;margin-right:10px;}
    .remove-btn{color:red;font-weight:bold;font-size:18px;cursor:pointer;margin-left:10px;}
    .total{font-weight:bold;font-size:18px;margin:25px 0;text-align:right;color:#3b2a19;}
    .cart-actions{display:flex;justify-content:flex-end;gap:15px;margin-top:25px;}
    .btn{padding:12px 24px;border:none;border-radius:8px;font-weight:600;cursor:pointer;text-decoration:none;display:inline-block;}
    .btn-continue{background:#fff;border:2px solid #6B4F3F;color:#6B4F3F;}
    .btn-continue:hover{background:#f1e5d6;}
    .btn-checkout{background:#6B4F3F;color:#fff;}
    .btn-checkout:hover{background:#5a3e30;}


/* PRODUCT DETAILS MODAL */
#product-detail-overlay {
    position: fixed;
    top: 0; left: 0; width: 100%; height: 100%;
    background: rgba(0,0,0,0.7);
    display: none;
    align-items: center;
    justify-content: center;
    z-index: 9999;
}
.product-modal {
    background: #fff;
    width: 90%;
    max-width: 500px;
    border-radius: 20px;
    overflow: hidden;
    box-shadow: 0 20px 40px rgba(0,0,0,0.3);
    animation: zoomIn 0.4s ease;
}
.product-modal-img {
    width: 100%;
    height: 280px;
    object-fit: cover;
}
.product-modal-body {
    padding: 25px;
}
.product-modal-name {
    font-size: 1.6rem;
    font-weight: 700;
    color: #4d2e00;
    margin: 0 0 10px;
}
.product-modal-category {
    font-size: 0.9rem;
    color: #8B6F5F;
    margin-bottom: 12px;
    font-style: italic;
}
.product-modal-desc {
    color: #555;
    line-height: 1.6;
    margin-bottom: 20px;
}
.product-modal-price {
    font-size: 1.8rem;
    font-weight: 800;
    color: #6B4F3F;
    margin-bottom: 25px;
}
.product-modal-stock {font-weight:700;color:#4d2e00;margin-bottom:10px}
.product-modal-actions {
    display: flex;
    gap: 12px;
}
.btn-modal {
    flex: 1;
    padding: 14px;
    border: none;
    border-radius: 12px;
    font-weight: 600;
    font-size: 1rem;
    cursor: pointer;
    transition: all 0.3s;
}
.btn-modal:disabled {opacity:0.6;cursor:not-allowed}
.add-btn[disabled] {opacity:0.6;cursor:not-allowed}
.btn-add-cart {
    background: #b57b46;
    color: white;
}
.btn-add-cart:hover {background: #a66d3d;}
.btn-order-now {
    background: #6B4F3F;
    color: white;
}
.btn-order-now:hover {background: #5a3e30; transform: translateY(-2px);}

@keyframes zoomIn {
    from {transform: scale(0.8); opacity: 0;}
    to {transform: scale(1); opacity: 1;}
}

@keyframes spin {
    from {transform: rotate(0deg);}
    to {transform: rotate(360deg);}
}

   /* ---------- CHECKOUT STYLES ---------- */
    .checkout-modern {
    background: linear-gradient(135deg, #fefcf7 0%, #f5ece2 100%);
    padding: 28px 45px;  
    border-radius: 24px;
    max-width: 500px;
    width: 94%;
    margin: 0 auto;
    box-shadow: 0 20px 40px rgba(107, 79, 63, 0.18);
    position: relative;
    max-height: 90vh;
    overflow-y: auto;
}
    .form-group {margin-bottom: 18px;}
    .form-label {display: block;font-weight: 600;color: #4d2e00;margin-bottom: 8px;font-size: 0.95rem;}
    .form-control {
        width: 100%;
        padding: 12px 14px;
        border: 1.5px solid #ddd;
        border-radius: 12px;
        font-size: 15px;
        background: #fff;
        transition: all 0.2s;
    }
    .form-control:focus {
        outline: none;
        border-color: #6B4F3F;
        box-shadow: 0 0 0 3px rgba(107, 79, 63, 0.15);
    }

    .form-select {
        appearance: none;
        background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' fill='%236B4F3F' viewBox='0 0 16 16'%3E%3Cpath d='M8 11L3 6h10l-5 5z'/%3E%3C/svg%3E");
        background-repeat: no-repeat;
        background-position: right 14px center;
    }

    .toggle-reservation {
        display: flex;
        align-items: center;
        gap: 12px;
        margin-bottom: 16px;
    }

    .toggle-reservation label {
        font-weight: 600;
        color: #4d2e00;
        margin: 0;
        cursor: pointer;
    }

    .switch {
        position: relative;
        display: inline-block;
        width: 48px;
        height: 26px;
    }

    .switch input {
        opacity: 0;
        width: 0;
        height: 0;
    }

    .slider {
        position: absolute;
        cursor: pointer;
        top: 0;
        left: 0;
        right: 0;
        bottom: 0;
        background-color: #ccc;
        transition: .3s;
        border-radius: 34px;
    }

    .slider:before {
        position: absolute;
        content: "";
        height: 20px;
        width: 20px;
        left: 3px;
        bottom: 3px;
        background-color: white;
        transition: .3s;
        border-radius: 50%;
    }

    input:checked + .slider {
        background-color: #6B4F3F;
    }

    input:checked + .slider:before {
        transform: translateX(22px);
    }

    .order-summary {
        background: #f9f1e8;
        padding: 16px;
        border-radius: 12px;
        margin: 20px 0;
        font-size: 0.95rem;
    }

    .summary-row {
        display: flex;
        justify-content: space-between;
        margin-bottom: 8px;
        color: #5a3e30;
    }

    .summary-row.total {
        font-weight: bold;
        font-size: 1.1rem;
        color: #3b2a19;
        padding-top: 8px;
        border-top: 1px dashed #ccc;
        margin-top: 8px;
    }

    .btn-place-order {
        background: linear-gradient(135deg, #6B4F3F, #8B6F5F);
        color: #fff;
        border: none;
        width: 100%;
        padding: 14px;
        border-radius: 50px;
        font-weight: 600;
        font-size: 1.05rem;
        cursor: pointer;
        display: flex;
        align-items: center;
        justify-content: center;
        gap: 8px;
        transition: all 0.3s;
        box-shadow: 0 4px 15px rgba(107, 79, 63, 0.3);
    }

    .btn-place-order:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 20px rgba(107, 79, 63, 0.4);
    }

    .btn-place-order:active {
        transform: translateY(0);
    }

    /* Placing order overlay */
    #placing-overlay { position: fixed; inset: 0; display: none; align-items: center; justify-content: center; z-index: 10001; }
    #placing-overlay .content { background: rgba(255,255,255,0.98); padding: 24px 32px; border-radius: 12px; box-shadow: 0 8px 30px rgba(0,0,0,0.2); text-align: center; font-weight:700; color:#4d2e00; }

    /* ---------- THANK YOU SCREEN ---------- */
    .thankyou-screen{text-align:center;padding:40px;background:#fefcf7;border-radius:12px;max-width:600px;margin:0 auto;}
    .thankyou-img{margin-bottom:20px;}
    .thankyou-img img{width:120px;}
    .thankyou-title{font-size:1.8rem;font-weight:700;color:#4d2e00;margin-bottom:15px;}
    .thankyou-msg{color:#666;line-height:1.6;margin-bottom:30px;}
    .thankyou-actions{display:flex;gap:15px;justify-content:center;}
    /* When inside overlay-content make thankyou-screen a column and keep action at bottom */
    .overlay-content .thankyou-screen{display:flex;flex-direction:column;max-height:85vh;overflow-y:auto;box-sizing:border-box;padding:28px;}
    .overlay-content .thankyou-screen .thankyou-actions{margin-top:auto;padding-top:20px;}
    .thankyou-btn{background:#6B4F3F;color:#fff;padding:12px 24px;border-radius:50px;font-weight:600;cursor:pointer;}
    .thankyou-btn:hover{background:#5a3e30;}

    /* Success Message */
    .success-message {
        position: fixed;
        top: 20px;
        right: 20px;
        background: #4CAF50;
        color: white;
        padding: 16px 24px;
        border-radius: 12px;
        font-weight: 600;
        box-shadow: 0 4px 12px rgba(0,0,0,0.2);
        z-index: 9999;
        opacity: 0;
        transform: translateX(100%);
        transition: all 0.4s ease;
    }
.success-message.show {opacity: 1;transform: translateX(0);

}
/* Header icons */
header {
        display: flex;
        justify-content: space-between;
        align-items: center;
        padding: 15px 30px;
        background: #6B4F3F;
        color: #fff;
        position: relative;
    }
    .header-icons {display: flex;align-items: center;gap: 8px;}
    .icon-btn {
        background: none;
        border: none;
        color: white;
        font-size: 29px;
        cursor: pointer;
        padding: 8px;
        border-radius: 0;
        transition: all 0.2s ease;
        filter: brightness(0) invert(1);
    }
    .icon-btn:hover {background: rgba(255, 255, 255, 0.15);transform: scale(1.1);}
    .profile-btn {font-size: 30px;
    
}


.profile-btn {
    font-size: 30px;
}
/* Cart button wrapper */
.cart-wrapper {
    position: relative;
    display: inline-block;
}

/* Cart badge */
.cart-badge {
    position: absolute;
    top: -8px;
    right: -9px;
    background: #e74c3c;
    color: white;
    font-size: 12px;
    font-weight: bold;
    min-width: 8px;
    height: 11px;
    border-radius: 50%;
    display: <?= $cart_count > 0 ? 'flex' : 'none' ?>;
    z-index: 10;
}
/* Custom Profile Dropdown  */
.user-dropdown-menu.show {opacity: 1;visibility: visible;transform: translateY(0);}
    .dropdown-header {
        padding: 16px 20px 8px;
        color: #6B4F3F;
        font-weight: 600;
        font-size: 15px;
}

.dropdown-header div {
        font-size: 13px;
        color: #888;
        font-weight: normal;
}

.dropdown-link {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 20px;
        color: #4d2e00;
        text-decoration: none;
        font-size: 15px;
        font-weight: 500;
        transition: background 0.2s;
}

.dropdown-link:hover {background: #f9f1e8;color: #6B4F3F;}
    .dropdown-link i {font-size: 18px;width: 24px;text-align: center;}
    .text-danger {color: #e74c3c !important;}
    .text-danger:hover {background: #fdf2f2 !important;}
    .menu-divider {margin: 8px 0;border: none;border-top: 1px solid #eee;
}


/* USER PROFILE DROPDOWN */
.user-profile-wrapper {
    position: relative;
    display: inline-block;
}

.user-dropdown-menu {
    position: absolute;
    top: 58px;           
    right: 0;
    background: white;
    min-width: 220px;
    border-radius: 16px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.25);
    opacity: 0;
    visibility: hidden;
    transform: translateY(-10px);
    transition: all 0.25s ease;
    z-index: 99999;
    overflow: hidden;
}

.user-dropdown-menu.show {
    opacity: 1;
    visibility: visible;
    transform: translateY(0);
}

.dropdown-link {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 14px 20px;
    color: #4d2e00;
    text-decoration: none;
    font-size: 15px;
    font-weight: 500;
    transition: background 0.2s;
}

.dropdown-link:hover {
    background: #f9f1e8;
    color: #6B4F3F;
}

.dropdown-link i {
    font-size: 18px;
    width: 24px;
    text-align: center;
}

.text-danger { color: #e74c3c !important; }
.text-danger:hover { background: #fdf2f2 !important; }

.fadeInUp {
    animation: fadeInUp 0.5s ease-out;
}

/* Profile Modal Specific Padding Fix */
#profile-overlay .checkout-modern > div {
    padding: 32px 36px 40px !important;
    max-width: 450px;
    margin: 0 auto;
    min-height: 520px;
    display: flex;
    flex-direction: column;
}

/* ---------- CATEGORY TABS (FoodPanda style) ---------- */
.category-tabs {
    display: flex;
    gap: 0;
    overflow-x: auto;
    overflow-y: hidden;
    scrollbar-width: none;
    -ms-overflow-style: none;
    border-bottom: 1px solid #eee;
    scroll-behavior: smooth;
    width: 100%;
    margin-bottom: 20px;
}
.category-tabs::-webkit-scrollbar { display: none; }
.category-tab {
    flex-shrink: 0;
    padding: 10px 18px;
    background: #fff;
    border: none;
    border-bottom: 3px solid transparent;
    color: #666;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.2s;
    white-space: nowrap;
    display: flex;
    align-items: center;
    gap: 6px;
    min-width: fit-content;
    font-size: 14px;
}
.category-tab.active {
    color: #6B4F3F;
    border-bottom-color: #6B4F3F;
}
.category-tab:hover {
    color: #6B4F3F;
    background: #f9f1e8;
}

/* Landscape orientation adjustments */
@media (orientation: landscape) {
    .category-tabs {
        gap: 0;
    }
    .category-tab {
        padding: 10px 16px;
        font-size: 13px;
    }
}

@media (max-width: 768px) {
    .announcement-banner{flex-direction:column;}
    .announcement-dismiss{align-self:flex-end;}
}

/* ---------- TOP PRODUCTS SLIDESHOW ---------- */
.top-products-container {
    margin-bottom: 30px;
}
.slideshow-container {
    position: relative;
    max-width: 100%;
    margin: auto;
    overflow-x: auto;
    -webkit-overflow-scrolling: touch;
    border-radius: 10px;
}
.slideshow {
    display: flex;
    gap: 20px;
    width: max-content;
}
.slide {
    min-width: 100%;
    display: flex;
    gap: 20px;
    justify-content: flex-start;
    flex-shrink: 0;
}
.prev, .next {
    position: absolute;
    top: 50%;
    transform: translateY(-50%);
    background: rgba(0,0,0,0.5);
    color: white;
    border: none;
    padding: 10px;
    cursor: pointer;
    border-radius: 50%;
    font-size: 18px;
    z-index: 10;
}
.prev { left: 10px; }
.next { right: 10px; }

/* ---------- BOTTOM CART BAR ---------- */
.bottom-cart-bar {
    position: fixed;
    bottom: 0;
    left: 0;
    right: 0;
    background: #fff;
    border-top: 1px solid #ddd;
    padding: 16px 20px;
    display: none;
    box-shadow: 0 -2px 10px rgba(0,0,0,0.1);
    z-index: 1000;
}
.cart-bar-content {
    display: flex;
    justify-content: space-between;
    align-items: center;
    max-width: 1200px;
    margin: 0 auto;
}
.cart-bar-left {
    display: flex;
    align-items: center;
    gap: 12px;
}
.cart-bar-icon {
    width: 40px;
    height: 40px;
    background: #6B4F3F;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    color: white;
}
.cart-bar-text {
    font-weight: 600;
    color: #4d2e00;
}
.cart-bar-subtotal {
    color: #6B4F3F;
    font-weight: 700;
}
.view-cart-btn {
    background: #6B4F3F;
    color: white;
    border: none;
    padding: 12px 24px;
    border-radius: 25px;
    font-weight: 600;
    cursor: pointer;
    transition: background 0.2s;
}
.view-cart-btn:hover {
    background: #5a3e30;
}


</style>
</head>
<body>

<!-- ADD TO CART SUCCESS TOAST -->
<div id="add-to-cart-toast" class="success-message" style="background:#6B4F3F; display:none;">
    ✅
    <span id="toast-product-name"></span> added to cart!
</div>

<header>
    <div class="logo" onclick="location.reload()">Guillermo’s</div>

    <div class="top-right-icons">

        <!-- Cart Button -->
<button class="icon-btn" id="open-cart" aria-label="Open Cart">
    🛒
    <span id="cart-count" class="badge-top-right">
        <?= $cart_count ?>
    </span>
</button>
        <!-- CUSTOMER PROFILE -->
        <div class="user-profile-wrapper">
            <button class="icon-btn profile-btn" id="userIcon">
                👤
            </button>

            <!-- Dropdown Menu -->
            <div class="user-dropdown-menu" id="userDropdown">
                <div class="dropdown-header">
                    <?= htmlspecialchars($current_user['Name'] ?? 'Customer') ?>
                    <div><?= htmlspecialchars($current_user['Email'] ?? '') ?></div>
                </div>
                <hr class="menu-divider">
                <a href="#" class="dropdown-link" onclick="openProfileModal(); return false;">
                    👤 My Profile
                </a>
                <a href="?view=history" class="dropdown-link" onclick="event.preventDefault(); showPurchaseHistory();">
                <i class="bi bi-clock-history"></i> Purchase History
                </a>
                <a href="#" class="dropdown-link" onclick="event.preventDefault(); showReservations();">
                <i class="bi bi-calendar-check"></i> My Reservations
                </a>
                <hr class="menu-divider">
                <a href="../../index.php" class="dropdown-link text-danger">
                    <i class="bi bi-box-arrow-right"></i> Logout
                </a>
            </div>
        </div>

    </div>
</header>

<!-- PRODUCT DETAILS MODAL -->
<div id="product-detail-overlay">
    <div class="product-modal">
        <img id="modal-img" class="product-modal-img" src="" alt="">
        <div class="product-modal-body">
            <button class="close-btn" id="close-product-modal" style="position:absolute;top:15px;right:15px;background:none;border:none;font-size:28px;color:#999;">×</button>
            
            <h3 id="modal-name" class="product-modal-name"></h3>
            <div id="modal-category" class="product-modal-category"></div>
            <p id="modal-desc" class="product-modal-desc"></p>
            <div id="modal-price" class="product-modal-price"></div>
            
            <div id="modal-stock" class="product-modal-stock" style="display:none;">&nbsp;</div>
            <div class="product-modal-actions">
                <button class="btn-modal btn-add-cart" id="modal-add-to-cart">
                    ➕ Add to Cart
                </button>
                <button class="btn-modal btn-order-now" id="modal-order-now">
                    ⚡ Order Now
                </button>
            </div>
        </div>
    </div>
</div>

<!-- CART OVERLAY -->
<div id="cart-overlay" class="overlay">
    <div class="overlay-content">
        <button class="close-btn" id="close-cart">X</button>
        <div class="overlay-header">
            <h2>My Cart</h2>
            <p>Review your items before checkout</p>
        </div>
        <div id="cart-items"></div>
        <div class="total">TOTAL: <span id="cart-total">₱0.00</span></div>
        <div class="cart-actions">
            <button class="btn btn-continue" id="continue-shopping">Continue Shopping</button>
            <button class="btn btn-checkout" id="proceed-checkout">Proceed to Checkout</button>
        </div>
    </div>
</div>

<!-- Inside cart items -->
    <div id="empty-cart-message" style="text-align:center;color:#888;padding:60px 0;font-size:1.1rem;display:none;">
        🛒
        Your cart is empty.<br>
        <small style="color:#aaa;">Start adding your favorite items!</small>
    </div>

<!-- MY RESERVATIONS OVERLAY -->
<div id="reservations-overlay" class="overlay" style="display:none;">
    <div class="overlay-content" style="max-width:980px; width:95%;">
        <button class="close-btn" onclick="closeReservations()">×</button>

        <div style="text-align:center;margin-bottom:20px;">
            <h2 style="color:#4d2e00;margin:0;font-size:1.5rem;font-weight:700;">📅 My Reservations</h2>
            <p style="color:#888;font-size:14px;margin:8px 0 0;">View and manage your table reservations</p>
        </div>

        <div style="margin-bottom:20px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:10px;">
            <button class="btn btn-quick" onclick="openCreateReservation()" style="min-width:200px;">
                <i class="bi bi-plus-circle me-2"></i> Create New Reservation
            </button>
            <input id="reservation-search" type="text" placeholder="🔍 Search reservations..." class="search-input" style="max-width:300px;padding:10px 16px;border:2px solid #e2d7c8;border-radius:10px;font-size:14px;">
        </div>

        <style>
            .reservation-card { 
                background: #fff; 
                border-radius: 12px; 
                margin-bottom: 16px; 
                box-shadow: 0 2px 8px rgba(0,0,0,0.08); 
                overflow: hidden;
                transition: all 0.3s;
            }
            .reservation-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.12); }
            
            .reservation-header { 
                background: linear-gradient(135deg, #6B4F3F 0%, #8B6F5F 100%); 
                color: #fff; 
                padding: 16px 20px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                flex-wrap: wrap;
                gap: 12px;
            }
            .reservation-id { font-size: 14px; font-weight: 600; }
            .reservation-date { font-size: 16px; font-weight: 700; }
            .reservation-status { display: flex; align-items: center; gap: 16px; }
            
            .status-badge-res { 
                padding: 6px 12px; 
                border-radius: 20px; 
                font-size: 11px; 
                font-weight: 700; 
                text-transform: uppercase; 
                letter-spacing: 0.5px;
            }
            .status-pending { background: #fff3cd; color: #856404; }
            .status-confirmed { background: #d4edda; color: #155724; }
            .status-cancelled { background: #f8d7da; color: #721c24; }
            .status-completed { background: #cfe2ff; color: #084298; }
            
            .reservation-body { padding: 20px; }
            .reservation-info { display: flex; gap: 30px; flex-wrap: wrap; margin-bottom: 15px; }
            .info-item { display: flex; flex-direction: column; }
            .info-label { font-size: 12px; color: #888; text-transform: uppercase; margin-bottom: 4px; }
            .info-value { font-size: 15px; color: #4d2e00; font-weight: 600; }
            
            .reservation-actions { 
                padding: 14px 20px; 
                background: #fafafa; 
                display: flex; 
                justify-content: flex-end;
                gap: 10px;
            }
        </style>

        <div id="no-reservations-message" style="display:none;text-align:center;padding:48px 20px;color:#888;">
            <div style="font-size:2rem;">📅</div>
            <div style="font-weight:700;margin-top:10px;color:#6B4F3F;">No reservations found</div>
            <div style="font-size:0.95rem;color:#aaa;margin-top:6px;">Your reservations will appear here once you create one.</div>
        </div>

        <div id="reservations-list" class="orders-container" style="display:none;max-height:65vh;overflow-y:auto;padding:8px;">
            <!-- Reservation cards will be inserted here by JS -->
        </div>
    </div>
</div>

<!-- CREATE RESERVATION MODAL -->
<div id="create-reservation-modal" class="overlay" style="display:none;">
    <div class="checkout-modern" style="max-width:500px;">
        <button class="close-btn" onclick="closeCreateReservation()" style="position:absolute;top:15px;right:15px;">×</button>
        <h2 style="color:#4d2e00;margin-bottom:20px;font-size:1.5rem;font-weight:700;">
            <i class="bi bi-calendar-plus me-2"></i>Create New Reservation
        </h2>
        
        <form id="create-reservation-form">
            <div class="form-group" style="margin-bottom:20px;">
                <label class="form-label">Reservation Date & Time <span class="text-danger">*</span></label>
                <input type="datetime-local" class="form-control" id="reservation-date-input" name="reservation_date" required style="padding:12px;border:1.5px solid #ddd;border-radius:12px;font-size:15px;">
                <small style="color:#888;font-size:0.9rem;margin-top:5px;display:block;">Select your preferred date and time</small>
            </div>
            
            <div class="form-group" style="margin-bottom:20px;">
                <label class="form-label">Select Products to Reserve <span class="text-danger">*</span></label>
                <select id="reservation-product-select" class="form-control" name="product_id[]" multiple required style="padding:12px;border:1.5px solid #ddd;border-radius:12px;font-size:15px;min-height:120px;">
                    <?php
                    $allProducts = $controller->getProductsByCategory('all');
                    foreach ($allProducts as $p) {
                        echo '<option value="' . $p['Product_ID'] . '">' . htmlspecialchars($p['Product_Name']) . ' - ₱' . number_format($p['Price'], 2) . '</option>';
                    }
                    ?>
                </select>
                <small style="color:#888;font-size:0.9rem;margin-top:5px;display:block;">Hold Ctrl (or Cmd on Mac) to select multiple products</small>
            </div>
            
            <div style="display:flex;gap:10px;">
                <button type="button" class="btn btn-secondary" onclick="closeCreateReservation()" style="flex:1;padding:12px;border-radius:8px;">Cancel</button>
                <button type="submit" class="btn-quick" style="flex:1;padding:12px;border-radius:8px;border:none;">
                    <i class="bi bi-check-circle me-2"></i>Create Reservation
                </button>
            </div>
        </form>
    </div>
</div>

<!-- FEEDBACK MODAL -->
<div id="feedback-modal" class="overlay" style="display:none;">
    <div class="checkout-modern" style="max-width:550px;">
        <button class="close-btn" onclick="closeFeedbackModal()" style="position:absolute;top:15px;right:15px;background:none;border:none;font-size:32px;color:#888;cursor:pointer;z-index:10;">×</button>
        <h2 style="color:#4d2e00;margin-bottom:20px;font-size:1.5rem;font-weight:700;">
            <i class="bi bi-star-fill me-2" style="color:#ffc107;"></i>Rate Your Order
        </h2>
        
        <form id="feedback-form">
            <input type="hidden" id="feedback-order-id" name="order_id">
            
            <div class="form-group" style="margin-bottom:25px;">
                <label class="form-label" style="display:block;margin-bottom:12px;font-weight:600;color:#4d2e00;">How was your experience?</label>
                <div id="star-rating" style="display:flex;gap:8px;justify-content:center;font-size:40px;margin:15px 0;">
                    <span class="star" data-rating="1" style="cursor:pointer;color:#ddd;transition:all 0.2s;">★</span>
                    <span class="star" data-rating="2" style="cursor:pointer;color:#ddd;transition:all 0.2s;">★</span>
                    <span class="star" data-rating="3" style="cursor:pointer;color:#ddd;transition:all 0.2s;">★</span>
                    <span class="star" data-rating="4" style="cursor:pointer;color:#ddd;transition:all 0.2s;">★</span>
                    <span class="star" data-rating="5" style="cursor:pointer;color:#ddd;transition:all 0.2s;">★</span>
                </div>
                <input type="hidden" id="rating-value" name="rating" required>
                <div id="rating-error" style="color:#e74c3c;font-size:14px;text-align:center;display:none;margin-top:8px;">Please select a rating</div>
            </div>
            
            <div class="form-group" style="margin-bottom:20px;">
                <label class="form-label" style="font-weight:600;color:#4d2e00;">Tell us more about your experience (optional)</label>
                <textarea class="form-control" id="feedback-comment" name="comment" rows="4" placeholder="Share your thoughts about the food quality, delivery, service..." style="padding:12px;border:1.5px solid #ddd;border-radius:12px;font-size:15px;resize:vertical;"></textarea>
                <small style="color:#888;font-size:0.9rem;margin-top:5px;display:block;">Your feedback helps us improve our service</small>
            </div>
            
            <div style="display:flex;gap:10px;">
                <button type="button" class="btn btn-secondary" onclick="closeFeedbackModal()" style="flex:1;padding:12px;border-radius:8px;">Cancel</button>
                <button type="submit" class="btn-quick" style="flex:1;padding:12px;border-radius:8px;border:none;background:linear-gradient(135deg, #ffc107 0%, #ff9800 100%);">
                    <i class="bi bi-send-fill me-2"></i>Submit Feedback
                </button>
            </div>
        </form>
    </div>
</div>

<!-- USER PROFILE-->
<div id="profile-overlay" class="overlay">
    <div class="checkout-modern" style="position:relative;">
        <div style="padding:32px 36px 40px;max-width:450px;margin:0 auto;">
            <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;">
                <h1 style="font-size:1.6rem;color:#4d2e00;margin:0;font-weight:600;">
                    👤
                    My Profile
                </h1>
                <button class="close-btn" id="close-profile" style="background:none;border:none;font-size:32px;color:#888;cursor:pointer;">×</button>
            </div>

            <div style="text-align:center;margin-bottom:25px;">
                <div style="width:70px;height:70px;background:linear-gradient(135deg,#f0e6d6,#e8dcc4);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;box-shadow:0 4px 12px rgba(107,79,63,0.15);">
                    👤
                </div>
                <p style="color:#666;font-size:0.95rem;margin:0;">Update your personal information</p>
            </div>

            <form id="profile-form">
                <div class="form-group">
                    <label class="form-label">👤 Full Name <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" name="name" value="<?= htmlspecialchars($current_user['Name'] ?? '') ?>" required>
                </div>

                <div class="form-group">
                    <i class='bi bi-tag-fill' style='color:#b57b46;'></i> Username <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" name="username" value="<?= htmlspecialchars($current_user['Username'] ?? '') ?>" required>
                </div>

                <div class="form-group">
                     <i class='bi bi-envelope-fill' style='color:#a0845c;'></i> Email Address <small style="color:#888;font-size:0.85rem;">(read-only)</small>
                    <input type="email" class="form-control" name="email" value="<?= htmlspecialchars($current_user['Email'] ?? '') ?>" readonly style="background:#f8f9fa;color:#6c757d;">
                </div>

                <div class="form-group">
                    <i class='bi bi-telephone-fill' style='color:#c1976b;'></i> Phone Number <small style="color:#888;font-size:0.85rem;">(read-only)</small>
                    <input type="text" class="form-control" name="phonenumber" value="<?= htmlspecialchars($current_user['Phonenumber'] ?? '') ?>" readonly style="background:#f8f9fa;color:#6c757d;">
                </div>

                <div style="text-align:right;margin-top:30px;">
          <button type="submit" class="btn-place-order" style="width:100%;padding:14px;font-size:1rem;background:linear-gradient(135deg,#6f4e37,#b57b46);color:#fff;border:none;border-radius:50px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 15px rgba(107,79,63,0.3);">
            <i class='bi bi-check2-square' style='font-size:1.2rem;'></i> Save Changes
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>
<!-- PURCHASE HISTORY OVERLAY -->
<div id="purchase-history-overlay" class="overlay" style="display:none;">
    <div class="overlay-content" style="max-width:980px; width:95%;">
        <button class="close-btn" onclick="closePurchaseHistory()">×</button>

        <div style="text-align:center;margin-bottom:20px;">
            <h2 style="color:#4d2e00;margin:0;font-size:1.5rem;font-weight:700;">🕒 Purchase History</h2>
            <p style="color:#888;font-size:14px;margin:8px 0 0;">View and manage your past orders</p>
        </div>

        <div style="margin-bottom:20px;">
            <input id="purchase-search" type="text" placeholder="🔍 Search by item name or date..." class="search-input" style="width:100%;padding:12px 16px;border:2px solid #e2d7c8;border-radius:10px;font-size:14px;">
        </div>

        <style>
            /* Purchase history card-based design */
            #purchase-history-overlay .overlay-content { max-width: 900px; }
            #purchase-history-overlay .orders-container { max-height: 65vh; overflow-y: auto; padding: 8px; }
            
            .order-card { 
                background: #fff; 
                border-radius: 12px; 
                margin-bottom: 16px; 
                box-shadow: 0 2px 8px rgba(0,0,0,0.08); 
                overflow: hidden;
                transition: all 0.3s;
            }
            .order-card:hover { box-shadow: 0 4px 16px rgba(0,0,0,0.12); }
            
            .order-header-card { 
                background: linear-gradient(135deg, #6B4F3F 0%, #8B6F5F 100%); 
                color: #fff; 
                padding: 16px 20px; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                flex-wrap: wrap;
                gap: 12px;
            }
            .order-date-time { font-size: 14px; font-weight: 600; }
            .order-date-time small { display: block; font-size: 12px; opacity: 0.9; margin-top: 2px; }
            .order-status-total { display: flex; align-items: center; gap: 16px; flex-wrap: wrap; }
            .order-total-amount { font-size: 18px; font-weight: 700; }
            
            .status-badge { 
                padding: 6px 12px; 
                border-radius: 20px; 
                font-size: 11px; 
                font-weight: 700; 
                text-transform: uppercase; 
                letter-spacing: 0.5px;
            }
            .status-completed { background: #d4edda; color: #155724; }
            .status-pending { background: #fff3cd; color: #856404; }
            .status-cancelled { background: #f8d7da; color: #721c24; }
            
            .order-items { padding: 0; }
            .order-item-row { 
                padding: 14px 20px; 
                border-bottom: 1px solid #f3ece3; 
                display: flex; 
                justify-content: space-between; 
                align-items: center;
                gap: 12px;
                transition: background 0.2s;
            }
            .order-item-row:hover { background: #fffbf7; }
            .order-item-row:last-child { border-bottom: none; }
            
            .item-name-qty { flex: 1; }
            .item-name { font-weight: 600; color: #4d2e00; font-size: 15px; }
            .item-qty { color: #888; font-size: 13px; margin-top: 2px; }
            
            .item-prices { display: flex; gap: 16px; align-items: center; }
            .item-price { color: #6B4F3F; font-weight: 600; font-size: 14px; }
            .item-subtotal { color: #6B4F3F; font-weight: 700; font-size: 15px; }
            
            .order-actions { 
                padding: 14px 20px; 
                background: #fafafa; 
                display: flex; 
                justify-content: flex-end;
            }
            
            .action-btn { 
                padding: 10px 20px; 
                border-radius: 8px; 
                border: none; 
                cursor: pointer; 
                font-weight: 600; 
                font-size: 13px;
                transition: all 0.3s;
                box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                display: inline-flex;
                align-items: center;
                gap: 4px;
            }
            .buy-again { background: linear-gradient(135deg, #b57b46 0%, #8B6F5F 100%); color: #fff; }
            .buy-again:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(181,123,70,0.3); }
            .feedback-btn { background: linear-gradient(135deg, #ffc107 0%, #ff9800 100%); color: #fff; }
            .feedback-btn:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(255,193,7,0.3); }
            .cancel-order { background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%); color: #fff; }
            .cancel-order:hover { transform: translateY(-2px); box-shadow: 0 4px 8px rgba(231,76,60,0.3); }
            .action-disabled { background: #ddd; color: #888; cursor: not-allowed; }
            
            /* Reservation overlay background */
            #reservations-overlay .overlay { background: rgba(0,0,0,0.6); }
            #create-reservation-modal .overlay { background: rgba(0,0,0,0.6); }
        </style>

        <div id="no-orders-message" style="display:none;text-align:center;padding:48px 20px;color:#888;">
            <div style="font-size:2rem;">📦</div>
            <div style="font-weight:700;margin-top:10px;color:#6B4F3F;">No orders found</div>
            <div style="font-size:0.95rem;color:#aaa;margin-top:6px;">Your order history will appear here once you place your first order.</div>
        </div>

        <div id="purchase-history-cards" class="orders-container" style="display:none;">
            <!-- Order cards will be inserted here by JS -->
        </div>
    </div>
</div>

<!-- CHECKOUT SCREEN -->
<div id="checkout-screen" class="overlay" style="display:none;">
    <div class="checkout-modern">
        <div class="checkout-card">
            <div class="checkout-card-header">
                <button class="back-btn" id="back-to-cart">
                    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M19 12H5M12 19l-7-7 7-7"/>
                    </svg>
                </button>
                <h1>Complete Your Order</h1>
                <div class="cart-badge">
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <circle cx="9" cy="21" r="1"/><circle cx="20" cy="21" r="1"/>
                        <path d="M1 1h4l2.68 13.39a2 2 0 0 0 2 1.61h9.72a2 2 0 0 0 2-1.61L23 6H6"/>
                    </svg>
                    <span id="checkout-cart-count">0</span>
                </div>
            </div>

            <div class="checkout-card-body">

                <!-- Customer Name -->
                <div class="form-group">
                    <label class="form-label">Full Name <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="customer_name" placeholder="e.g. Juan Dela Cruz" value="<?= htmlspecialchars($current_user['Name'] ?? '') ?>" required>
                </div>

                <!-- Delivery Address  -->
                <div class="form-group">
                    <label class="form-label">Delivery Address <span class="text-danger">*</span></label>
                    <input type="text" class="form-control" id="house_street" placeholder="House #, Street Name" required style="margin-bottom:10px;">
                    <select class="form-control form-select" id="barangay" required style="margin-bottom:10px;">
                        <option value="">Select Barangay</option>
                        <option value="Barangay 1 (Pob.)">Barangay 1 (Pob.)</option>
                        <option value="Barangay 2 (Pob.)">Barangay 2 (Pob.)</option>
                        <option value="Barangay 3 (Pob.)">Barangay 3 (Pob.)</option>
                        <option value="Barangay 4 (Pob.)">Barangay 4 (Pob.)</option>
                        <option value="Barangay 5 (Pob.)">Barangay 5 (Pob.)</option>
                        <option value="Barangay 6 (Pob.)">Barangay 6 (Pob.)</option>
                        <option value="Barangay 7 (Pob.)">Barangay 7 (Pob.)</option>
                        <option value="Barangay 8 (Pob.)">Barangay 8 (Pob.)</option>
                        <option value="Barangay 9 (Pob.)">Barangay 9 (Pob.)</option>
                        <option value="Barangay 10 (Pob.)">Barangay 10 (Pob.)</option>
                        <option value="Barangay 11 (Pob.)">Barangay 11 (Pob.)</option>
                        <option value="Barangay 12 (Pob.)">Barangay 12 (Pob.)</option>
                        <option value="Bucana">Bucana</option>
                        <option value="Talangan">Talangan</option>
                    </select>
                    <input type="text" class="form-control" id="city" value="Nasugbu, Batangas" readonly style="background:#f5f5f5;cursor:not-allowed;">
                    <small style="color:#888;font-size:0.9rem;margin-top:5px;display:block;">
                        <i class="bi bi-info-circle"></i> We only deliver within Nasugbu, Batangas
                    </small>
                </div>

                <!-- Payment Method -->
                <div class="form-group">
                    <label class="form-label">Payment Method <span class="text-danger">*</span></label>
                    <select class="form-control form-select" id="payment_method" required>
                        <option value="cash" selected>Cash on Delivery (Pay upon arrival)</option>
                        <option value="gcash" disabled>GCash (currently unavailable)</option>
                    </select>
                    <div style="margin-top:8px;font-size:0.9rem;color:#a0845c;">Driver will collect your payment when the order is delivered.</div>
                </div>

                <!-- Order Summary -->
                <div class="order-summary">
                    <div class="summary-row">
                        <span>Subtotal</span>
                        <span id="checkout-subtotal">₱0.00</span>
                    </div>
                    <div class="summary-row">
                        <span>Delivery Fee</span>
                        <span id="checkout-delivery-fee">₱0.00</span>
                    </div>
                    <div class="summary-row total">
                        <strong>Total Amount Due</strong>
                        <strong id="checkout-total">₱0.00</strong>
                    </div>
                </div>

                <button class="btn-place-order" id="finalize-order">
                    <span id="place-order-text">Place Order</span>
                    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                        <path d="M5 12h14M12 5l7 7-7 7"/>
                    </svg>
                </button>
            </div>
        </div>
    </div>
</div>

<!-- THANK YOU SCREEN -->
<div id="thankyou-screen" class="overlay" style="display:none;">
    <div class="thankyou-screen">
        <div class="thankyou-img">
            <img src="icons/cafee.png" alt="Thank you">
        </div>
        <div class="thankyou-title">🎉 Order Complete!</div>
        <div class="thankyou-msg" id="delivery-message">
            Your order has been confirmed and is now being prepared.<br>
            Thank you for choosing Guillermo’s Café!
        </div>
        <div class="thankyou-actions">
            <button class="thankyou-btn" id="back-home">BACK TO HOME</button>
        </div>
    </div>
</div>

<div class="container">

    <!-- PLACING ORDER OVERLAY -->
    <div id="placing-overlay" style="display:none;">
        <div class="content">Finalizing your order... Please wait.</div>
    </div>

    <?php if (!empty($announcements)): ?>
    <section class="announcement-banner" id="customerAnnouncements">
        <div class="announcement-icon">📢</div>
        <div class="announcement-content">
            <?php foreach ($announcements as $announcement): ?>
                <div class="announcement-item">
                    <p class="announcement-text"><?= nl2br(htmlspecialchars($announcement['message'] ?? '')) ?></p>
                    <?php if (!empty($announcement['created_at_formatted']) || !empty($announcement['expires_at_formatted'])): ?>
                        <div class="announcement-meta">
                            <?php if (!empty($announcement['created_at_formatted'])): ?>
                                <span>Posted <?= htmlspecialchars($announcement['created_at_formatted']) ?></span>
                            <?php endif; ?>
                            <?php if (!empty($announcement['expires_at_formatted'])): ?>
                                <span>Expires <?= htmlspecialchars($announcement['expires_at_formatted']) ?></span>
                            <?php endif; ?>
                        </div>
                    <?php endif; ?>
                </div>
            <?php endforeach; ?>
        </div>
        <button type="button" class="announcement-dismiss" id="dismissAnnouncements" aria-label="Dismiss announcements">×</button>
    </section>
    <?php endif; ?>

    <?php
        // Remove orders that have no available items (items array empty)
        $recentOrdersAvailable = [];
        if (!empty($recentOrders) && is_array($recentOrders)) {
            foreach ($recentOrders as $order) {
                if (!empty($order['items']) && is_array($order['items'])) {
                    $recentOrdersAvailable[] = $order;
                }
            }
        }
    ?>
    <?php if (!empty($recentOrdersAvailable)): ?>
    <section class="order-again-section">
        <div class="order-again-header">
            <div>
                <h3 class="order-again-title">Want to Order Again?</h3>
                <p class="order-again-subtitle">Reorder your recent favorites in just a tap.</p>
            </div>
            <button type="button" class="order-again-view" onclick="showPurchaseHistory();">View Purchase History</button>
        </div>
        <div class="order-again-cards">
            <?php foreach ($recentOrdersAvailable as $order): ?>
                <article class="order-again-card">
                    <div class="order-card-date">
                        <i class="bi bi-calendar-check"></i>
                        <?= (function($raw) {
                            if (!$raw) return '';
                            try {
                                $dt = new \DateTimeImmutable($raw);
                                return $dt->setTimezone(new \DateTimeZone('Asia/Manila'))->format('M d, Y');
                            } catch (\Throwable $e) {
                                return date('M d, Y', strtotime($raw));
                            }
                        })($order['Order_Date']) ?>
                    </div>
                    <ul class="order-card-items">
                        <?php if (!empty($order['items'])): ?>
                            <?php $displayCount = min(3, count($order['items'])); ?>
                            <?php for ($i = 0; $i < $displayCount; $i++): $item = $order['items'][$i]; ?>
                                <li class="order-card-item">
                                    <?php if (!empty($item['Image'])): ?>
                                        <img src="<?= $item['Image'] ?>" alt="<?= htmlspecialchars($item['Product_Name']) ?>">
                                    <?php else: ?>
                                        <span class="order-card-placeholder">🍽️</span>
                                    <?php endif; ?>
                                    <div>
                                        <p class="order-card-item-name"><?= htmlspecialchars($item['Product_Name']) ?></p>
                                        <p class="order-card-item-meta">Qty: <?= (int)$item['Quantity'] ?></p>
                                    </div>
                                </li>
                            <?php endfor; ?>
                            <?php if (count($order['items']) > 3): ?>
                                <li class="order-card-more">+<?= count($order['items']) - 3 ?> more item(s)</li>
                            <?php endif; ?>
                        <?php else: ?>
                            <li class="order-card-empty">Items no longer available for preview</li>
                        <?php endif; ?>
                    </ul>
                    <div class="order-card-total">Total: ₱<?= number_format((float)$order['Total_Amount'], 2) ?></div>
                    <button type="button" class="order-card-btn" onclick="orderAgain(<?= $order['OrderID'] ?>);">
                        <i class="bi bi-cart-plus"></i>
                        Order Again
                    </button>
                </article>
            <?php endforeach; ?>
        </div>
    </section>
    <?php endif; ?>

    <!-- ==== SEARCH + CATEGORY TABS ==== -->
<div style="display: flex; justify-content: space-between; align-items: center; flex-wrap: wrap; gap: 15px; margin: 20px 0;">
    <!-- Search Bar  -->
    <div class="search-container" style="display:flex; gap:10px;">
        <input type="text" id="search-input" class="search-input" placeholder="Search products..." autocomplete="off">
    </div>
</div>

<!-- Category Tabs -->
<div style="display: flex; align-items: center; width: 100%;">
  
    <div class="category-tabs" id="category-tabs">
        <button class="category-tab active" data-cat="all">🍽️ All</button>
        <button class="category-tab" data-cat="Pasta">🍝 Pasta</button>
        <button class="category-tab" data-cat="Rice Meals">🍚 Rice Meals</button>
        <button class="category-tab" data-cat="Pizza">🍕 Pizza</button>
        <button class="category-tab" data-cat="Sandwiches & Salad">🥗 Sandwiches & Salad</button>
        <button class="category-tab" data-cat="Lemon Series">🍋 Lemon Series</button>
        <button class="category-tab" data-cat="Coffee Beverages">☕ Coffee</button>
        <button class="category-tab" data-cat="NonCoffee">🥤 Non-Coffee</button>
        <button class="category-tab" data-cat="Breads">🍞 Breads</button>
        <button class="category-tab" data-cat="Cakes">🎂 Cakes</button>
        <button class="category-tab" data-cat="Pie-Cookies-Bar">🍪 Pie-Cookies-Bar</button>
        <button class="category-tab" data-cat="Milktea">🧋 Milktea</button>
        <button class="category-tab" data-cat="Fruits & Yogurt">🍎 Fruits & Yogurt</button>
    </div>
   
</div>

<div id="no-results-message" style="display:none;text-align:center;padding:40px 20px;color:#888;">
    <div style="font-size:2rem;">🔍</div>
    <div style="font-weight:600;margin-top:10px;">No matching products found</div>
    <div style="font-size:0.9rem;color:#aaa;">Try searching with a different keyword.</div>
</div>

   <div class="product-grid" id="product-grid">
    <?php if (!empty($products)): ?>
        <?php foreach ($products as $row): ?>
            <?php $isOutOfStock = (int)($row['Stock_Quantity'] ?? 0) <= 0; ?>
            <div class="product"
            data-name="<?= htmlspecialchars($row['Product_Name']) ?>"
            data-category="<?= htmlspecialchars($row['Category']) ?>"
            data-product-id="<?= $row['Product_ID'] ?>"
            data-stock="<?= $row['Stock_Quantity'] ?? 0 ?>"
            data-price="<?= $row['Price'] ?>"
            data-desc="<?= htmlspecialchars($row['Description'] ?? '') ?>"
            style="cursor:pointer; transition: all 0.3s;<?= $isOutOfStock ? ' opacity:0.6;' : '' ?>"
                 style="cursor:pointer; transition: all 0.3s;<?= $isOutOfStock ? ' opacity:0.6;' : '' ?>"
                 onmouseover="this.style.transform='translateY(-6px)'; this.style.boxShadow='0 12px 20px rgba(0,0,0,0.15)'"
                 onmouseout="this.style.transform=''; this.style.boxShadow=''">
                
                <div style="position:relative;">
                    <?php if ($row['Image']): ?>
                        <img src="<?= $row['Image'] ?>" alt="<?= htmlspecialchars($row['Product_Name']) ?>"
                             style="width:100%; height:120px; object-fit:cover; border-radius:12px; margin-bottom:12px;">
                    <?php else: ?>
                        <div style="height:120px;background:#f0e6d6;border-radius:12px;display:flex;align-items:center;justify-content:center;color:#aaa;">
                            🖼️
                        </div>
                    <?php endif; ?>
                    <?php // OUT OF STOCK overlay removed; stock is shown in product modal only ?>
                </div>
                
                <h3 class="product-name"><?= htmlspecialchars($row['Product_Name']) ?></h3>
                <p class="product-desc">
                    <?= htmlspecialchars(strlen($row['Description']) > 60 
                        ? substr($row['Description'], 0, 60) . '...' 
                        : $row['Description']) ?>
                </p>
                
                    <div class="product-bottom">
                        <?php $stockQty = (int)($row['Stock_Quantity'] ?? 0); ?>
                    <p class="price">₱<?= number_format($row['Price'], 2) ?></p>
                    <?php if ($isOutOfStock): ?>
                        <button class="add-btn" disabled 
                                style="background:#ccc;cursor:not-allowed;opacity:0.5;">
                            Unavailable
                        </button>
                    <?php else: ?>
                        <button class="add-btn" 
                                onclick="event.stopPropagation(); 
                                         addToCart(<?= $row['Product_ID'] ?>, '<?= addslashes($row['Product_Name']) ?>', <?= $row['Price'] ?>, '<?= addslashes($row['Image'] ?? '') ?>')">
                            Add
                        </button>
                    <?php endif; ?>
                </div>
            </div>
            
        <?php endforeach; ?>
    <?php else: ?>
        <p>No products available in this category.</p>
    <?php endif; ?>
</div>

<!-- BOTTOM CART BAR -->
<div id="bottom-cart-bar" class="bottom-cart-bar">
    <div class="cart-bar-content">
        <div class="cart-bar-left">
            <div class="cart-bar-icon">
                <span id="bottom-cart-bar-icon" style="cursor:pointer;">🛒</span>
            </div>
            <div>
                <div class="cart-bar-text" id="cart-bar-count">0 items</div>
                <div class="cart-bar-subtotal" id="cart-bar-subtotal">₱0.00</div>
            </div>
        </div>
        <button class="view-cart-btn" id="bottom-view-cart">View Cart</button>
    </div>
</div>

<script>
    (function () {
        const banner = document.getElementById('customerAnnouncements');
        if (!banner) return;
        const storageKey = 'customerAnnouncementsDismissed';
        try {
            if (sessionStorage.getItem(storageKey) === '1') {
                banner.style.display = 'none';
            }
        } catch (error) {
            console.warn('Unable to access session storage for announcements.', error);
        }

        document.getElementById('dismissAnnouncements')?.addEventListener('click', () => {
            banner.style.display = 'none';
            try {
                sessionStorage.setItem(storageKey, '1');
            } catch (error) {
                console.warn('Unable to persist announcement dismissal.', error);
            }
        });
    })();

    // Show cart overlay when cart icon is clicked
    document.getElementById('open-cart').addEventListener('click', function() {
        document.getElementById('cart-overlay').style.display = 'flex';
        document.body.style.overflow = 'hidden';
    });

    // Show cart overlay when bottom cart bar button is clicked
    document.getElementById('bottom-view-cart')?.addEventListener('click', () => {
        document.getElementById('cart-overlay').style.display = 'flex';
        document.body.style.overflow = 'hidden';
    });

    // Hide cart overlay when clicking outside overlay content
    document.getElementById('cart-overlay').addEventListener('click', function(e) {
        if (e.target === this) {
            this.style.display = 'none';
            document.body.style.overflow = 'auto';
        }
    });


    // Hide cart overlay when clicking close button
    document.getElementById('close-cart').addEventListener('click', function() {
        document.getElementById('cart-overlay').style.display = 'none';
        document.body.style.overflow = 'auto';
    });

    // Continue Shopping button: hide cart overlay, restore scroll
    document.getElementById('continue-shopping').addEventListener('click', function() {
        document.getElementById('cart-overlay').style.display = 'none';
        document.body.style.overflow = 'auto';
    });

    // Proceed to Checkout button: hide cart overlay, show checkout overlay
    document.getElementById('proceed-checkout').addEventListener('click', function() {
        document.getElementById('cart-overlay').style.display = 'none';
        document.getElementById('checkout-screen').style.display = 'flex';
        document.body.style.overflow = 'hidden';
    });

// Open / Close Purchase History
function showPurchaseHistory() {
    document.getElementById('purchase-history-overlay').style.display = 'flex';
    document.querySelector('body').style.overflow = 'hidden';
    
    // Load orders via AJAX
    fetch(location.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=get_orders'
    })
    .then(r => r.json())
    .then(res => {
        if (res.status === 'success') {
            renderPurchaseHistory(res.orders);
        } else {
            alert('Error loading orders: ' + res.message);
        }
    })
    .catch(err => {
        console.error(err);
        alert('Network error loading orders.');
    });
}
function closePurchaseHistory() {
    document.getElementById('purchase-history-overlay').style.display = 'none';
    document.querySelector('body').style.overflow = 'auto';
}

// Render purchase history as cards
function renderPurchaseHistory(orders) {
    const container = document.getElementById('purchase-history-cards');
    const noOrders = document.getElementById('no-orders-message');

    if (!orders || orders.length === 0) {
        container.style.display = 'none';
        noOrders.style.display = 'block';
        container.innerHTML = '';
        return;
    }

    noOrders.style.display = 'none';
    container.style.display = 'block';
    container.innerHTML = '';

    orders.forEach(order => {
        const items = order.items || [];
        const date = new Date(order.Order_Date);
        const rawStatus = String(order.Status ?? '').trim();
        const normalizedStatus = rawStatus.toLowerCase();
        
        // Create order card
        const card = document.createElement('div');
        card.className = 'order-card';
        
        // Order header
        const header = document.createElement('div');
        header.className = 'order-header-card';
        
        const dateTime = document.createElement('div');
        dateTime.className = 'order-date-time';
        dateTime.innerHTML = `${date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'Asia/Manila' })}<small>${date.toLocaleTimeString('en-US', { hour: 'numeric', minute: '2-digit', hour12: true, timeZone: 'Asia/Manila' })}</small>`;
        
        const statusTotal = document.createElement('div');
        statusTotal.className = 'order-status-total';
        
        const statusBadge = document.createElement('span');
        statusBadge.className = 'status-badge';
        if (normalizedStatus === 'completed') statusBadge.classList.add('status-completed');
        else if (normalizedStatus === 'pending') statusBadge.classList.add('status-pending');
        else if (normalizedStatus === 'confirmed') statusBadge.classList.add('status-confirmed');
        else statusBadge.classList.add('status-cancelled');
        statusBadge.textContent = rawStatus || 'Unknown';
        
        const totalAmount = document.createElement('div');
        totalAmount.className = 'order-total-amount';
        totalAmount.textContent = '₱' + parseFloat(order.Total_Amount).toFixed(2);
        
        statusTotal.appendChild(statusBadge);
        statusTotal.appendChild(totalAmount);
        header.appendChild(dateTime);
        header.appendChild(statusTotal);
        card.appendChild(header);
        
        // Order items
        const itemsContainer = document.createElement('div');
        itemsContainer.className = 'order-items';
        
        items.forEach(item => {
            const itemRow = document.createElement('div');
            itemRow.className = 'order-item-row';
            
            const nameQty = document.createElement('div');
            nameQty.className = 'item-name-qty';
            const itemName = document.createElement('div');
            itemName.className = 'item-name';
            itemName.textContent = item.Product_Name;
            const itemQty = document.createElement('div');
            itemQty.className = 'item-qty';
            itemQty.textContent = `Quantity: ${item.Quantity}`;
            nameQty.appendChild(itemName);
            nameQty.appendChild(itemQty);
            
            const prices = document.createElement('div');
            prices.className = 'item-prices';
            const price = document.createElement('div');
            price.className = 'item-price';
            price.textContent = '₱' + parseFloat(item.Price).toFixed(2) + ' each';
            const subtotal = document.createElement('div');
            subtotal.className = 'item-subtotal';
            subtotal.textContent = '₱' + (parseFloat(item.Price) * parseInt(item.Quantity)).toFixed(2);
            prices.appendChild(price);
            prices.appendChild(subtotal);
            
            itemRow.appendChild(nameQty);
            itemRow.appendChild(prices);
            itemsContainer.appendChild(itemRow);
        });
        
        card.appendChild(itemsContainer);
        
        // Order actions
        const actions = document.createElement('div');
        actions.className = 'order-actions';
        
            if (normalizedStatus === 'completed') {
            const buyAgainBtn = document.createElement('button');
            buyAgainBtn.className = 'action-btn buy-again';
            buyAgainBtn.textContent = 'Buy Again';
            buyAgainBtn.onclick = () => reorder(order.OrderID);
            actions.appendChild(buyAgainBtn);
                // Disable buy again if any order item is not available in sufficient quantity
                const notAvailable = (order.items || []).some(it => {
                    const card = Array.from(document.querySelectorAll('#product-grid .product')).find(el => el.getAttribute('data-name') === it.Product_Name);
                    if (!card) return true; // if product not found, treat as not available
                    const s = Number(card.getAttribute('data-stock') || 0);
                    return s < Number(it.Quantity || 0);
                });
                if (notAvailable) {
                    buyAgainBtn.disabled = true;
                    buyAgainBtn.classList.add('action-disabled');
                    buyAgainBtn.textContent = 'Unavailable';
                }
            
            const feedbackBtn = document.createElement('button');
            feedbackBtn.className = 'action-btn feedback-btn';
            feedbackBtn.id = 'feedback-btn-' + order.OrderID;
            feedbackBtn.innerHTML = '<i class="bi bi-star-fill"></i>Leave Feedback';
            feedbackBtn.onclick = () => openFeedbackModal(order.OrderID);
            actions.appendChild(feedbackBtn);
            
            // Check if feedback already submitted for this order
            checkFeedbackStatus(order.OrderID);
        } else if (normalizedStatus === 'pending') {
            const btn = document.createElement('button');
            btn.className = 'action-btn cancel-order';
            btn.textContent = 'Cancel Order';
            btn.dataset.orderId = order.OrderID;
            btn.onclick = function() { cancelOrder(order.OrderID, this); };
            actions.appendChild(btn);
        } else if (normalizedStatus === 'confirmed') {
            const span = document.createElement('span');
            span.className = 'action-disabled';
            span.textContent = 'Order confirmed; contact support for changes.';
            actions.appendChild(span);
        } else {
            const span = document.createElement('span');
            span.className = 'action-disabled';
            span.textContent = 'No actions available';
            actions.appendChild(span);
        }
        
        card.appendChild(actions);
        container.appendChild(card);
    });
}

// Quick reorder shortcut used by order again cards
function orderAgain(orderId) {
    reorder(orderId);
}

// Reorder entire previous order
function reorder(orderId) {
    if (!confirm('Add all items from this order to your cart?')) return;

    fetch(location.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'reorder=' + orderId
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            alert(res.message || 'Items added to cart!');
            closePurchaseHistory();
            location.reload(); 
        } else {
            alert('Error: ' + res.message);
        }
    });
}

// Cancel order
function cancelOrder(orderId, btn) {
    if (!confirm('Are you sure you want to cancel this order? This action cannot be undone.')) return;

    // Show loading on the button
    if (!btn) {
        btn = document.querySelector('.action-btn.cancel-order[data-order-id="' + orderId + '"]') || document.querySelector('.action-btn.cancel-order');
    }
    const originalText = (btn && btn.innerHTML) ? btn.innerHTML : 'Cancelling...';
    btn.disabled = true;
    btn.innerHTML = '<span style="display:inline-block;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;"></span> Cancelling...';

    fetch(location.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=cancel_order&order_id=' + orderId
    })
    .then(r => r.json())
    .then(res => {
        if (res.status === 'success') {
            alert('Order cancelled successfully!');
            location.reload(); // Reload to show updated status
        } else {
            alert('Error: ' + res.message);
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    })
    .catch(err => {
        alert('Network error, please try again.');
        btn.disabled = false;
        btn.innerHTML = originalText;
    });
}

// Close overlay when clicking outside
document.getElementById('purchase-history-overlay').addEventListener('click', function(e) {
    if (e.target === this) closePurchaseHistory();
});

// PRODUCT DETAILS MODAL
function openProductModal(img, name, desc, category, price, rawName, passedProductId) {
    document.getElementById('modal-img').src = img || 'https://via.placeholder.com/500x280/6B4F3F/FFFFFF?text=No+Image';
    document.getElementById('modal-name').textContent = name;
    document.getElementById('modal-category').textContent = category ? `Category: ${category}` : '';
    document.getElementById('modal-desc').textContent = desc || 'No description available.';
    document.getElementById('modal-price').textContent = '₱' + Number(price).toFixed(2);

    // Try to resolve Product_ID: prefer passed id, else lookup product-grid elements
    let pid = null;
    if (typeof passedProductId !== 'undefined' && passedProductId !== null) {
        pid = Number(passedProductId) || null;
    }

    if (!pid) {
        const candidates = document.querySelectorAll('#product-grid .product');
        for (const el of candidates) {
            const pName = el.querySelector('.product-name')?.textContent?.trim();
            const dataName = el.getAttribute('data-name') || '';
            if (pName === name || dataName === (name || '').toLowerCase()) {
                const attr = el.getAttribute('data-product-id');
                if (attr) { pid = Number(attr); break; }
            }
        }
    }

    window.currentModalProduct = { product_id: pid, name: rawName, price: price, image: img };
    // Resolve stock and set modal state
    const modalStockEl = document.getElementById('modal-stock');
    let stock = null;
    if (pid) {
        const card = document.querySelector('#product-grid .product[data-product-id="' + pid + '"]');
        if (card && typeof card.dataset.stock !== 'undefined') stock = Number(card.dataset.stock || 0);
    }
    if (stock === null) {
        // fallback to any matched product by name
        const matching = Array.from(document.querySelectorAll('#product-grid .product')).find(el => el.dataset.name === name || el.querySelector('.product-name')?.textContent?.trim() === name);
        if (matching && typeof matching.dataset.stock !== 'undefined') stock = Number(matching.dataset.stock || 0);
    }
    stock = Number.isFinite(stock) ? stock : 0;
    window.currentModalProduct.stock = stock;
    if (modalStockEl) {
        if (stock <= 0) {
            modalStockEl.textContent = 'Out of stock';
            modalStockEl.style.display = 'block';
            document.getElementById('modal-add-to-cart').disabled = true;
            document.getElementById('modal-order-now').disabled = true;
        } else if (stock <= 3) {
            modalStockEl.textContent = 'Only ' + stock + ' left';
            modalStockEl.style.display = 'block';
            document.getElementById('modal-add-to-cart').disabled = false;
            document.getElementById('modal-order-now').disabled = false;
        } else {
            modalStockEl.textContent = 'Stock: ' + stock;
            modalStockEl.style.display = 'block';
            document.getElementById('modal-add-to-cart').disabled = false;
            document.getElementById('modal-order-now').disabled = false;
        }
    }
    document.getElementById('product-detail-overlay').style.display = 'flex';
}
window.openProductModal = openProductModal;

// Close modal
document.getElementById('close-product-modal').onclick = () => {
    document.getElementById('product-detail-overlay').style.display = 'none';
};
document.getElementById('product-detail-overlay').onclick = (e) => {
    if (e.target === document.getElementById('product-detail-overlay')) {
        document.getElementById('product-detail-overlay').style.display = 'none';
    }
};

// Add to Cart from modal
document.getElementById('modal-add-to-cart').onclick = () => {
    const p = window.currentModalProduct || {};
    const stock = Number(p.stock || 0);
    const name = p.name || '';
    const curQty = cart[name] ? cart[name].quantity : 0;
    if (stock && (curQty + 1) > stock) {
        alert('You cannot add more than ' + stock + ' unit(s) of ' + name + ' to your cart.');
        return;
    }
    addToCart(p.product_id, p.name, p.price, p.image);
    document.getElementById('product-detail-overlay').style.display = 'none';
};

// Order Now = Add to cart + go to checkout
document.getElementById('modal-order-now').onclick = () => {
    const p = window.currentModalProduct || {};
    const stock = Number(p.stock || 0);
    const name = p.name || '';
    const curQty = cart[name] ? cart[name].quantity : 0;
    if (stock && (curQty + 1) > stock) {
        alert('You cannot add more than ' + stock + ' unit(s) of ' + name + ' to your cart.');
        return;
    }
    addToCart(p.product_id, p.name, p.price, p.image);
    document.getElementById('product-detail-overlay').style.display = 'none';
    document.getElementById('cart-overlay').style.display = 'none';
    document.getElementById('checkout-screen').style.display = 'flex';
    renderCart();
};

// USER PROFILE DROPDOWN
document.addEventListener("DOMContentLoaded", function () {
    const userIcon = document.getElementById("userIcon");
    const dropdown = document.getElementById("userDropdown");

    userIcon.addEventListener("click", e => {
        e.stopPropagation();
        dropdown.classList.toggle("show");
    });
    document.addEventListener("click", () => dropdown.classList.remove("show"));
    dropdown.addEventListener("click", e => e.stopPropagation());
    // Auto-add item to cart after login: check localStorage where landing saves pending product id
    (function() {
        try {
            const pending = localStorage.getItem('gw_pending_add');
            if (pending) {
                const pid = parseInt(pending, 10);
                if (!isNaN(pid) && pid > 0) {
                    // Wait a bit to ensure products are rendered
                    setTimeout(() => {
                        if (typeof addToCart === 'function') {
                            // add to cart using product id
                            addToCart(pid);
                        }
                        try { localStorage.removeItem('gw_pending_add'); } catch (e) {}
                    }, 400);
                } else {
                    try { localStorage.removeItem('gw_pending_add'); } catch (e) {}
                }
            }
        } catch (err) {
            // localStorage might be unavailable in private mode
            console.warn('Auto-add after login check failed', err);
        }
    })();
});

// PROFILE MODAL
function openProfileModal() {
    document.getElementById('profile-overlay').style.display = 'flex';
}
document.getElementById('close-profile').onclick = () => {
    document.getElementById('profile-overlay').style.display = 'none';
};

// PROFILE FORM SUBMIT (AJAX)
document.getElementById('profile-form').addEventListener('submit', function(e) {
    e.preventDefault();

    const fd = new FormData(this);
    fd.append('action', 'update_profile');

    fetch(location.href, {
        method: 'POST',
        body: fd
    })
    .then(r => r.json())
    .then(res => {
        if (res.success) {
            const successToast = document.getElementById('success-message');
            if (successToast) {
                successToast.textContent = 'Profile updated successfully!';
                successToast.classList.add('show');
                setTimeout(() => {
                    successToast.classList.remove('show');
                    document.getElementById('profile-overlay').style.display = 'none';
                    // Update dropdown header without reload
                    document.querySelector('.dropdown-header').innerHTML = `
                        ${res.name}
                        <div>${res.email || ''}</div>
                    `;
                }, 2000);
            } else {
                // Fallback if toast element was removed
                alert('Profile updated successfully!');
                document.getElementById('profile-overlay').style.display = 'none';
                document.querySelector('.dropdown-header').innerHTML = `
                    ${res.name}
                    <div>${res.email || ''}</div>
                `;
            }
        } else {
            alert('Error: ' + (res.message || 'Update failed'));
        }
    })
    .catch(() => alert('Network error, please try again.'));
});


//  CART STATE & HELPERS

let cart = <?= json_encode($cart ?? []) ?>;

const $ = id => document.getElementById(id);
const badge = $('cart-count');
const checkoutBadge = $('checkout-cart-count');

const fmt = p => '₱' + Number(p).toFixed(2);

function totalItems() {
    return Object.values(cart).reduce((sum, item) => sum + item.quantity, 0);
}
function calcSubtotal() {
    return Object.values(cart).reduce((sum, item) => sum + item.price * item.quantity, 0);
}

function currentDeliveryFee() {
    if (totalItems() === 0) {
        return 0;
    }
    const orderTypeSelect = $('order_type_select');
    if (orderTypeSelect && orderTypeSelect.value !== 'delivery') {
        return 0;
    }
    return 50;
}


// UPDATE BADGE

function updateBadge() {
    const count = totalItems();
    badge.textContent = count;
    badge.style.display = count > 0 ? 'inline' : 'none';

    // Update bottom cart bar
    const bar = document.getElementById('bottom-cart-bar');
    const barCount = document.getElementById('cart-bar-count');
    const barSubtotal = document.getElementById('cart-bar-subtotal');
    if (bar && barCount && barSubtotal) {
        if (count > 0) {
            bar.style.display = 'block';
            barCount.textContent = `${count} item${count > 1 ? 's' : ''}`;
            barSubtotal.textContent = fmt(calcSubtotal());
        } else {
            bar.style.display = 'none';
        }
    }
    // Adjust Add button states on product cards based on cart quantities and stock
    const cards = document.querySelectorAll('#product-grid .product');
    cards.forEach(card => {
        const pname = (card.getAttribute('data-name') || card.querySelector('.product-name')?.textContent || '').trim();
        const stock = Number(card.getAttribute('data-stock') || 0);
        const addBtn = card.querySelector('.add-btn');
        const curQty = cart[pname] ? cart[pname].quantity : 0;
        if (addBtn) {
            if (stock <= 0 || (curQty >= stock)) {
                addBtn.disabled = true;
                addBtn.style.opacity = '0.6';
                addBtn.style.cursor = 'not-allowed';
                addBtn.textContent = stock <= 0 ? 'Unavailable' : 'Add';
            } else {
                addBtn.disabled = false;
                addBtn.style.opacity = '';
                addBtn.style.cursor = '';
                addBtn.textContent = 'Add';
            }
        }
    });
}


//  RENDER CART (sa overlay at checkout)

function renderCart() {
    const container = $('cart-items');
    const totalEl = $('cart-total');
    const subtotalEl = $('checkout-subtotal');
    const totalCheckoutEl = $('checkout-total');
    const feeEl = $('checkout-delivery-fee');

    if (Object.keys(cart).length === 0) {
        container.innerHTML = '<p style="text-align:center;color:#888;padding:60px 0;font-size:1.1rem;">Your cart is empty.<br>Start adding your favorite items!</p>';
        if (totalEl) totalEl.textContent = '₱0.00';
        if (subtotalEl) subtotalEl.textContent = '₱0.00';
        if (totalCheckoutEl) totalCheckoutEl.textContent = '₱0.00';
        if (feeEl) feeEl.textContent = '₱0.00';
        // Hide bottom cart bar when empty
        var bottom = document.getElementById('bottom-cart-bar'); if (bottom) bottom.style.display = 'none';
        return;
    }

    let html = '';
    let subtotal = 0;
    let index = 0;

    for (const [name, item] of Object.entries(cart)) {
        // Resolve stock for this product from the product grid using name or data-name
        const cardElement = document.querySelector('#product-grid .product[data-name="' + name + '"]') || Array.from(document.querySelectorAll('#product-grid .product')).find(el => el.querySelector('.product-name')?.textContent?.trim() === name);
        const stockForItem = cardElement ? Number(cardElement.getAttribute('data-stock') || 0) : null;
        const lineTotal = item.price * item.quantity;
        subtotal += lineTotal;

        html += `
            <div class="cart-item" style="--item-index: ${index++};">
                <div class="cart-item-img">
                    <img src="${item.image || 'https://via.placeholder.com/80/6B4F3F/FFFFFF?text=No+Image'}" alt="${name}" onerror="this.src='https://via.placeholder.com/80/6B4F3F/FFFFFF?text=Image'">
                </div>
                <div class="cart-item-details">
                    <div class="cart-item-name">${name}</div>
                    <div class="cart-item-price">${fmt(item.price)} each</div>
                </div>
                <div class="quantity-controls">
                    <button class="quantity-btn" data-action="decrease" data-product="${name}">−</button>
                    <span class="quantity">${item.quantity}</span>
                    <button class="quantity-btn" data-action="increase" data-product="${name}" ${stockForItem !== null && item.quantity >= stockForItem ? 'disabled' : ''}>+</button>
                </div>
                <div class="line-total">${fmt(lineTotal)}</div>
                <button class="remove-btn" data-action="remove" data-product="${name}">×</button>
            </div>`;
    }

    container.innerHTML = html;
    totalEl.textContent = fmt(subtotal);
    if (subtotalEl) subtotalEl.textContent = fmt(subtotal);

    const deliveryFee = currentDeliveryFee();
    if (feeEl) feeEl.textContent = fmt(deliveryFee);
    if (totalCheckoutEl) totalCheckoutEl.textContent = fmt(subtotal + deliveryFee);
}


//  ADD TO CART 

function addToCart(productId, name, price, image) {
    // Accept either addToCart(productId, name, price, image) or addToCart(name, price, image)
    if (typeof productId === 'string' && typeof name !== 'undefined') {
        image = price;
        price = name;
        name = productId;
        productId = null;
    }

    // Check stock from product grid: find by id or name and enforce limit per cart
    let stock = null;
    const productElements = productId ? document.querySelectorAll('.product[data-product-id="' + productId + '"]') : document.querySelectorAll('.product[data-name="' + name + '"]');
    if (productElements.length > 0) {
        stock = parseInt(productElements[0].getAttribute('data-stock') || '0');
    } else {
        // Try fallback by product text matching
        const fallback = Array.from(document.querySelectorAll('#product-grid .product')).find(el => el.querySelector('.product-name')?.textContent?.trim() === name);
        if (fallback) stock = parseInt(fallback.getAttribute('data-stock') || '0');
    }
    stock = Number.isFinite(Number(stock)) ? Number(stock) : null;
    const currentQty = cart[name] ? cart[name].quantity : 0;
    if (stock !== null && stock <= 0) {
        alert('Sorry, ' + name + ' is currently out of stock.');
        return;
    }
    if (stock !== null && (currentQty + 1) > stock) {
        alert('You cannot add more than ' + stock + ' unit(s) of ' + name + ' to your cart.');
        return;
    }

    const fd = new FormData();
    fd.append('action', 'increase');
    fd.append('product', name);

    fetch(location.href, { method: 'POST', body: fd })
        .then(() => {
            if (!cart[name]) {
                cart[name] = { product_id: productId || null, price: price, quantity: 0, image: image, stock: stock };
            } else {
                if (!cart[name].product_id && productId) cart[name].product_id = productId;
                if (typeof stock !== 'undefined' && stock !== null) cart[name].stock = stock;
            }
            cart[name].quantity++;

            updateBadge();
            renderCart();

            // SHOW TOAST NOTIFICATION
            const toast = document.getElementById('add-to-cart-toast');
            const toastName = document.getElementById('toast-product-name');
            toastName.textContent = name;
            toast.style.display = 'block';
            toast.classList.remove('show');

            // Trigger reflow then add show class
            void toast.offsetWidth;
            toast.classList.add('show');

            // Auto hide after 3 seconds
            setTimeout(() => {
                toast.classList.remove('show');
                setTimeout(() => { toast.style.display = 'none'; }, 400);
            }, 3000);

        })
        .catch(err => {
            console.error(err);
            alert("Error adding to cart.");
        });
}
window.addToCart = addToCart;

// Delegated click handling for .product cards
document.getElementById('product-grid').addEventListener('click', function(e) {
    const card = e.target.closest('.product');
    if (!card) return;
    // If clicked an Add button, stop to prevent opening product modal
    if (e.target.closest('.add-btn')) return;
    const imgEl = card.querySelector('img') || null;
    const imgSrc = imgEl ? imgEl.src : '';
    const name = card.getAttribute('data-name') || (card.querySelector('.product-name')?.textContent || '');
    const desc = card.getAttribute('data-desc') || (card.querySelector('.product-desc')?.textContent || '');
    const category = card.getAttribute('data-category') || '';
    const price = Number(card.getAttribute('data-price') || card.querySelector('.price')?.textContent?.replace(/[^0-9.]/g,'') || 0);
    const productId = Number(card.getAttribute('data-product-id') || 0);
    openProductModal(imgSrc, name, desc, category, price, name, productId);
});

// Ensure product_id values exist for cart items by querying server when necessary
function ensureProductIdsForCart() {
    var promises = [];
    for (var key in cart) {
        if (!Object.prototype.hasOwnProperty.call(cart, key)) continue;
        (function(name, item) {
            if (!item.product_id) {
                var body = 'action=get_product_by_name&name=' + encodeURIComponent(name);
                promises.push(
                    fetch(location.href, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: body })
                    .then(function(r) { return r.json(); })
                    .then(function(res) {
                        if (res.status === 'success' && res.product) {
                            item.product_id = Number(res.product.Product_ID);
                            item.price = parseFloat(res.product.Price);
                        }
                    })
                    .catch(function(err) { console.warn('Failed to resolve product id for', name, err); })
                );
            }
        })(key, cart[key]);
    }
    return Promise.all(promises);
}

//  CART BUTTONS

document.addEventListener('click', e => {
    const btn = e.target.closest('.quantity-btn, .remove-btn');
    if (!btn) return;

    const action = btn.dataset.action;
    const product = btn.dataset.product;
    // If trying to increase quantity, enforce stock limits
    if (action === 'increase') {
        const currentQty = cart[product] ? cart[product].quantity : 0;
        let stock = null;
        const byName = Array.from(document.querySelectorAll('#product-grid .product')).find(el => (el.getAttribute('data-name') === product) || (el.querySelector('.product-name')?.textContent?.trim() === product));
        if (byName && byName.getAttribute('data-stock') !== null) stock = parseInt(byName.getAttribute('data-stock') || '0');
        if (stock !== null && stock <= 0) {
            alert(product + ' is out of stock.');
            return;
        }
        if (stock !== null && (currentQty + 1) > stock) {
            alert('You cannot add more than ' + stock + ' unit(s) of ' + product + ' to your cart.');
            return;
        }
    }

    const fd = new FormData();
    fd.append('action', action);
    fd.append('product', product);

    fetch(location.href, { method: 'POST', body: fd })
        .then(() => {
            if (action === 'increase') cart[product].quantity++;
            else if (action === 'decrease') {
                cart[product].quantity--;
                if (cart[product].quantity <= 0) delete cart[product];
            } else if (action === 'remove') {
                delete cart[product];
            }
            updateBadge();
            renderCart();
        });
});

// Close checkout when clicking X or outside
document.getElementById('checkout-screen').addEventListener('click', function(e) {
    if (e.target === this || e.target.id === 'close-checkout') {
        this.style.display = 'none';
    }
});




//  live search function

const searchInput = $('search-input');
let currentSearch = '';
let currentCategory = 'all';
const noResultsMsg = document.getElementById('no-results-message');

function performSearch() {
    const term = searchInput.value.trim().toLowerCase();
    currentSearch = term;
    filterProducts();
}

function filterProducts() {
    const products = document.querySelectorAll('#product-grid .product');
    let visible = 0;
    products.forEach(p => {
        const name = (p.getAttribute('data-name') || '').toLowerCase();
        const category = p.getAttribute('data-category') || '';
        const matchesSearch = currentSearch === '' || name.includes(currentSearch);
        const categoryNormalized = (category || '').toString().trim().toLowerCase();
        const matchesCategory = currentCategory === 'all' || categoryNormalized === currentCategory;
        if (matchesSearch && matchesCategory) {
            p.style.display = '';
            visible++;
        } else {
            p.style.display = 'none';
        }
    });
    if (noResultsMsg) {
        noResultsMsg.style.display = (currentSearch !== '' && visible === 0) ? 'block' : 'none';
    }
}

searchInput?.addEventListener('input', performSearch);

// CATEGORY TABS

const categoryTabs = document.querySelectorAll('.category-tab');

categoryTabs.forEach(tab => {
    tab.addEventListener('click', function() {
        categoryTabs.forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        currentCategory = (this.getAttribute('data-cat') || 'all').toString().trim().toLowerCase();
        filterProducts();
    });
});

// Scroll arrows for category tabs (only if arrow buttons exist)
const scrollLeftBtn = document.getElementById('scroll-left');
if (scrollLeftBtn) {
    scrollLeftBtn.addEventListener('click', () => {
        document.getElementById('category-tabs').scrollBy({ left: -200, behavior: 'smooth' });
    });
}

const scrollRightBtn = document.getElementById('scroll-right');
if (scrollRightBtn) {
    scrollRightBtn.addEventListener('click', () => {
        document.getElementById('category-tabs').scrollBy({ left: 200, behavior: 'smooth' });
    });
}

// Reservations functions consolidated — canonical implementation used later; this earlier version was removed.

// Cancel reservation
// Canonical implementation defined later (near the bottom of the reservations code).

// Close reservations overlay when clicking outside
document.getElementById('reservations-overlay')?.addEventListener('click', function(e) {
    if (e.target === this) closeReservations();
});

document.getElementById('create-reservation-modal')?.addEventListener('click', function(e) {
    if (e.target === this) closeCreateReservation();
});

// Reservation search
document.getElementById('reservation-search')?.addEventListener('input', function(e) {
    const search = e.target.value.toLowerCase();
    const cards = document.querySelectorAll('.reservation-card');
    
    cards.forEach(card => {
        const text = card.textContent.toLowerCase();
        card.style.display = text.includes(search) ? '' : 'none';
    });
});

// PURCHASE HISTORY LIVE SEARCH (works with card-based layout)
const purchaseSearchInput = document.getElementById('purchase-search');
if (purchaseSearchInput) {
    purchaseSearchInput.addEventListener('input', function() {
        const term = this.value.trim().toLowerCase();
        const container = document.getElementById('purchase-history-cards');
        if (!container) return;

        const cards = container.querySelectorAll('.order-card');
        let visibleCardsCount = 0;

        cards.forEach(card => {
            const items = card.querySelectorAll('.order-item-row');
            let hasMatchingItem = false;

            items.forEach(itemRow => {
                const itemName = itemRow.querySelector('.item-name');
                if (!itemName) return;
                const text = itemName.textContent.toLowerCase();
                
                if (term === '' || text.includes(term)) {
                    itemRow.style.display = '';
                    hasMatchingItem = true;
                } else {
                    itemRow.style.display = 'none';
                }
            });

            // Show card if any item matches or search is empty
            if (hasMatchingItem || term === '') {
                card.style.display = '';
                visibleCardsCount++;
                // Reset all items when search is cleared
                if (term === '') {
                    items.forEach(item => item.style.display = '');
                }
            } else {
                card.style.display = 'none';
            }
        });

        const noOrders = document.getElementById('no-orders-message');
        if (noOrders) noOrders.style.display = (term !== '' && visibleCardsCount === 0) ? 'block' : 'none';
    });
}

//  NAVIGATION: Cart → Checkout → Thank You

$('open-cart').onclick = () => {
    $('cart-overlay').style.display = 'flex';
    renderCart();
};
$('close-cart').onclick = () => $('cart-overlay').style.display = 'none';
$('continue-shopping').onclick = () => $('cart-overlay').style.display = 'none';

$('proceed-checkout').onclick = () => {
    $('cart-overlay').style.display = 'none';
    $('checkout-screen').style.display = 'flex';
    renderCart();
    document.getElementById('bottom-cart-bar').style.display = 'none';
};

$('back-to-cart').onclick = () => {
    $('checkout-screen').style.display = 'none';
    $('cart-overlay').style.display = 'flex';
    renderCart();
    updateBadge(); // to show bar again
};


// === NEW CHECKOUT SYSTEM (Payment + Bayad + Sukli) ===

function updateCheckoutDisplay() {
    const subtotal = calcSubtotal();
    const deliveryFee = currentDeliveryFee();
    const total = subtotal + deliveryFee;

    const subtotalEl = $('checkout-subtotal');
    if (subtotalEl) subtotalEl.textContent = fmt(subtotal);
    const totalEl = $('checkout-total');
    if (totalEl) totalEl.textContent = fmt(total);
    const feeEl = $('checkout-delivery-fee');
    if (feeEl) feeEl.textContent = fmt(deliveryFee);
}

// No extra fields needed for COD; still refresh totals when payment method changes in case more options return later
if ($('payment_method')) {
    $('payment_method').addEventListener('change', updateCheckoutDisplay);
}

// Enhance renderCart to update checkout totals too
const oldRenderCart = renderCart;
renderCart = function() {
    oldRenderCart();
    updateCheckoutDisplay();
};

// Navigation
$('open-cart').onclick = () => {
    $('cart-overlay').style.display = 'flex';
    renderCart();
};
$('close-cart').onclick = () => $('cart-overlay').style.display = 'none';
$('continue-shopping').onclick = () => $('cart-overlay').style.display = 'none';

$('proceed-checkout').onclick = () => {
    $('cart-overlay').style.display = 'none';
    $('checkout-screen').style.display = 'flex';
    renderCart();
    updateCheckoutDisplay();
};

$('back-to-cart').onclick = () => {
    $('checkout-screen').style.display = 'none';
    $('cart-overlay').style.display = 'flex';
    renderCart();
};

// FINALIZE ORDER
$('finalize-order').onclick = async () => {
    const name = $('customer_name').value.trim();
    const houseStreet = $('house_street').value.trim();
    const barangay = $('barangay').value;
    const city = $('city').value.trim();
    const method = $('payment_method').value;

    if (!name) return alert("Please enter your full name.");
    if (!houseStreet) return alert("Please enter your house number and street.");
    if (!barangay) return alert("Please select a barangay.");
    
    // Validate city is Nasugbu
    if (!city.toLowerCase().includes('nasugbu')) {
        return alert("Sorry, we only deliver within Nasugbu, Batangas.");
    }

    // Allowed barangays in Nasugbu for delivery
    const allowedBarangays = [
        "Barangay 1 (Pob.)", "Barangay 2 (Pob.)", "Barangay 3 (Pob.)",
        "Barangay 4 (Pob.)", "Barangay 5 (Pob.)", "Barangay 6 (Pob.)",
        "Barangay 7 (Pob.)", "Barangay 8 (Pob.)", "Barangay 9 (Pob.)",
        "Barangay 10 (Pob.)", "Barangay 11 (Pob.)", "Barangay 12 (Pob.)",
        "Bucana", "Talangan"
    ];

    if (!allowedBarangays.includes(barangay)) {
        return alert("Sorry, we do not deliver to " + barangay + ". We only deliver to selected barangays in Nasugbu, Batangas.");
    }

    if (!method) return alert("Please select payment method.");

    // Combine address parts
    const address = `${houseStreet}, ${barangay}, ${city}`;

    // Check if cart is empty
    if (Object.keys(cart).length === 0) {
        return alert("Your cart is empty. Please add items before placing an order.");
    }

    // Resolve missing product IDs from server if any
    await ensureProductIdsForCart();

    // Validate all items have product_id now
    for (const [name, item] of Object.entries(cart)) {
        if (!item.product_id) {
            return alert(`Error: Product ID missing for ${name}. Please refresh the page and try again.`);
        }
    }

    const subtotal = calcSubtotal();
    const deliveryFee = currentDeliveryFee();
    const total = subtotal + deliveryFee;

    // Format cart items for the new API
    const items = [];
    for (const [productName, item] of Object.entries(cart)) {
        items.push({
            product_id: item.product_id,
            product_name: productName,
            quantity: item.quantity,
            price: item.price
        });
    }

    const orderData = {
        customer_name: name,
        delivery_address: address,
        items: items,
        total_amount: total,
        payment_method: method === 'cash' ? 'Cash' : 'GCash',
        amount_tendered: total
    };

    const fd = new FormData();
    fd.append('action', 'place_order');
    fd.append('order_data', JSON.stringify(orderData));

    // Disable button during processing and show placing overlay
    const btn = $('finalize-order');
    const originalText = btn.innerHTML;
    btn.disabled = true;
    btn.innerHTML = '<span style="display:inline-block;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;"></span> Finalizing your order...';
    const placing = document.getElementById('placing-overlay');
    if (placing) placing.style.display = 'flex';

    fetch(location.href, { method: 'POST', body: fd })
        .then(async response => {
            const text = await response.text();
            try {
                return JSON.parse(text);
            } catch (error) {
                const clean = text.trim();
                console.error('Place order parse error. Raw response:', clean);
                throw new Error(clean || 'Invalid response from server');
            }
        })
        .then(res => {
            if (res.status === 'success') {
                // Success: clear cart, update UI, show thank you
                cart = {};
                updateBadge();
                if (placing) placing.style.display = 'none';
                $('checkout-screen').style.display = 'none';
                $('thankyou-screen').style.display = 'flex';

                const changeAmount = method === 'cash' ? res.change : 0;
                $('delivery-message').innerHTML = `
                    <div style="font-size:1.2rem;color:#6B4F3F;margin-bottom:15px;"><strong>🎉 Your order has been placed successfully!</strong></div>
                    <div style="background:#f8f5f0;padding:20px;border-radius:12px;border-left:4px solid #6B4F3F;margin:20px 0;">
                        <div style="margin-bottom:10px;"><strong>Order ID:</strong> <span style="color:#6B4F3F;font-weight:600;">#${res.order_id}</span></div>
                        <div style="margin-bottom:10px;"><strong>Delivery Address:</strong> ${address}</div>
                        <div style="margin-bottom:10px;"><strong>Payment Method:</strong> ${method.toUpperCase()}${method === 'cash' && changeAmount > 0 ? ` (Change: ₱${changeAmount.toFixed(2)})` : ''}</div>
                        <div style="margin-bottom:10px;"><strong>Status:</strong> <span style="color:#28a745;font-weight:600;">Pending wait for the staff to confirmed your order</span></div>
                    </div>
                    <div style="color:#666;font-size:0.95rem;margin:15px 0;">
                        📧 A receipt has been sent to your email.<br>
                        🚚 Our delivery team will contact you shortly with updates.
                    </div>
                    <div style="color:#4d2e00;font-weight:600;margin-top:20px;">
                        Thank you for choosing Guillermo's Café! 🍽️
                    </div>`;
                // leave button disabled while on thankyou screen
            } else {
                alert("Order failed: " + (res.message || "Please try again."));
                if (placing) placing.style.display = 'none';
                btn.disabled = false;
                btn.innerHTML = originalText;
            }
        })
        .catch(err => {
            console.error('Order error:', err);
            if (placing) placing.style.display = 'none';
            btn.disabled = false;
            btn.innerHTML = originalText;
            const msg = err && err.message ? String(err.message).slice(0, 300) : 'Network error. Please check your connection and try again.';
            alert(`Order failed: ${msg}`);
        });
};

// Thank you buttons
$('back-home').onclick = () => location.reload();

// RESERVATION FUNCTIONS
function showReservations() {
    document.getElementById('reservations-overlay').style.display = 'flex';
    document.body.style.overflow = 'hidden';
    loadReservations();
}

function closeReservations() {
    document.getElementById('reservations-overlay').style.display = 'none';
    document.body.style.overflow = 'auto';
}

function loadReservations() {
    const container = document.getElementById('reservations-list');
    const noReservations = document.getElementById('no-reservations-message');
    
    // Show loading
    container.innerHTML = '<div style="text-align:center;padding:40px;"><div style="display:inline-block;width:20px;height:20px;border:2px solid #6B4F3F;border-top-color:transparent;border-radius:50%;animation:spin 0.8s linear infinite;"></div><div style="margin-top:10px;color:#666;">Loading reservations...</div></div>';
    container.style.display = 'block';
    noReservations.style.display = 'none';

    fetch(location.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=get_reservations'
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(res => {
        if (res.status === 'success') {
            renderReservations(res.reservations);
        } else {
            console.error('Error loading reservations:', res.message);
            container.innerHTML = '<div style="text-align:center;padding:40px;color:#e74c3c;"><div style="font-size:2rem;">⚠️</div><div style="margin-top:10px;">Error loading reservations</div><div style="font-size:0.9rem;color:#888;margin-top:5px;">' + (res.message || 'Please try again later') + '</div></div>';
        }
    })
    .catch(err => {
        console.error('Network error loading reservations:', err);
        container.innerHTML = '<div style="text-align:center;padding:40px;color:#e74c3c;"><div style="font-size:2rem;">🔌</div><div style="margin-top:10px;">Network error</div><div style="font-size:0.9rem;color:#888;margin-top:5px;">Please check your connection and try again</div></div>';
    });
}

function renderReservations(reservations) {
    const container = document.getElementById('reservations-list');
    const noReservations = document.getElementById('no-reservations-message');

    if (!reservations || reservations.length === 0) {
        container.style.display = 'none';
        noReservations.style.display = 'block';
        return;
    }

    noReservations.style.display = 'none';
    container.style.display = 'block';
    container.innerHTML = '';

    reservations.forEach(reservation => {
        const card = document.createElement('div');
        card.className = 'reservation-card';

        const date = new Date(reservation.Reservation_Date);
        const formattedDate = date.toLocaleDateString('en-US', { 
            weekday: 'short', 
            year: 'numeric', 
            month: 'short', 
            day: 'numeric',
            hour: 'numeric',
            minute: '2-digit',
            hour12: true,
            timeZone: 'Asia/Manila'
        });

        let statusClass = 'status-pending';
        if (reservation.Payment_Status === 'Confirmed') statusClass = 'status-confirmed';
        else if (reservation.Payment_Status === 'Cancelled') statusClass = 'status-cancelled';
        else if (reservation.Payment_Status === 'Completed') statusClass = 'status-completed';

        card.innerHTML = `
            <div class="reservation-header">
                <div class="reservation-id">Reservation #${reservation.Reservation_ID}</div>
                <div class="reservation-date">${formattedDate}</div>
                <div class="reservation-status">
                    <span class="status-badge-res ${statusClass}">${reservation.Payment_Status}</span>
                </div>
            </div>
            <div class="reservation-body">
                <div class="reservation-info">
                    <div class="info-item">
                        <div class="info-label">PRODUCT</div>
                        <div class="info-value">${reservation.Product_Name || 'Unknown Product'}</div>
                    </div>
                    <div class="info-item">
                        <div class="info-label">PRICE</div>
                        <div class="info-value">₱${parseFloat(reservation.Price || 0).toFixed(2)}</div>
                    </div>
                </div>
                ${reservation.Payment_Status === 'Pending' ? `
                <div class="reservation-actions">
                    <button class="btn btn-secondary" data-reservation-id="${reservation.Reservation_ID}" onclick="cancelReservation(${reservation.Reservation_ID}, this)" style="padding:8px 16px;border-radius:6px;border:1px solid #dc3545;color:#dc3545;background:#fff;">
                        <i class="bi bi-x-circle me-1"></i>Cancel
                    </button>
                </div>
                ` : ''}
            </div>
        `;

        container.appendChild(card);
    });
}

// Canonical: Open/Create reservation helpers with min-date logic
function openCreateReservation() {
    const modal = document.getElementById('create-reservation-modal');
    if (!modal) return;
    modal.style.display = 'flex';
    document.body.style.overflow = 'hidden';
    // Set minimum date to today (local timezone)
    const now = new Date();
    now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
    const input = document.getElementById('reservation-date-input');
    if (input) input.min = now.toISOString().slice(0, 16);
}

function closeCreateReservation() {
    const modal = document.getElementById('create-reservation-modal');
    if (!modal) return;
    modal.style.display = 'none';
    document.body.style.overflow = 'auto';
    const form = document.getElementById('create-reservation-form');
    if (form) form.reset();
}

function cancelReservation(reservationId, btn) {
    if (!confirm('Are you sure you want to cancel this reservation? This action cannot be undone.')) {
        return;
    }

    // Determine the button if not provided
    if (!btn) {
        btn = document.querySelector('.btn.btn-secondary[data-reservation-id="' + reservationId + '"]') || document.querySelector('.btn.btn-secondary');
    }
    // Show loading on the cancel button
    const originalText = (btn && btn.innerHTML) ? btn.innerHTML : 'Cancelling...';
    if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span style="display:inline-block;width:14px;height:14px;border:2px solid #dc3545;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;margin-right:6px;"></span>Cancelling...';
    }

    fetch(location.href, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: 'action=cancel_reservation&reservation_id=' + reservationId
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(res => {
        if (res.status === 'success') {
            alert('Reservation cancelled successfully!');
            loadReservations(); // Reload the reservations list
        } else {
            alert('Error: ' + (res.message || 'Failed to cancel reservation'));
            btn.disabled = false;
            btn.innerHTML = originalText;
        }
    })
    .catch(err => {
        console.error('Network error:', err);
        alert('Network error, please try again.');
        btn.disabled = false;
        btn.innerHTML = originalText;
    });
}

// Handle create reservation form submission
document.getElementById('create-reservation-form').addEventListener('submit', function(e) {
    e.preventDefault();

    const dateInput = this.querySelector('#reservation-date-input').value;
    const productSelect = this.querySelector('#reservation-product-select');
    
    if (!dateInput) {
        alert('Please select a date and time');
        return;
    }
    
    if (!productSelect || productSelect.selectedOptions.length === 0) {
        alert('Please select at least one product to reserve');
        return;
    }

    const formData = new FormData(this);
    formData.append('action', 'create_reservation');

    const submitBtn = this.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span style="display:inline-block;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;margin-right:8px;"></span>Creating...';

    fetch(location.href, {
        method: 'POST',
        body: formData
    })
    .then(response => {
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        return response.json();
    })
    .then(res => {
        if (res.status === 'success') {
            alert('Reservation created successfully!');
            closeCreateReservation();
            loadReservations(); // Reload the reservations list
        } else {
            alert('Error: ' + (res.message || 'Failed to create reservation'));
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    })
    .catch(err => {
        console.error('Network error:', err);
        alert('Network error, please try again.');
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    });
});// Close reservation overlay when clicking outside
document.getElementById('reservations-overlay').addEventListener('click', function(e) {
    if (e.target === this) closeReservations();
});

// Close create reservation modal when clicking outside
document.getElementById('create-reservation-modal').addEventListener('click', function(e) {
    if (e.target === this) closeCreateReservation();
});

// ============ FEEDBACK MODAL FUNCTIONS ============
let selectedRating = 0;

function openFeedbackModal(orderId) {
    // Close purchase history overlay first
    closePurchaseHistory();
    
    // Open feedback modal
    document.getElementById('feedback-order-id').value = orderId;
    document.getElementById('feedback-modal').style.display = 'flex';
    document.querySelector('body').style.overflow = 'hidden';
    selectedRating = 0;
    document.getElementById('rating-value').value = '';
    document.getElementById('feedback-comment').value = '';
    document.getElementById('rating-error').style.display = 'none';
    
    // Reset stars
    document.querySelectorAll('#star-rating .star').forEach(star => {
        star.style.color = '#ddd';
    });
    // Ensure interactive stars and comment are enabled for create mode
    const starRatingElem = document.getElementById('star-rating');
    if (starRatingElem) starRatingElem.style.pointerEvents = 'auto';
    document.getElementById('feedback-comment').disabled = false;
    const submitBtn = document.querySelector('#feedback-form button[type="submit"]');
    if (submitBtn) {
        submitBtn.style.display = '';
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="bi bi-send-fill me-2"></i>Submit Feedback';
    }
    // Reset modal title
    const titleEl = document.querySelector('#feedback-modal h2');
    if (titleEl) titleEl.textContent = '⭐ Rate Your Order';
}

// Open view-only feedback modal: fetch feedback and populate fields, disable editing
async function openViewFeedbackModal(orderId) {
    try {
        const resp = await fetch(`?action=get_feedback&order_id=${orderId}`, { headers: { 'Accept': 'application/json' } });

        // Handle unauthorized / redirect scenarios
        if (resp.status === 401) {
            alert('Please log in to view feedback.');
            return;
        }

        if (!resp.ok) {
            // Try to parse JSON error body if the server returned JSON
            const contentType = (resp.headers.get('content-type') || '').toLowerCase();
            if (contentType.includes('application/json')) {
                const errObj = await resp.json();
                throw new Error(errObj.message || 'Failed to fetch feedback');
            }
            const text = await resp.text();
            throw new Error('Failed to fetch feedback: ' + (text ? text.slice(0, 400) : resp.statusText));
        }

        const contentType = (resp.headers.get('content-type') || '').toLowerCase();
        if (!contentType.includes('application/json')) {
            // The server returned HTML (likely login page or an error), log and show friendly message
            const text = await resp.text();
            console.error('openViewFeedbackModal: expected JSON but got:', text.slice(0, 800));
            alert('Could not load feedback – your session may have expired. Please reload and try again.');
            return;
        }

        const data = await resp.json();
        if (data.status !== 'success' || !data.feedback) {
            alert('Feedback not found');
            return;
        }

        const feedback = data.feedback;
        // Close other overlays
        closePurchaseHistory();

        document.getElementById('feedback-order-id').value = orderId;
        document.getElementById('feedback-modal').style.display = 'flex';
        document.querySelector('body').style.overflow = 'hidden';

        // Set rating
        const rating = parseInt(feedback.rating) || 0;
        selectedRating = rating;
        document.getElementById('rating-value').value = rating;
        highlightStars(rating);

        // Set comment and disable editing
        const commentEl = document.getElementById('feedback-comment');
        commentEl.value = feedback.comment || '';
        commentEl.disabled = true;

        // Disable star interactions via CSS pointer-events
        const starRatingElem = document.getElementById('star-rating');
        if (starRatingElem) starRatingElem.style.pointerEvents = 'none';

        // Hide submit button - enforce read-only
        const submitBtn = document.querySelector('#feedback-form button[type="submit"]');
        if (submitBtn) submitBtn.style.display = 'none';

        // Update modal title to indicate read-only mode
        const titleEl = document.querySelector('#feedback-modal h2');
        if (titleEl) titleEl.textContent = '📝 View Feedback';

    } catch (err) {
        console.error('Error opening view feedback modal', err);
        alert('Could not load feedback.');
    }
}

function closeFeedbackModal() {
    document.getElementById('feedback-modal').style.display = 'none';
    document.querySelector('body').style.overflow = 'auto';
    // Re-enable interactive fields and show submit button for future opens
    document.getElementById('feedback-comment').disabled = false;
    const starRatingElem = document.getElementById('star-rating');
    if (starRatingElem) starRatingElem.style.pointerEvents = 'auto';
    const submitBtn = document.querySelector('#feedback-form button[type="submit"]');
    if (submitBtn) {
        submitBtn.style.display = '';
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="bi bi-send-fill me-2"></i>Submit Feedback';
    }
}

// Star rating interaction
document.querySelectorAll('#star-rating .star').forEach(star => {
    star.addEventListener('mouseenter', function() {
        const rating = parseInt(this.getAttribute('data-rating'));
        highlightStars(rating);
    });
    
    star.addEventListener('click', function() {
        selectedRating = parseInt(this.getAttribute('data-rating'));
        document.getElementById('rating-value').value = selectedRating;
        document.getElementById('rating-error').style.display = 'none';
        highlightStars(selectedRating);
    });
});

document.getElementById('star-rating').addEventListener('mouseleave', function() {
    highlightStars(selectedRating);
});

function highlightStars(rating) {
    document.querySelectorAll('#star-rating .star').forEach(star => {
        const starRating = parseInt(star.getAttribute('data-rating'));
        if (starRating <= rating) {
            star.style.color = '#ffc107';
            star.style.transform = 'scale(1.1)';
        } else {
            star.style.color = '#ddd';
            star.style.transform = 'scale(1)';
        }
    });
}

// Submit feedback form
document.getElementById('feedback-form').addEventListener('submit', async function(e) {
    e.preventDefault();
    
    const orderId = document.getElementById('feedback-order-id').value;
    const rating = document.getElementById('rating-value').value;
    const comment = document.getElementById('feedback-comment').value.trim();
    
    if (!rating) {
        document.getElementById('rating-error').style.display = 'block';
        return;
    }
    
    const formData = new FormData();
    formData.append('action', 'submit_feedback');
    formData.append('order_id', orderId);
    formData.append('rating', rating);
    formData.append('comment', comment);
    
    const submitBtn = this.querySelector('button[type="submit"]');
    const originalText = submitBtn.innerHTML;
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<span style="display:inline-block;width:16px;height:16px;border:2px solid #fff;border-top-color:transparent;border-radius:50%;animation:spin 0.6s linear infinite;margin-right:8px;"></span>Submitting...';
    
    try {
        const response = await fetch(location.href, {
            method: 'POST',
            body: formData
        });
        
        // Check if response is OK
        if (!response.ok) {
            throw new Error(`HTTP error! status: ${response.status}`);
        }
        
        // Get response text first to debug
        const text = await response.text();
        
        // Try to parse as JSON
        let result;
        try {
            result = JSON.parse(text);
        } catch (parseError) {
            console.error('Failed to parse JSON:', text);
            throw new Error('Invalid response from server. Please check if you are logged in.');
        }
        
        if (result.status === 'success') {
            alert(result.message || 'Thank you for your feedback!');
            closeFeedbackModal();
            // Reload purchase history to update button state
            showPurchaseHistory();
        } else {
            alert('Error: ' + (result.message || 'Failed to submit feedback'));
            submitBtn.disabled = false;
            submitBtn.innerHTML = originalText;
        }
    } catch (error) {
        console.error('Error submitting feedback:', error);
        alert(error.message || 'Network error, please try again.');
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText;
    }
});

// Close feedback modal when clicking outside
document.getElementById('feedback-modal').addEventListener('click', function(e) {
    if (e.target === this) closeFeedbackModal();
});

// Check if feedback already submitted for an order
async function checkFeedbackStatus(orderId) {
    try {
        const response = await fetch(`?action=check_feedback&order_id=${orderId}`, { headers: { 'Accept': 'application/json' } });
        if (response.status === 401) return; // user not logged in; nothing to do
        const ctype = (response.headers.get('content-type') || '').toLowerCase();
        if (!ctype.includes('application/json')) {
            // Something returned HTML, maybe a session timeout - log and return
            const txt = await response.text();
            console.warn('checkFeedbackStatus: expected JSON but received:', txt.slice(0, 500));
            return;
        }
        const result = await response.json();
        
        if (result.status === 'success' && result.has_feedback) {
            const feedbackBtn = document.getElementById('feedback-btn-' + orderId);
            if (feedbackBtn) {
                // Make the button show it has feedback and allow viewing in read-only mode
                feedbackBtn.disabled = false;
                feedbackBtn.innerHTML = '<i class="bi bi-check-circle-fill"></i> Feedback Submitted';
                feedbackBtn.style.background = '#6c757d';
                feedbackBtn.style.cursor = 'pointer';
                feedbackBtn.onclick = () => openViewFeedbackModal(orderId);
            }
        }
    } catch (error) {
        console.error('Error checking feedback status:', error);
    }
}

// Initialize
updateBadge();
performSearch();
updateCheckoutDisplay();
    
    // Initialize purchase history layout controls
    (function(){
        const toggle = document.getElementById('ph-adjust-toggle');
        const controls = document.getElementById('ph-adjust-controls');
        const overlay = document.getElementById('purchase-history-overlay');
        if (!toggle || !controls || !overlay) return;

        const itemInput = document.getElementById('ph-col-item');
        const totalInput = document.getElementById('ph-col-total');
        const actionInput = document.getElementById('ph-col-action');
        const itemVal = document.getElementById('ph-col-item-val');
        const totalVal = document.getElementById('ph-col-total-val');
        const actionVal = document.getElementById('ph-col-action-val');

        toggle.addEventListener('click', () => {
            controls.style.display = controls.style.display === 'none' ? 'block' : 'none';
        });

        function writeVars() {
            const item = (itemInput && itemInput.value) ? itemInput.value + '%' : getComputedStyle(overlay).getPropertyValue('--ph-col-item');
            const total = (totalInput && totalInput.value) ? totalInput.value + '%' : getComputedStyle(overlay).getPropertyValue('--ph-col-total');
            const action = (actionInput && actionInput.value) ? actionInput.value + '%' : getComputedStyle(overlay).getPropertyValue('--ph-col-action');
            overlay.style.setProperty('--ph-col-item', item);
            overlay.style.setProperty('--ph-col-total', total);
            overlay.style.setProperty('--ph-col-action', action);
            if (itemVal) itemVal.textContent = item;
            if (totalVal) totalVal.textContent = total;
            if (actionVal) actionVal.textContent = action;
        }

        if (itemInput) itemInput.addEventListener('input', writeVars);
        if (totalInput) totalInput.addEventListener('input', writeVars);
        if (actionInput) actionInput.addEventListener('input', writeVars);

        // initialize values from CSS vars
        const cs = getComputedStyle(overlay);
        const initItem = cs.getPropertyValue('--ph-col-item').trim().replace('%','') || '44';
        const initTotal = cs.getPropertyValue('--ph-col-total').trim().replace('%','') || '10';
        const initAction = cs.getPropertyValue('--ph-col-action').trim().replace('%','') || '8';
        if (itemInput) itemInput.value = initItem;
        if (totalInput) totalInput.value = initTotal;
        if (actionInput) actionInput.value = initAction;
        writeVars();
    })();
</script>
</body>
</html>
