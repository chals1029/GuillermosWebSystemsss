<?php
 session_start();
// Check if user is logged in as owner
if (!isset($_SESSION['user_role']) || strtolower($_SESSION['user_role']) !== 'owner') {
    // Redirect to landing page if not authenticated
    header('Location: ../../Views/landing/index.php');
    exit;
}
require_once __DIR__ . '/../../Controllers/OwnerController.php';
require_once __DIR__ . '/../../Controllers/EmailApiController.php';
require_once __DIR__ . '/../../Controllers/Security/DdosGuard.php';

$ownerActionRequest = isset($_GET['action']) || isset($_POST['action']);
if ($ownerActionRequest && !DdosGuard::protect([
    'scope' => 'owner_dashboard',
    'max_requests' => (int)(getenv('OWNER_DDOS_MAX_REQUESTS') ?: 120),
    'window_seconds' => (int)(getenv('OWNER_DDOS_WINDOW_SECONDS') ?: 60),
    'block_seconds' => (int)(getenv('OWNER_DDOS_BLOCK_SECONDS') ?: 180),
    'request_methods' => ['GET', 'POST'],
    'response_type' => 'json',
    'message' => 'Too many admin requests detected. Please wait and try again.',
    'exit_on_block' => false,
])) {
    exit;
}

$ownerController = new OwnerController();
// ADD NEW STAFF
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'add_staff') {
    header('Content-Type: application/json');
    $name = trim($_POST['Name'] ?? '');
    $username = trim($_POST['Username'] ?? '');
    $password = password_hash($_POST['Password'], PASSWORD_DEFAULT);
    $email = trim($_POST['Email'] ?? '');
    $phone = trim($_POST['Phonenumber'] ?? '');
    $existingUserId = 0;
    // server-side validation: phone must be empty or an 11-digit numeric string
    if ($phone !== '' && !preg_match('/^\d{11}$/', $phone)) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid phone number. Phone must be 11 digits (e.g. 09123456789).']);
      exit;
    }
    $role = trim($_POST['User_Role'] ?? 'Staff');
    // Use mysqli connection ($conn) instead of undefined $pdo
    global $conn;
    if (!isset($conn) || !($conn instanceof \mysqli)) {
      echo json_encode(['status' => 'error', 'message' => 'Database connection unavailable']);
      exit;
    }

    // Check if username already exists (allow if it belongs to an existing user who will be upgraded)
    $check = $conn->prepare("SELECT User_ID FROM users WHERE Username = ? LIMIT 1");
    if ($check) {
      $check->bind_param('s', $username);
      $check->execute();
      $res = $check->get_result();
      if ($res && ($row = $res->fetch_assoc())) {
        $existingUsernameUserId = (int)($row['User_ID'] ?? 0);
        if ($existingUsernameUserId > 0 && $existingUsernameUserId !== $existingUserId) {
          echo json_encode(['status' => 'error', 'message' => 'Username already taken!']);
          $check->close();
          exit;
        }
      }
      $check->close();
    }

    // Check if email already exists
    $existingRole = null;
    $checkEmail = $conn->prepare("SELECT User_ID, User_Role FROM users WHERE Email = ? LIMIT 1");
    if ($checkEmail) {
      $checkEmail->bind_param('s', $email);
      $checkEmail->execute();
      $res = $checkEmail->get_result();
      if ($res && ($row = $res->fetch_assoc())) {
        $existingUserId = (int)($row['User_ID'] ?? 0);
        $existingRole = $row['User_Role'] ?? null;
      }
      $checkEmail->close();
    }

    if ($existingUserId > 0 && strcasecmp((string)$existingRole, 'Staff') === 0) {
      // Email is already used by a staff — cannot add
      echo json_encode(['status' => 'error', 'message' => 'Email already belongs to an existing staff.']);
      exit;
    }
    // Generate verification code
    $verification_code = substr(number_format(time() * rand(), 0, '', ''), 0, 6);
    // Store in session
    $_SESSION['staff_registration'] = [
        'username' => $username,
        'passwordHash' => $password,
        'name' => $name,
        'email' => $email,
        'phonenumber' => $phone === '' ? null : $phone,
      'user_role' => $role,
      'existing_user_id' => $existingUserId,
        'verification_code' => $verification_code,
        'timestamp' => time()
    ];
    // Send email
    $emailResult = EmailApiController::sendVerificationEmail($email, $name, $verification_code);
    if ($emailResult === true) {
      echo json_encode(['status' => 'verification_sent', 'message' => 'Verification code sent to ' . $email . '. Please enter the code to complete registration.']);
    } else {
      unset($_SESSION['staff_registration']);
      echo json_encode(['status' => 'error', 'message' => is_string($emailResult) ? $emailResult : 'Failed to send verification email.']);
    }
    exit;
}

// VERIFY STAFF
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'verify_staff') {
    header('Content-Type: application/json');
    $code = trim($_POST['verification_code'] ?? '');
    if (empty($code)) {
        echo json_encode(['status' => 'error', 'message' => 'Verification code is required']);
        exit;
    }
    if (!isset($_SESSION['staff_registration'])) {
        echo json_encode(['status' => 'error', 'message' => 'No pending staff registration found']);
        exit;
    }
    $data = $_SESSION['staff_registration'];
    if (time() - $data['timestamp'] > 600) { // 10 minutes
        unset($_SESSION['staff_registration']);
        echo json_encode(['status' => 'error', 'message' => 'Verification code has expired']);
        exit;
    }
    if ($data['verification_code'] !== $code) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid verification code']);
        exit;
    }
    // Validate phone number again on verify step
    $phoneToSave = $data['phonenumber'] ?? '';
    if ($phoneToSave !== null && $phoneToSave !== '' && !preg_match('/^\d{11}$/', $phoneToSave)) {
      echo json_encode(['status' => 'error', 'message' => 'Invalid phone number. Phone must be 11 digits (e.g. 09123456789).']);
      exit;
    }
    // Insert new user or update existing user (upgrade role) using mysqli
    global $conn;
    $existingUserId = isset($data['existing_user_id']) ? (int)$data['existing_user_id'] : 0;
    if ($existingUserId > 0) {
      $updateStmt = $conn->prepare("UPDATE users SET Username = ?, Password = ?, Name = ?, Phonenumber = ?, User_Role = ? WHERE User_ID = ?");
      if ($updateStmt) {
        $u = $data['username'];
        $p = $data['passwordHash'];
        $n = $data['name'];
        $ph = $data['phonenumber'];
        $r = $data['user_role'];
        $uid = $existingUserId;
        $updateStmt->bind_param('sssssi', $u, $p, $n, $ph, $r, $uid);
        if ($updateStmt->execute()) {
          unset($_SESSION['staff_registration']);
          echo json_encode(['status' => 'success', 'message' => $data['name'] . ' promoted to ' . $data['user_role'] . '!']);
        } else {
          unset($_SESSION['staff_registration']);
          echo json_encode(['status' => 'error', 'message' => 'Error updating user: ' . $updateStmt->error]);
        }
        $updateStmt->close();
      } else {
        unset($_SESSION['staff_registration']);
        echo json_encode(['status' => 'error', 'message' => 'Failed to prepare update statement: ' . $conn->error]);
      }
    } else {
      $insertStmt = $conn->prepare("INSERT INTO users
        (Username, Password, Name, Email, Phonenumber, User_Role, Date_Created)
        VALUES (?, ?, ?, ?, ?, ?, NOW())");
      if ($insertStmt) {
        $u = $data['username'];
        $p = $data['passwordHash'];
        $n = $data['name'];
        $e = $data['email'];
        $ph = $data['phonenumber'];
        $r = $data['user_role'];
        $insertStmt->bind_param('ssssss', $u, $p, $n, $e, $ph, $r);
        if ($insertStmt->execute()) {
          unset($_SESSION['staff_registration']);
          echo json_encode(['status' => 'success', 'message' => $data['name'] . ' added as ' . $data['user_role'] . '!']);
        } else {
          unset($_SESSION['staff_registration']);
          echo json_encode(['status' => 'error', 'message' => 'Error inserting user: ' . $insertStmt->error]);
        }
        $insertStmt->close();
      } else {
        unset($_SESSION['staff_registration']);
        echo json_encode(['status' => 'error', 'message' => 'Failed to prepare insert statement: ' . $conn->error]);
      }
    }
    exit;
}

  // Profile editing removed: owner profile is read-only in the dashboard now.
// Existing handleAjax() for other actions (inventory, etc.)
if (isset($_GET['action']) || (isset($_POST['action']) && !in_array($_POST['action'], ['add_staff', 'verify_staff']))) {
    $ownerController->handleAjax();
    exit;
}

  $current_user = null;
  $userId = (int)($_SESSION['user_id'] ?? 0);
  $sessionUser = $_SESSION['user'] ?? [];
  if ($userId > 0) {
    $profile = $ownerController->getOwnerProfile($userId);
    if (is_array($profile)) {
      $current_user = $profile;
      $_SESSION['user'] = [
        'user_id' => (int)($profile['User_ID'] ?? $userId),
        'User_ID' => (int)($profile['User_ID'] ?? $userId),
        'Username' => $profile['Username'] ?? ($sessionUser['Username'] ?? ''),
        'Name' => $profile['Name'] ?? ($sessionUser['Name'] ?? ''),
        'Email' => $profile['Email'] ?? ($sessionUser['Email'] ?? ''),
        'Phonenumber' => $profile['Phonenumber'] ?? ($sessionUser['Phonenumber'] ?? ''),
        'user_role' => $profile['User_Role'] ?? ($sessionUser['user_role'] ?? ''),
        'User_Role' => $profile['User_Role'] ?? ($sessionUser['User_Role'] ?? ''),
      ];
      $_SESSION['username'] = $_SESSION['user']['Username'];
      $_SESSION['user_role'] = $_SESSION['user']['user_role'];
    }
  }

  if ($current_user === null && !empty($sessionUser)) {
    $current_user = $sessionUser;
  }

  if (!is_array($current_user)) {
    $current_user = [
      'User_ID' => 0,
      'Name' => 'Owner',
      'Username' => 'owner',
      'Email' => '',
      'Phonenumber' => '',
      'User_Role' => 'Owner',
      'user_role' => 'Owner',
    ];
  }
$dashboardStats = $ownerController->getDashboardStats();
$inventoryData = $ownerController->getInventory();
$productPerformance = $ownerController->getProductPerformance();
?>
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Guillermo’s Admin Dashboard</title>
  <link rel="icon" type="image/x-icon" href="../../guillermos.ico">
  <link rel="shortcut icon" type="image/x-icon" href="../../guillermos.ico">
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Pacifico&display=swap" rel="stylesheet">
  <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js"></script>
  <style>
    body {font-family:'Poppins',sans-serif;background:#fefcf7;margin:0;padding:0;}
    /* Sidebar: brown + white combination */
    .sidebar{
      width:250px;
      height:100vh;
      /* soft white-to-brown gradient */
      background: linear-gradient(180deg, #ffffff 0%, #fbf6f0 30%, #f2e7dc 60%, #fffaf6 100%);
      border-right:1px solid #e6dccf;
      position:fixed;top:0;left:0;padding:1rem;
      box-shadow: 0 6px 18px rgba(75,47,0,0.04);
      overflow:visible;
      transition: transform .25s ease;
    }
    /* Replaced image logo with floating font logo */
    .sidebar .logo-floating {
      font-family: 'Pacifico', 'Brush Script MT', cursive;
      font-size:34px;
      color:#4d2e00;
      display:inline-block;
      padding:6px 12px;
      background: rgba(255,255,255,0.7);
      border-radius:12px;
      box-shadow: 0 6px 18px rgba(75,47,0,0.08);
      position:relative;
      left:50%;
      transform:translateX(-50%);
      margin-bottom:1.25rem;
      z-index:5;
      transition: transform .25s ease;
    }
    .sidebar .logo-floating:hover { transform: translateX(-50%) translateY(-3px); }
    .sidebar .nav-link{color:#4d2e00;font-weight:500;margin-bottom:.5rem;border-radius:6px;cursor:pointer;display:flex;align-items:center;gap:10px;padding:10px;}
    .sidebar .nav-link.active{background:#c1976b;color:#fff;}
    .header{background:#6B4F3F;color:#fff;padding:20px 40px;position:fixed;left:250px;right:0;top:0;z-index:10;
            box-shadow:0 2px 10px rgba(0,0,0,.1);display:flex;justify-content:space-between;align-items:center;}
    .header .title { flex-shrink: 1; min-width: 0; }
    .header .title p{margin:0;font-size:1rem; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
    .main{margin-left:250px;margin-top:100px;padding:20px 40px;transition: margin-left .3s;}

    /* Smooth page transition */
    /* pages will show a blurred background image (Front.jpg) — applied only to main content pages */
    .page {
      display: none;
      opacity: 0;
      transition: opacity 0.3s ease;
      position: relative; /* required for pseudo-element background */
      overflow: hidden;
    }
    .page.active {display: block; opacity: 1;}
    /* Background image (blurred) for the requested pages */
    #dashboard::before,
    #funding::before,
    #performance::before,
    #inventory::before,
    #history::before {
      content: "";
      position: absolute;
      inset: 0;
    
      background-size: cover;
      background-position: center;
      /* blur + slight darken to keep text readable */
      filter: blur(8px) brightness(0.6) saturate(0.95);
      transform: scale(1.03); /* avoid edges when blurred */
      z-index: 0;
      pointer-events: none;
    }
    /* Ensure page content appears above the blurred background */
    .page > * { position: relative; z-index: 1; }
    /* ==== USER PROFILE: open a Bootstrap modal with a nice form ==== */
    .user-profile-dropdown .profile-btn {
      background: none;
      border: none;
      color: #fff;
      font-size: 1.6rem;
      padding: 0;
      display: flex;
      align-items: center;
      gap: 8px;
      cursor: pointer;
    }
    .user-profile-dropdown .profile-btn:focus { outline:none; box-shadow: 0 0 0 0.15rem rgba(255,255,255,0.12); }
    .profile-modal .modal-content { border-radius: 16px; overflow: hidden; }
    .profile-modal .modal-header { background: linear-gradient(90deg,#c1976b,#8d6e63); color: #fff; border:none; }
    .profile-modal .modal-title { font-weight:700; }
    .profile-avatar {
      width:72px;height:72px;border-radius:50%;background:#fff;display:flex;align-items:center;justify-content:center;color:#4d2e00;font-weight:700;font-size:1.1rem;border:4px solid rgba(255,255,255,0.25);
      box-shadow: 0 10px 24px rgba(0,0,0,0.06);
    }
    /* Cards */
    .card-box{background:#d7b79a;border-radius:20px;padding:25px;color:#fff;display:flex;align-items:center;justify-content:space-between;box-shadow:0 4px 12px rgba(0,0,0,.1);transition:transform .2s;height:130px;}
    .card-box:hover{transform:translateY(-5px);}
    .card-box img{width:60px;height:60px;}
    .card-text p{margin:0;margin-top:6vh;font-size:1rem;font-weight:700;color:#3b2c23;}
     /* Order Summary */
    .order-summary-card{background:#f5e6d3;border-radius:20px;padding:25px;box-shadow:0 4px 12px rgba(0,0,0,.1);text-align:center;height:100%;display:flex;flex-direction:column;justify-content:flex-start;transition:transform .2s;}
    .order-summary-card:hover{transform:translateY(-5px);}
    .order-summary-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;font-weight:700;color:#4d2e00;}
    .order-tabs{display:flex;gap:15px;position:relative;}
    .order-tab{cursor:pointer;padding:5px 10px;font-size:0.9rem;color:#8d6e63;transition:color .3s;}
    .order-tab.active{color:#4d2e00;}
    .underline{position:absolute;Bottom:-8px;height:2px;background:#4d2e00;transition:all .3s ease;border-radius:2px;}
    .no-orders-msg{margin-top:30px;color:#8d6e63;font-size:1.1rem;}
    .no-orders-msg i{font-size:2.5rem;color:#d7b79a;margin-bottom:10px;}
    /* Funding */
    .no-funding{text-align:center;padding:40px;color:#8d6e63;font-size:1.2rem;}
    .no-funding i{font-size:3rem;color:#d7b79a;margin-bottom:15px;}
    /* Revenue & Charts */
    .revenue-section,.chart-placeholder{background:#fff;border-radius:16px;padding:25px;box-shadow:0 4px 10px rgba(0,0,0,.05);}
    .chart-placeholder{height:300px;display:flex;justify-content:center;align-items:center;color:#b08968;font-weight:600;font-size:1.1rem;}
    /* ---- Product Performance ---- */
    .perf-header{display:flex;gap:12px;align-items:center;margin-bottom:20px;flex-wrap:wrap;}
    .cat-btn{padding:6px 14px;border-radius:20px;background:#fff;color:#4d2e00;font-weight:600;cursor:pointer;transition:.2s;}
    .cat-btn.active,.cat-btn:hover{background:#e2c9a7;}
    .dropdown-menu{--bs-dropdown-min-width:220px;}
    .product-card{background:#fff;border-radius:16px;padding:16px;box-shadow:0 2px 8px rgba(0,0,0,.06);display:flex;align-items:center;gap:16px;margin-bottom:12px;}
    .product-img{flex:0 0 70px;height:70px;background:#e9ecef;border-radius:12px;}
    .product-img img{width:100%;height:100%;object-fit:cover;border-radius:12px;}
    .product-img.placeholder{display:flex;align-items:center;justify-content:center;font-size:1.5rem;color:#c1b7ae;}
    .product-info{flex:1;}
    .product-name{font-weight:600;color:#3b2c23;margin-bottom:4px;}
    .product-sales{font-size:.9rem;color:#8d6e63;}
    .rating{font-size:.85rem;color:#ffb400;}
    .quantity{font-weight:600;color:#4d2e00;}
    .empty-msg{text-align:center;color:#8d6e63;margin-top:40px;font-size:1.1rem;}
    .empty-msg i{font-size:2.5rem;color:#d7b79a;margin-bottom:12px;display:block;}
    .pagination{margin-top:20px;display:flex;gap:8px;justify-content:center;}
    .page-link{padding:6px 12px;border-radius:8px;background:#fff;color:#4d2e00;border:1px solid #ddd;cursor:pointer;}
    .page-link.active{background:#e2c9a7;border-color:#e2c9a7;}
    .page-link.disabled{color:#bbb;cursor:not-allowed;}
    /* ---- Inventory Page ---- */
    .inventory-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:12px;}
    .add-product-btn{background:#4d2e00;color:#fff;padding:8px 16px;border-radius:20px;font-weight:600;cursor:pointer;transition:.2s;}
    .add-product-btn:hover{background:#3a2300;}
    .inventory-table{width:100%;background:#fff;border-radius:16px;box-shadow:0 4px 10px rgba(0,0,0,.05);}
    .inventory-table table{width:100%;border-collapse:collapse;}
    .inventory-table th{background:#f5e6d3;padding:16px;text-align:left;font-weight:600;color:#4d2e00;}
    .inventory-table td{padding:14px;font-size:.95rem;color:#3b2c23;}
    .inventory-table tr{border-bottom:1px solid #eee;}
    .inventory-table tr:hover{background:#fdf9f0;}
    .stock-low{color:#d32f2f;font-weight:600;}
    .filter-select{padding:6px 12px;border-radius:20px;border:1px solid #ddd;font-size:.9rem;}
    .action-btn{background:none;border:none;color:#6c757d;cursor:pointer;font-size:1.1rem;}
    .action-btn.edit{color:#4d2e00;}
    .action-btn.delete{color:#d32f2f;}
    .modal-content{border-radius:16px;}
    .modal-header{border-bottom:none;padding:20px 24px;}
    .modal-title{font-weight:700;color:#4d2e00;}
    .modal-body{padding:20px 24px;}
    .form-label{font-weight:600;color:#4d2e00;}
    .form-control, .form-select{border-radius:12px;}
    .btn-primary{background:#4d2e00;border:none;border-radius:12px;padding:10px 20px;}
    .btn-primary:hover{background:#3a2300;}
    /* Live Clock Styling */
    #datetime {
      font-size: 0.85rem;
      color: #ffffffff;
      margin-top: 4px;
    }
    /* Prevent success message from blocking clicks */
    #successMessage {
      pointer-events: none !important;
    }
    #successMessage > * {
      pointer-events: auto !important;
    }
    /* Improved Button Styles (general improvements where buttons fit) */
    .btn {
      border-radius: 12px;
      transition: transform .12s ease, box-shadow .12s ease, opacity .12s ease;
    }
    .btn:active { transform: translateY(1px); }
    .btn:focus { box-shadow: 0 0 0 0.2rem rgba(75, 47, 0, 0.15); outline: none; }
    .dashboard-actions {
      flex-wrap: wrap;
    }
    .dashboard-actions > * {
      white-space: nowrap;
    }
    /* Announcements */
    .announcement-card{background:#fff;border-radius:16px;padding:20px;box-shadow:0 8px 20px rgba(0,0,0,0.08);}
    .announcement-card-header{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:16px;}
    .announcement-card-header h5{margin:0;color:#4d2e00;font-weight:700;}
    .announcement-card-header small{color:#8d6e63;}
    .announcement-list{list-style:none;margin:0;padding:0;display:flex;flex-direction:column;gap:12px;}
    .announcement-item{display:flex;justify-content:space-between;align-items:flex-start;gap:16px;background:#fdf7f1;border-radius:12px;padding:14px 16px;}
    .announcement-text{margin:0;color:#4d2e00;font-weight:500;}
    .announcement-meta{font-size:.8rem;color:#8d6e63;margin-top:6px;display:flex;gap:12px;flex-wrap:wrap;}
    .announcement-actions{display:flex;gap:8px;}
    .announcement-action{border:none;background:#6B4F3F;color:#fff;padding:6px 12px;border-radius:999px;font-size:.8rem;cursor:pointer;transition:background .2s;}
    .announcement-action:hover{background:#5a4234;}
    .announcement-empty{padding:16px;border-radius:12px;background:#f8f1e8;color:#8d6e63;text-align:center;font-size:.95rem;}
    .btn-brown {
      background-color: #6B4F3F;
      color: #fff;
      border-color: #6B4F3F;
    }
    .btn-brown:hover { background-color: #5a4234; color: #fff; border-color: #5a4234; }
    .btn-history:hover { opacity: .95; transform: translateY(-2px); }
    /* AI Order Analytics */
    .ai-analytics-shell{position:relative;min-height:360px;}
    .ai-loading-overlay{position:absolute;inset:0;display:flex;flex-direction:column;justify-content:center;align-items:center;text-align:center;background:rgba(255,250,244,0.92);color:#6B4F3F;z-index:10;padding:48px 16px;backdrop-filter:blur(2px);}
    .ai-loading-overlay .spinner-border{color:#6B4F3F;width:2.5rem;height:2.5rem;}
    .ai-loading-overlay .loading-headline{font-weight:600;font-size:1.05rem;}
    .ai-loading-overlay .loading-subtle{color:#8d6e63;font-size:.85rem;}
    .ai-regression-card{background:#fff7ec;border-radius:14px;padding:14px 16px;box-shadow:inset 0 0 0 1px rgba(107,79,63,0.12);font-size:.9rem;color:#4d2e00;}
    .ai-regression-card.regression-up{border-left:4px solid #2e7d32;}
    .ai-regression-card.regression-down{border-left:4px solid #c62828;}
    .ai-prediction-footer{background:#fff7ec;border-radius:12px;padding:14px 18px;box-shadow:0 8px 18px rgba(0,0,0,0.05);color:#4d2e00;font-size:.95rem;}
    .ai-summary-card{background:#fff;border-radius:18px;padding:20px;box-shadow:0 6px 16px rgba(0,0,0,0.05);min-height:150px;display:flex;flex-direction:column;justify-content:space-between;gap:6px;}
    .ai-summary-card h5{font-weight:700;color:#4d2e00;margin:0;}
    .ai-summary-metric{font-size:2rem;font-weight:700;color:#3b2c23;}
    .ai-summary-delta{font-size:.9rem;font-weight:600;color:#8d6e63;}
    .ai-summary-delta.positive{color:#2e7d32;}
    .ai-summary-delta.negative{color:#c62828;}
    .ai-insights-card{background:#fff;border-radius:18px;padding:24px;box-shadow:0 8px 18px rgba(0,0,0,0.06);}
    .ai-insights-card h5{font-weight:700;color:#4d2e00;}
    .ai-insights-card ul{margin:0;padding-left:20px;}
    .ai-insights-card li{margin-bottom:10px;color:#4d2e00;line-height:1.5;}
    .ai-loading-overlay.d-none{display:none!important;}
    .ai-error{border-radius:16px;}
    #aiTrendChartWrapper,#aiPaymentChartWrapper{background:#fff;border-radius:18px;padding:20px;box-shadow:0 8px 18px rgba(0,0,0,0.05);min-height:380px;}
    #aiTrendChart,#aiPaymentChart{max-height:300px;}
    #aiPaymentChartWrapper h5{font-weight:700;color:#4d2e00;}
    .ai-table thead{background:#f5e6d3;color:#4d2e00;}
    .ai-table tbody tr:nth-child(even){background:#fff8f1;}
    .ai-table td,.ai-table th{vertical-align:middle;}
    #aiPeaksList li{margin-bottom:8px;color:#4d2e00;}
    #aiPeaksList li:last-child{margin-bottom:0;}
    .badge-muted{background:rgba(109,83,60,0.1);color:#6B4F3F;}
    .history-table{
      background:#fff;
      border-radius:20px;
      padding:24px;
      box-shadow:0 14px 32px rgba(45,29,12,0.12);
      border:1px solid rgba(155,130,100,0.18);
    }
    .history-table::before{display:none;}
    .history-table table{
      width:100%;
      border-collapse:separate;
      border-spacing:0 20px;
    }
    .history-head{display:none;}
    .history-row{
      background:transparent;
      box-shadow:none;
      border-radius:0;
      transition:none;
    }
    .history-row:hover{transform:none;}
    .history-row td{
      padding:0;
      border:none;
    }
    .history-card{
      background:#fff;
      border-radius:18px;
      border:1px solid rgba(155,130,100,0.18);
      box-shadow:0 12px 28px rgba(45,29,12,0.12);
      padding:18px 20px;
      display:flex;
      flex-direction:column;
      gap:14px;
    }
    .history-card-top{
      display:flex;
      justify-content:space-between;
      align-items:flex-start;
      gap:16px;
      flex-wrap:wrap;
    }
    .history-card-tags{
      display:flex;
      flex-wrap:wrap;
      gap:10px;
      align-items:center;
    }
    .history-id-badge{
      display:inline-flex;
      align-items:center;
      gap:8px;
      background:#4d2e00;
      color:#fff;
      font-weight:600;
      font-size:0.82rem;
      padding:7px 12px;
      border-radius:999px;
      box-shadow:0 8px 18px rgba(77,46,0,0.22);
    }
    .history-id-badge i{font-size:0.85rem;opacity:0.9;}
    .history-pill{
      display:inline-flex;
      align-items:center;
      justify-content:center;
      font-weight:600;
      font-size:0.75rem;
      padding:6px 12px;
      border-radius:999px;
      letter-spacing:0.02em;
    }
    .history-pill-add{background:rgba(46,204,113,0.14);color:#1d7c4e;}
    .history-pill-update{background:rgba(255,193,7,0.18);color:#9b6b00;}
    .history-pill-remove{background:rgba(231,76,60,0.14);color:#b9382a;}
    .history-pill-neutral{background:rgba(149,117,84,0.18);color:#5d422d;}
    .history-headline{
      font-weight:700;
      color:#2d1c10;
      font-size:1rem;
    }
    .history-card-main{
      display:flex;
      flex-direction:column;
      gap:10px;
    }
    .history-meta{
      display:flex;
      flex-wrap:wrap;
      gap:6px;
      margin:4px 0 0;
      padding:0;
      list-style:none;
    }
    .history-meta li{
      background:rgba(151,120,88,0.15);
      color:#5d422d;
      border-radius:999px;
      padding:4px 10px;
      font-size:0.78rem;
      font-weight:600;
    }
    .history-note{
      margin-top:12px;
      background:#faf3ea;
      border:1px solid rgba(155,130,100,0.2);
      border-radius:12px;
      padding:10px 14px;
      color:#4d2e00;
      font-size:0.9rem;
      line-height:1.4;
      box-shadow:inset 0 2px 4px rgba(77,46,0,0.08);
    }
    .history-note div + div{margin-top:4px;}
    .history-note-empty{
      background:rgba(245,229,212,0.6);
      color:#9d8060;
      font-style:italic;
      border-style:dashed;
    }
    .history-card-footer{
      display:flex;
      justify-content:space-between;
      align-items:center;
      flex-wrap:wrap;
      gap:10px;
      padding-top:12px;
      border-top:1px solid rgba(155,130,100,0.2);
    }
    .history-user-main{
      display:inline-flex;
      align-items:center;
      gap:8px;
      color:#6b4f3f;
      font-weight:600;
    }
    .history-card-timestamp{
      display:flex;
      flex-direction:column;
      align-items:flex-end;
      text-align:right;
      gap:2px;
      color:#6b4f3f;
    }
    .history-date-date{color:#2d1c10;font-weight:700;}
    .history-date-time{color:#5d422d;font-weight:600;font-size:0.9rem;}
    .history-date-zone{
      font-size:0.72rem;
      font-weight:600;
      color:#9d8060;
      letter-spacing:0.08em;
      text-transform:uppercase;
    }
    .history-role-badge{
      display:inline-flex;
      align-items:center;
      background:rgba(107,79,63,0.12);
      color:#4d2e00;
      border-radius:6px;
      font-size:0.75rem;
      padding:3px 8px;
      font-weight:600;
    }
    .history-empty{
      text-align:center;
      color:#8d6e63;
      padding:50px 20px;
      font-weight:600;
      background:rgba(255,255,255,0.8);
      border-radius:12px;
    }
    .history-spinner{
      width:26px;
      height:26px;
      border:3px solid rgba(107,79,63,0.2);
      border-top-color:#6b4f3f;
      border-radius:50%;
      margin:0 auto 14px;
      animation:historySpin .8s linear infinite;
    }
    @keyframes historySpin { to { transform: rotate(360deg); } }
    .history-controls{
      display:flex;
      gap:10px;
      align-items:center;
      flex-wrap:wrap;
      justify-content:flex-start;
    }
    .history-controls #refreshHistory{
      margin-left:auto;
      background:#f7e1c6;
      border-color:transparent;
      color:#6b4f3f;
    }
    .history-controls #refreshHistory:hover{background:#efd1ae;}
    .history-controls #exportHistory{
      background:#6b4f3f;
      border:none;
      color:#fff;
      box-shadow:0 6px 15px rgba(77,46,0,0.22);
    }
    .history-controls #exportHistory:hover{background:#5a3e30;}
    .history-updated{color:#af8a62;font-weight:600;display:block;margin-top:6px;}

    @media (max-width:767px) {
      .header{padding:12px 16px; flex-wrap: wrap; height: auto;}
      .header .title { order: 2; width: 100%; text-align: left; padding-top: 8px; }
      .header .title p:first-child { display: none; } /* Hide "WELCOME BACK" on mobile */
      .header .d-flex.align-items-center.gap-3 { order: 1; margin-left: auto; } /* User icons */
      .header > div:first-of-type { order: 0; } /* Hamburger */
      .main{padding:12px 16px; margin-top: 130px;}
      .sidebar{width:200px;}      
      .card-box { flex-direction: column; align-items: flex-start; height: auto; position: relative; }
      .card-box img { position: absolute; top: 15px; right: 15px; width: 45px; height: 45px; opacity: 0.7; }
      .card-text p { margin-top: 0; }      
      .page .card-box {height:auto;}
      .history-controls { gap:8px; }
      .history-controls #refreshHistory { margin-left: 0; order:3; width:auto; }
      .history-controls #exportHistory { order:4; width:auto; }
      .history-table{padding:16px;}
      .history-table table{border-spacing:0 16px;}
      .history-card{padding:16px;gap:12px;}
      .history-card-top{flex-direction:column;align-items:flex-start;gap:12px;}
      .history-card-timestamp{align-items:flex-start;text-align:left;}
      .history-card-footer{flex-direction:column;align-items:flex-start;gap:8px;}
      .announcement-item{flex-direction:column;}
      .announcement-actions{align-self:flex-end;}
      .dashboard-actions {
        width: 100%;
        gap: 10px;
        justify-content: flex-start;
        margin-top: 12px;
      }
      .dashboard-actions > * {
        flex: 1 1 100%;
        text-align: center;
      }
    }
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
 /* --- Customer-style user icon and dropdown for owner (matches staff) --- */
        .user-profile-wrapper {
          position: relative;
          display: inline-block;
        }
        .profile-btn {
          font-size: 30px;
          background: none;
          border: none;
          outline: none;
          color: #6f4e37;
          display: flex;
          align-items: center;
          justify-content: center;
          padding: 0;
          transition: color 0.2s;
        }
        .profile-btn:hover {
          transform: scale(1.18);
          background: rgba(255, 255, 255, 0.18);
          box-shadow: 0 8px 20px rgba(231, 111, 81, 0.25);
          color: #f4a261 !important;
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
        .dropdown-header {
          font-size: 1rem;
          color: #4d2e00;
          background: #f9f1e8;
          border-bottom: 1px solid #eee;
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
        .menu-divider { margin: 8px 0; border: none; border-top: 1px solid #eee; }
       
    /* ---------- HAMBURGER + RESPONSIVE SIDEBAR (ADDED, minimal & non-intrusive) ---------- */
    /* Hamburger button that looks like 3 lines; placed on header left */
    .hamburger-btn {
      background: none;
      border: none;
      width:44px;
      height:44px;
      display:inline-flex;
      align-items:center;
      justify-content:center;
      cursor:pointer;
      margin-right:12px;
      border-radius:8px;
      transition: background .15s, transform .15s;
      color: #fff;
    }
    .hamburger-btn:hover { background: rgba(255,255,255,0.06); transform: scale(1.02); }
    .hamburger-lines {
      display:inline-block;
      width:22px;
      height:2px;
      background:#fff;
      position:relative;
      border-radius:2px;
    }
    .hamburger-lines::before,
    .hamburger-lines::after {
      content: "";
      position: absolute;
      left: 0;
      width:22px;
      height:2px;
      background:#fff;
      border-radius:2px;
      transition: transform .18s ease, top .18s ease, bottom .18s ease, opacity .18s;
    }
    .hamburger-lines::before { top: -7px; }
    .hamburger-lines::after { bottom: -7px; }

    /* Desktop: allow collapsing sidebar without shifting breaking layout */
    @media (min-width:768px) {
      body.sidebar-collapsed .sidebar { transform: translateX(-260px); }
      body.sidebar-collapsed .header { left: 0; }
      body.sidebar-collapsed .main { margin-left: 0; }
    }
    /* Mobile: default hide sidebar off-canvas; show when body.mobile-sidebar-open present */
    @media (max-width:767px) {
      .sidebar { transform: translateX(-260px); width:200px; left:0; }
      body.mobile-sidebar-open .sidebar { transform: translateX(0); z-index: 99999; box-shadow: 0 8px 32px rgba(0,0,0,0.4); }
      /* When off-canvas open, we add an overlay */
      #sidebarOverlay { display:none; }
      body.mobile-sidebar-open #sidebarOverlay { display:block; }
      /* keep header and main full-width on mobile (do not shift) */
      .header { left:0 !important; }
      .main { margin-left:0 !important; }
    }
    /* Overlay used only for mobile open state */
    #sidebarOverlay {
      position: fixed;
      inset: 0;
      background: rgba(0,0,0,0.35);
      z-index: 99998;
      display: none;
      transition: opacity .18s;
    }
  </style>
</head>
<body>
  <!-- Sidebar-same as staff & inserted logo, changes, 11-17-25-->
<div class="sidebar d-flex flex-column">
  <!-- Floating font logo -->
  <div class="text-center mb-3">
    <div class="logo-floating">Guillermo's</div>
  </div>
  <!-- Navigation -->
 <ul class="nav nav-pills flex-column mb-auto">
    <li class="nav-item">
      <a class="nav-link active" data-page="dashboard">
        <img src="icons/dasshboard.png" alt="Dashboard" class="me-3" width="22" height="22">
        Dashboard
      </a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-page="funding">
        <img src="icons/funding.png" alt="Funding" class="me-3" width="22" height="22">
        Funding Projections
      </a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-page="performance">
        <img src="icons/performance.png" alt="Performance" class="me-3" width="22" height="22">
        Product Performance
      </a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-page="ai-analytics">
        <i class="bi bi-robot me-3" style="font-size:1.05rem;"></i>
        AI Order Analytics
      </a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-page="inventory">
        <img src="icons/inventory.png" alt="Inventory" class="me-3" width="22" height="22">
        Inventory
      </a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-page="history">
        <i class="bi bi-clock-history me-3" style="font-size:1.05rem;"></i>
        System History
      </a>
    </li>
    <li class="nav-item">
      <a class="nav-link" data-page="manage-staff">
        <i class="bi bi-people-fill me-3" style="font-size:1.05rem;"></i>
        Manage Staff
      </a>
    </li>
  </ul>
</div>

<!-- Overlay for mobile sidebar -->
<div id="sidebarOverlay" onclick="document.body.classList.remove('mobile-sidebar-open');"></div>

  <!-- Header -->
  <div class="header">
    <!-- Hamburger on the left -->
    <div style="display:flex;align-items:center;gap:8px;">
      <button id="hamburger" class="hamburger-btn" aria-label="Toggle sidebar" title="Toggle sidebar">
        <span class="hamburger-lines" aria-hidden="true"></span>
      </button>
      <div class="title">
        <p>WELCOME BACK, <span id="ownerWelcomeName"><?= htmlspecialchars($current_user['Name'] ?? 'Owner') ?></span></p>
        <div id="datetime"></div>
      </div>
    </div>

    <!-- USER PROFILE -->
    <div class="d-flex align-items-center gap-3">
      <!-- Bell icon (optional, for parity with staff) -->
      <div class="dropdown">
        <i class="bi bi-bell position-relative" style="font-size:1.5rem;cursor:pointer;margin-right: 10px;color:#fff;" id="notifBell" data-bs-toggle="dropdown" aria-expanded="false" title="Notifications"></i>
        <ul class="dropdown-menu dropdown-menu-end p-2" aria-labelledby="notifBell" style="min-width:220px; max-height:300px; overflow-y:auto;">
          <li class="dropdown-item text-muted">No notifications</li>
        </ul>
      </div>
      <!-- User icon and dropdown -->
      <div class="user-profile-wrapper">
            <button class="icon-btn profile-btn" id="userIcon">
                👤
            </button>
            <!-- Dropdown Menu -->
        <div id="userDropdown" class="user-dropdown-menu">
          <div class="dropdown-header p-3 border-bottom">
            <span id="ownerNameDisplay"><?= htmlspecialchars($current_user['Name'] ?? 'Owner') ?></span>
            <div id="ownerEmailDisplay"><?= htmlspecialchars($current_user['Email'] ?? '') ?></div>
          </div>
          <a href="#" class="dropdown-link" id="openProfileLink">
            👤 My Profile
          </a>
          <div class="menu-divider"></div>
          <a href="../../index.php" class="dropdown-link text-danger"><i class="bi bi-box-arrow-right"></i> Logout</a>
        </div>
      </div>
    </div>
  </div>
</div>
  <!-- OWNER PROFILE OVERLAY -->
  <div id="profile-overlay" class="overlay" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;align-items:center;justify-content:center;z-index:99999;background:rgba(0,0,0,0.6);">
  <div class="profile-card-box" style="background:#fff;border-radius:22px;box-shadow:0 8px 32px rgba(44,37,29,0.18);padding:38px 36px 40px;max-width:430px;width:96vw;position:relative;">
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
      <p style="color:#888;font-size:1.05rem;margin:0;">Update your personal information</p>
    </div>
      <form id="profile-form">
       
        <div class="form-group">
            <label class="form-label">👤 Full Name</label>
          <input type="text" class="form-control" name="fullname" value="<?= htmlspecialchars($current_user['Name'] ?? '') ?>" readonly>
        </div>
        <div class="form-group" style="margin-bottom:18px;">
          <label class="form-label" style="font-weight:600;color:#4d2e00;margin-bottom:8px;font-size:0.95rem;">
            <i class='bi bi-tag-fill' style='color:#b57b46;'></i> Username</label>
          <input type="text" class="form-control" name="username" value="<?= htmlspecialchars($current_user['Username'] ?? '') ?>" readonly>
        </div>
         
        <div class="form-group" style="margin-bottom:18px;">
          <label class="form-label" style="font-weight:600;color:#4d2e00;margin-bottom:8px;font-size:0.95rem;">
            <i class='bi bi-envelope-fill' style='color:#a0845c;'></i> Email Address
          </label>
          <input type="email" class="form-control" name="email" value="<?= htmlspecialchars($current_user['Email'] ?? '') ?>" readonly>
        </div>
        <div class="form-group" style="margin-bottom:18px;">
          <label class="form-label" style="font-weight:600;color:#4d2e00;margin-bottom:8px;font-size:0.95rem;">
            <i class='bi bi-telephone-fill' style='color:#c1976b;'></i> Phone Number
          </label>
          <input type="text" class="form-control" name="phone" value="<?= htmlspecialchars($current_user['Phonenumber'] ?? '') ?>" readonly>
        </div>
        <div style="text-align:right;margin-top:30px;">
          <button type="button" id="profileCloseBtn" class="btn-place-order" style="width:100%;padding:14px;font-size:1rem;background:linear-gradient(135deg,#6f4e37,#b57b46);color:#fff;border:none;border-radius:50px;font-weight:600;display:flex;align-items:center;justify-content:center;gap:8px;box-shadow:0 4px 15px rgba(107,79,63,0.3);">
            Close
          </button>
        </div>
      </form>
    </div>
  </div>
</div>
  <!-- Success Message Toast -->
  <div id="successMessage" class="alert alert-success alert-dismissible fade" style="display:none; position:fixed; top:80px; right:20px; z-index:9999; min-width:300px; box-shadow:0 4px 12px rgba(0,0,0,.15);">
    <i class="bi bi-check-circle-fill me-2"></i>
    <span id="successText">Operation completed successfully!</span>
    <button type="button" class="btn-close" onclick="hideSuccessMessage()"></button>
  </div>
  <!-- Main Content -->
  <div class="main" id="page-content">
    <!-- ==================== DASHBOARD ==================== -->
    <div class="page active" id="dashboard">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 style="color:#4d2e00;font-weight:700;margin:0;">Dashboard</h4>
          <small class="text-muted">Overview of recent activity</small>
        </div>
        <div class="d-flex gap-2 dashboard-actions">
          <button type="button" class="btn btn-outline-light" id="openAnnouncementQuick" data-bs-toggle="modal" data-bs-target="#announcementModal" style="background:#c08457;color:#fff;border-radius:12px;border:none;">
            <i class="bi bi-megaphone-fill me-1"></i> New Announcement
          </button>
          <!-- Add Staff header button remains; floating button removed as requested -->
          <button type="button" class="btn btn-outline-light" id="openStaffQuick" data-bs-toggle="modal" data-bs-target="#staffModal" style="background:#4d2e00;color:#fff;border-radius:12px;">
            <i class="bi bi-person-plus-fill me-1"></i> Add Staff
          </button>
        </div>
      </div>
      <div class="row g-4 mb-4">
        <div class="col-md-3">
          <div class="card-box">
            <div class="card-text">
              <p>Total Customer<br><strong><?= number_format($dashboardStats['total_customers'] ?? 0) ?></strong></p>
            </div>
            <img src="icons/customer.png" alt="">
          </div>
        </div>
        <div class="col-md-3">
          <div class="card-box">
            <div class="card-text">
              <p>Total Orders<br><strong><?= number_format($dashboardStats['total_orders'] ?? 0) ?></strong></p>
            </div>
            <img src="icons/orders.png" alt="">
          </div>
        </div>
        <div class="col-md-3">
          <div class="card-box">
            <div class="card-text">
              <p>Total Delivered<br><strong><?= number_format($dashboardStats['total_delivered'] ?? 0) ?></strong></p>
            </div>
            <img src="icons/delivered.png" alt="">
          </div>
        </div>
        <div class="col-md-3">
          <div class="card-box">
            <div class="card-text">
              <p>Total Revenue<br><strong>₱<?= number_format($dashboardStats['total_revenue'] ?? 0, 2) ?></strong></p>
            </div>
            <img src="icons/revenue.png" alt="">
          </div>
        </div>
      </div>
      <div class="row g-4 mt-2">
        <div class="col-md-4">
          <div class="order-summary-card">
            <div class="order-summary-header">
              <h5 class="mb-0">Order Summary</h5>
              <div class="order-tabs">
                <div class="order-tab active" data-period="today">Today</div>
                <div class="order-tab" data-period="weekly">Weekly</div>
                <div class="order-tab" data-period="monthly">Monthly</div>
                <div class="underline" style="width:50px; left:10px;"></div>
              </div>
            </div>
            <div id="orderSummaryContent" class="p-4">
              <div class="d-flex justify-content-between align-items-center mb-3">
                <span class="text-muted">Total Orders</span>
                <span class="fw-bold fs-4" id="orderCount"><?= number_format($dashboardStats['orders_today'] ?? 0) ?></span>
              </div>
              <div class="d-flex justify-content-between align-items-center">
                <span class="text-muted">Revenue</span>
                <span class="fw-bold fs-4 text-success" id="orderRevenue">₱<?= number_format($dashboardStats['revenue_today'] ?? 0, 2) ?></span>
              </div>
            </div>
          </div>
        </div>
        <div class="col-md-8 position-relative">
          <div class="revenue-section" style="position:relative;">
            <div class="d-flex justify-content-between align-items-center mb-3">
              <div>
                <h5 class="fw-bold mb-0">Revenue Chart</h5>
              </div>
              <select id="revenueChartPeriod" class="form-select form-select-sm" style="width:120px;">
                <option value="weekly">Weekly</option>
                <option value="monthly">Monthly</option>
                <option value="yearly">Yearly</option>
              </select>
            </div>
            <div style="height:280px; position:relative;">
              <canvas id="revenueChart"></canvas>
            </div>
            <!-- Generate Report Button -->
            <button id="generateReportBtn" class="btn btn-success fw-bold d-flex align-items-center gap-2" style="position:absolute; bottom:18px; right:18px; z-index:2; box-shadow:0 2px 8px rgba(0,0,0,0.10);">
              <i class="bi bi-file-earmark-arrow-down"></i> Generate Report
            </button>
          </div>
        </div>
       
      </div>
      <div class="row g-4 mt-3">
        <div class="col-12">
          <div class="announcement-card">
            <div class="announcement-card-header">
              <div>
                <h5>Announcements</h5>
                <small>Share updates that customers will instantly see.</small>
              </div>
              <button type="button" class="btn btn-brown btn-sm" data-bs-toggle="modal" data-bs-target="#announcementModal">
                <i class="bi bi-plus-circle me-1"></i> New Announcement
              </button>
            </div>
            <ul class="announcement-list" id="announcementList">
              <li class="announcement-empty">No announcements yet. Use “New Announcement” to post an update.</li>
            </ul>
          </div>
        </div>
      </div>
    </div>
    <!-- ==================== MANAGE STAFF ==================== -->
    <div class="page" id="manage-staff">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 style="color:#4d2e00;font-weight:700;margin:0;">Manage Staff</h4>
          <small class="text-muted">View and edit staff accounts</small>
        </div>
        <div>
          <button id="refreshStaffBtn" class="btn btn-quick">Refresh</button>
        </div>
      </div>
      <div class="card shadow-sm mb-4">
        <div class="card-body">
          <div class="d-flex justify-content-between align-items-center mb-3">
            <div class="input-group" style="max-width:420px;">
              <input type="text" class="form-control" id="searchStaffInput" placeholder="Search by name, username or email">
              <button id="searchStaffBtn" class="btn btn-secondary">Search</button>
            </div>
            <div>
              <button id="openStaffModalBtn" class="btn btn-success">Add Staff</button>
            </div>
          </div>
          <div class="table-responsive">
            <table class="table table-sm" id="staffTable">
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Username</th>
                  <th>Email</th>
                  <th>Phone</th>
                  <th>Date Created</th>
                  <th>Actions</th>
                </tr>
              </thead>
              <tbody id="staffTableBody">
                <tr><td colspan="6" class="text-center text-muted">Loading staff list...</td></tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    <!-- ==================== FUNDING PROJECTIONS ==================== -->
    <div class="page" id="funding">
      <h3 class="mb-4" style="color: #4d2e00; font-weight: 700;">Funding Projections</h3>
      
      <!-- Projection Summary Cards -->
      <div class="row g-4 mb-4">
        <div class="col-md-3">
          <div class="card shadow-sm border-0" style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);">
            <div class="card-body text-white">
              <h6 class="text-white-50 mb-2">Current Month</h6>
              <h3 class="fw-bold mb-0" id="currentMonthRevenue">₱0.00</h3>
              <small class="text-white-50">Actual Revenue</small>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card shadow-sm border-0" style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%);">
            <div class="card-body text-white">
              <h6 class="text-white-50 mb-2">Next Month</h6>
              <h3 class="fw-bold mb-0" id="projectedNextMonth">₱0.00</h3>
              <small class="text-white-50">Projected</small>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card shadow-sm border-0" style="background: linear-gradient(135deg, #4facfe 0%, #00f2fe 100%);">
            <div class="card-body text-white">
              <h6 class="text-white-50 mb-2">3 Months</h6>
              <h3 class="fw-bold mb-0" id="projected3Months">₱0.00</h3>
              <small class="text-white-50">Projected</small>
            </div>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card shadow-sm border-0" style="background: linear-gradient(135deg, #43e97b 0%, #38f9d7 100%);">
            <div class="card-body text-white">
              <h6 class="text-white-50 mb-2">6 Months</h6>
              <h3 class="fw-bold mb-0" id="projected6Months">₱0.00</h3>
              <small class="text-white-50">Projected</small>
            </div>
          </div>
        </div>
      </div>

      <!-- Growth Metrics -->
      <div class="row g-4 mb-4">
        <div class="col-md-8">
          <div class="card shadow-sm border-0">
            <div class="card-body">
              <h5 class="card-title mb-4">Revenue Trend & Projections</h5>
              <div style="height:350px;">
                <canvas id="projectionChart"></canvas>
              </div>
            </div>
          </div>
        </div>
        <div class="col-md-4">
          <div class="card shadow-sm border-0 h-100">
            <div class="card-body">
              <h5 class="card-title mb-4">Growth Metrics</h5>
              <div class="mb-4">
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <span class="text-muted">Growth Rate</span>
                  <span class="badge" id="growthRateBadge" style="font-size:14px;">0%</span>
                </div>
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <span class="text-muted">Avg Monthly Revenue</span>
                  <strong id="avgMonthlyRevenue">₱0.00</strong>
                </div>
                <div class="d-flex justify-content-between align-items-center mb-2">
                  <span class="text-muted">Data Points</span>
                  <strong id="dataPoints">0 months</strong>
                </div>
                <div class="d-flex justify-content-between align-items-center mb-4">
                  <span class="text-muted">Confidence Level</span>
                  <span class="badge" id="confidenceBadge">Low</span>
                </div>
                <hr>
                <div class="alert alert-info mb-0" style="font-size:13px;">
                  <i class="bi bi-info-circle me-2"></i>
                  <strong>Note:</strong> Projections are based on historical data and growth trends. Actual results may vary.
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Historical Data Table -->
      <div class="card shadow-sm border-0">
        <div class="card-body">
          <h5 class="card-title mb-4">Historical Revenue Data</h5>
          <div class="table-responsive">
            <table class="table table-hover" id="historicalTable">
              <thead style="background:#f8f9fa;">
                <tr>
                  <th>Month</th>
                  <th class="text-end">Orders</th>
                  <th class="text-end">Revenue</th>
                  <th class="text-end">Avg Order Value</th>
                  <th class="text-end">Growth</th>
                </tr>
              </thead>
              <tbody id="historicalTableBody">
                <tr>
                  <td colspan="5" class="text-center text-muted">Loading historical data...</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
    <!-- ==================== PRODUCT PERFORMANCE ==================== -->
    <div class="page" id="performance">
      <h3 class="mb-4" style="color:#4d2e00;font-weight:700;">Most Selling Items</h3>
      <div class="perf-header">
        <select id="performance-category-filter" class="filter-select">
          <option value="All">All Categories</option>
          <option value="Pasta">Pasta</option>
          <option value="Rice Meals">Rice Meals</option>
          <option value="Coffee Beverages">Coffee Beverages</option>
          <option value="NonCoffee">Non-Coffee</option>
          <option value="Pizza">Pizza</option>
          <option value="Cakes">Cakes</option>
          <option value="Sandwiches & Salad">Sandwiches & Salad</option>
          <option value="Lemon Series">Lemon Series</option>
          <option value="Breads">Breads</option>
          <option value="Pie-Cookies-Bar">Pie-Cookies-Bar</option>
          <option value="Milktea">Milktea</option>
          <option value="Fruits & Yogurt">Fruits & Yogurt</option>
        </select>
      </div>
      <div id="products-list"></div>
      <div class="pagination" id="pagination" style="display:none;">
        <span class="page-link disabled">Previous</span>
        <span class="page-link active">1</span>
        <span class="page-link">2</span>
        <span class="page-link">3</span>
        <span class="page-link">4</span>
        <span class="page-link">Next</span>
      </div>
    </div>
    <!-- ==================== AI ORDER ANALYTICS ==================== -->
    <div class="page" id="ai-analytics">
      <div class="ai-analytics-shell">
        <div class="d-flex justify-content-between align-items-center mb-4">
          <div>
            <h4 style="color:#4d2e00;font-weight:700;margin:0;">AI Order Analytics</h4>
            <small class="text-muted">Local insights generated from recent order history.</small>
          </div>
          <button type="button" class="btn btn-outline-secondary" id="aiRefreshBtn">
            <i class="bi bi-arrow-repeat me-1"></i> Run Local AI
          </button>
        </div>
        <div id="aiAnalyticsError" class="alert alert-danger ai-error d-none" role="alert"></div>
        <div id="aiAnalyticsLoading" class="ai-loading-overlay">
          <div class="spinner-border" role="status" aria-hidden="true"></div>
          <p id="aiLoadingMessage" class="loading-headline mb-2">Fetching system-wide order history...</p>
          <p class="loading-subtle mb-0">Hang tight while we analyze every transaction.</p>
        </div>
        <div id="aiAnalyticsContent" class="d-none">
        <div class="row g-3">
          <div class="col-md-3 col-sm-6">
            <div class="ai-summary-card">
              <h5>Total Orders</h5>
              <div class="ai-summary-metric" id="aiSummaryOrders">0</div>
              <div class="ai-summary-delta" id="aiSummaryOrdersDelta">Awaiting data...</div>
            </div>
          </div>
          <div class="col-md-3 col-sm-6">
            <div class="ai-summary-card">
              <h5>Total Revenue</h5>
              <div class="ai-summary-metric" id="aiSummaryRevenue">₱0.00</div>
              <div class="ai-summary-delta" id="aiSummaryRevenueDelta">Awaiting data...</div>
            </div>
          </div>
          <div class="col-md-3 col-sm-6">
            <div class="ai-summary-card">
              <h5>Avg Order Value</h5>
              <div class="ai-summary-metric" id="aiSummaryAov">₱0.00</div>
              <div class="ai-summary-delta" id="aiSummaryAovDelta">Per order</div>
            </div>
          </div>
          <div class="col-md-3 col-sm-6">
            <div class="ai-summary-card">
              <h5>Items Sold</h5>
              <div class="ai-summary-metric" id="aiSummaryItems">0</div>
              <div class="ai-summary-delta" id="aiSummaryItemsDelta">Requires product tracking</div>
            </div>
          </div>
        </div>

        <div class="row g-3 mt-1">
          <div class="col-lg-8">
            <div id="aiTrendChartWrapper">
              <div class="d-flex justify-content-between align-items-center mb-3">
                <h5 class="mb-0" style="color:#4d2e00;font-weight:700;">Revenue Distribution</h5>
                <small class="text-muted" id="aiSummaryWindowLabel">Last 90 days</small>
              </div>
              <canvas id="aiTrendChart" height="300"></canvas>
              <div id="aiTrendEmpty" class="text-center text-muted small mt-3 d-none">No weekly data available for this window.</div>
              <div id="aiRegressionSummary" class="ai-regression-card mt-3">
                <div class="fw-semibold">Regression Forecast</div>
                <div class="small text-muted">Awaiting trend data...</div>
              </div>
            </div>
          </div>
          <div class="col-lg-4">
            <div id="aiPaymentChartWrapper" class="h-100">
              <h5 class="mb-3">Payment Channels</h5>
              <canvas id="aiPaymentChart" height="300"></canvas>
              <div id="aiPaymentEmpty" class="text-center text-muted small mt-3 d-none">No payment data recorded.</div>
            </div>
          </div>
        </div>

        <div class="row g-3 mt-1">
          <div class="col-lg-6">
            <div class="ai-insights-card h-100">
              <div class="d-flex justify-content-between align-items-center mb-2">
                <h5 class="mb-0">AI Highlights</h5>
                <span class="badge badge-muted" id="aiGeneratedAtBadge">—</span>
              </div>
              <ul id="aiInsightsList" class="mb-0"></ul>
            </div>
          </div>
          <div class="col-lg-6">
            <div class="card shadow-sm border-0 h-100">
              <div class="card-body">
                <h5 class="card-title">Product Movers</h5>
                <div class="table-responsive mb-3">
                  <table class="table table-sm ai-table mb-0" id="aiLeadersTable">
                    <thead>
                      <tr>
                        <th>Product</th>
                        <th>Category</th>
                        <th class="text-end">Units</th>
                        <th class="text-end">Growth</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr><td colspan="4" class="text-center text-muted">No movers yet.</td></tr>
                    </tbody>
                  </table>
                </div>
                <h6 class="fw-bold">Watchlist</h6>
                <div class="table-responsive">
                  <table class="table table-sm ai-table mb-0" id="aiLaggersTable">
                    <thead>
                      <tr>
                        <th>Product</th>
                        <th>Category</th>
                        <th class="text-end">Units</th>
                        <th class="text-end">Growth</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr><td colspan="4" class="text-center text-muted">Nothing flagged right now.</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        </div>

        <div class="row g-3 mt-1">
          <div class="col-lg-6">
            <div class="card shadow-sm border-0 h-100">
              <div class="card-body">
                <h5 class="card-title">Category Breakdown</h5>
                <div class="table-responsive">
                  <table class="table table-sm ai-table mb-0" id="aiCategoriesTable">
                    <thead>
                      <tr>
                        <th>Category</th>
                        <th class="text-end">Units</th>
                        <th class="text-end">Share</th>
                      </tr>
                    </thead>
                    <tbody>
                      <tr><td colspan="3" class="text-center text-muted">No category data yet.</td></tr>
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
          <div class="col-lg-6">
            <div class="card shadow-sm border-0 h-100">
              <div class="card-body">
                <h5 class="card-title">Demand Peaks</h5>
                <ul class="list-unstyled mb-0" id="aiPeaksList">
                  <li class="text-muted">Waiting for recent orders...</li>
                </ul>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    </div>
    <!-- ==================== INVENTORY ==================== -->
    <div class="page" id="inventory">
      <h3 class="mb-4" style="display:none;">
      <h4 class="mb-4">Inventory</h4>
      <div class="inventory-header">
        <select id="category-filter" class="filter-select">
          <option value="">All Categories</option>
          <option value="Pasta">Pasta</option>
          <option value="Rice Meals">Rice Meals</option>
          <option value="Coffee Beverages">Coffee Beverages</option>
          <option value="NonCoffee">Non-Coffee</option>
          <option value="Pizza">Pizza</option>
          <option value="Cakes">Cakes</option>
          <option value="Sandwiches & Salad">Sandwiches & Salad</option>
          <option value="Lemon Series">Lemon Series</option>
          <option value="Breads">Breads</option>
          <option value="Pie-Cookies-Bar">Pie-Cookies-Bar</option>
          <option value="Milktea">Milktea</option>
          <option value="Fruits & Yogurt">Fruits & Yogurt</option>
        </select>
        <button class="add-product-btn" data-bs-toggle="modal" data-bs-target="#productModal">
          Add Product
        </button>
      </div>      
      <!-- Wrapper div for horizontal scrolling on mobile -->
      <div class="table-responsive">
      <div class="inventory-table">
        <table id="inventory-table">
          <thead>
            <tr>
              <th>ID</th>
              <th>Image</th>
              <th>Product Name</th>
              <th>Category</th>
              <th>Price</th>
              <th>Stock</th>
              <th>Low Stock Alert</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody></tbody>
        </table>
      </div>
      </div>
    </div>
    <!-- ==================== SYSTEM HISTORY ==================== -->
    <div class="page" id="history">
      <div class="d-flex flex-column flex-lg-row flex-wrap justify-content-between align-items-lg-center mb-4 gap-3">
        <div>
          <h4 style="color:#4d2e00;font-weight:700;margin:0;">System History</h4>
          <small class="text-muted">Chronological log of inventory actions, customer activity, and staff confirmations.</small>
        </div>
        <div class="history-controls d-flex flex-wrap align-items-center gap-2">
          <div class="input-group" style="max-width:280px;">
            <input type="text" class="form-control" id="historySearchInput" placeholder="Search activity or users">
            <button type="button" class="btn btn-secondary" id="historySearchBtn">Search</button>
          </div>
          <select id="historyTypeFilter" class="form-select" style="min-width:160px;">
            <option value="">Choose category</option>
            <option value="inventory">Inventory updates</option>
            <option value="orders">Customer orders</option>
            <option value="feedback">Customer feedback</option>
            <option value="reservations">Staff confirmations</option>
          </select>
          <input type="date" id="historyDateFilter" class="form-control" style="max-width:160px;">
          <button type="button" class="btn btn-outline-secondary" id="refreshHistory"><i class="bi bi-arrow-repeat me-1"></i> Refresh</button>
          <button type="button" class="btn btn-secondary" id="exportHistory"><i class="bi bi-download me-1"></i> Export</button>
        </div>
      </div>
      <span class="history-updated" id="historyUpdated">History not loaded yet.</span>
      <div class="history-table mt-3">
        <div id="historyLoading" class="history-empty d-none"><span class="history-spinner"></span> Loading recent activity...</div>
        <div id="historyEmpty" class="history-empty">No history recorded yet. Activity will appear here once orders, feedback, or staff updates occur.</div>
        <table class="table align-middle mb-0 d-none" id="historyTable">
          <thead class="history-head">
            <tr>
              <th scope="col" style="width:160px;">Category</th>
              <th scope="col">Details</th>
              <th scope="col" style="width:180px;">User</th>
              <th scope="col" style="width:190px;">Timestamp</th>
            </tr>
          </thead>
          <tbody id="historyTableBody"></tbody>
        </table>
      </div>
    </div>
  </div>
  <!-- ADD / EDIT PRODUCT MODAL (LOW STOCK AUTO COMPUTE, CHANGES 11-16-25) -->
  <div class="modal fade" id="productModal" tabindex="-1">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="modalTitle">Add New Product</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
        </div>
        <div class="modal-body">
          <form id="productForm">
            <input type="hidden" name="Product_ID" id="productID">
            <div class="mb-3">
              <label class="form-label">Product Image</label>
              <input type="file" class="form-control" name="Image" accept="image/*">
              <div id="currentImage" class="mt-2" style="display:none;">
                <img id="imagePreview" src="" alt="Current Image" style="max-width:100px; max-height:100px;">
              </div>
            </div>
            <div class="mb-3">
              <label class="form-label">Product Name</label>
              <input type="text" class="form-control" name="Product_Name" required>
            </div>
            <div class="mb-3">
              <label class="form-label">Description</label>
              <textarea class="form-control" name="Description" rows="3"></textarea>
            </div>
            <div class="row">
              <div class="col-md-6 mb-3">
                <label class="form-label">Category</label>
                <select class="form-select" name="Category" required>
                  <option value="">Select Category</option>
                  <option value="Pasta">Pasta</option>
                  <option value="Rice Meals">Rice Meals</option>
                  <option value="Coffee Beverages">Coffee Beverages</option>
                  <option value="NonCoffee">Non-Coffee</option>
                  <option value="Pizza">Pizza</option>
                  <option value="Cakes">Cakes</option>
                  <option value="Sandwiches & Salad">Sandwiches & Salad</option>
                  <option value="Lemon Series">Lemon Series</option>
                  <option value="Breads">Breads</option>
                  <option value="Pie-Cookies-Bar">Pie-Cookies-Bar</option>
                  <option value="Milktea">Milktea</option>
                  <option value="Fruits & Yogurt">Fruits & Yogurt</option>
                </select>
              </div>
              <div class="col-md-6 mb-3">
                <label class="form-label">Sub Category</label>
                <select class="form-select" name="Sub_category">
                  <option value="">None</option>
                  <option value="Hot">Hot</option>
                  <option value="Iced">Iced</option>
                </select>
              </div>
            </div>
            <div class="row">
              <div class="col-md-6 mb-3">
                <label class="form-label">Price (₱)</label>
                <input type="number" step="0.01" class="form-control" name="Price" required>
              </div>
              <div class="col-md-6 mb-3">
                <label class="form-label">Stock Quantity</label>
                <input type="number" class="form-control" name="Stock_Quantity" min="0" required>
              </div>
            </div>
          </form>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
          <button type="button" class="btn btn-primary" id="saveProductBtn">Save Product</button>
        </div>
      </div>
    </div>
  </div>
  <!-- Announcement Modal -->
  <div class="modal fade" id="announcementModal" tabindex="-1" aria-labelledby="announcementModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg">
      <div class="modal-content">
        <form id="announcementForm">
          <div class="modal-header">
            <h5 class="modal-title" id="announcementModalLabel">Create Announcement</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
          </div>
          <div class="modal-body">
            <div class="mb-3">
              <label for="announcementMessage" class="form-label">Message</label>
              <textarea class="form-control" id="announcementMessage" name="message" rows="4" maxlength="600" placeholder="e.g. Due to high demand some products may be delayed." required></textarea>
              <small class="text-muted">Customers will see this notice on their dashboard.</small>
            </div>
            <div class="row g-3">
              <div class="col-md-6">
                <label for="announcementAudience" class="form-label">Audience</label>
                <select class="form-select" id="announcementAudience" name="audience">
                  <option value="customer" selected>Customers</option>
                  <option value="all">Everyone</option>
                </select>
              </div>
              <div class="col-md-6">
                <label for="announcementExpiresAt" class="form-label">Expires (optional)</label>
                <input type="datetime-local" class="form-control" id="announcementExpiresAt" name="expires_at">
              </div>
            </div>
          </div>
          <div class="modal-footer">
            <button type="button" class="btn btn-outline-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="submit" class="btn btn-brown" id="announcementSubmitBtn">
              <i class="bi bi-megaphone-fill me-1"></i> Post Announcement
            </button>
          </div>
        </form>
      </div>
    </div>
  </div>
  <!-- Scripts -->
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>
  <script>

     // --- Generate Report Button Logic ---
        document.getElementById('generateReportBtn')?.addEventListener('click', async function() {
          if (!confirm('Generate and download the current dashboard report as PDF?')) return;
          try {
            const currentUrl = new URL(window.location.href);
            currentUrl.searchParams.set('action', 'generate_dashboard_report');
            currentUrl.searchParams.delete('page');
            const reportUrl = currentUrl.pathname + '?' + currentUrl.searchParams.toString();

            const response = await fetch(reportUrl, { method: 'GET', credentials: 'same-origin' });
            const contentType = (response.headers.get('Content-Type') || '').toLowerCase();

            if (!response.ok || !contentType.includes('application/pdf')) {
              const errorText = (await response.text()).trim();
              throw new Error(errorText || 'Failed to generate report.');
            }

            const blob = await response.blob();
            const disposition = response.headers.get('Content-Disposition') || '';
            let filename = 'dashboard_report.pdf';
            const match = disposition.match(/filename="?([^";]+)"?/);
            if (match) {
              filename = match[1];
            }

            const blobUrl = URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = blobUrl;
            anchor.download = filename;
            document.body.appendChild(anchor);
            anchor.click();
            anchor.remove();
            setTimeout(() => URL.revokeObjectURL(blobUrl), 1000);

            if (typeof showSuccessMessage === 'function') {
              showSuccessMessage('Dashboard report downloaded.');
            }
          } catch (error) {
            console.error('Report download failed:', error);
            alert(error.message || 'Failed to generate report.');
          }
        });

    const aiRefreshBtn = document.getElementById('aiRefreshBtn');
    const aiElements = {
      loading: document.getElementById('aiAnalyticsLoading'),
      loadingMessage: document.getElementById('aiLoadingMessage'),
      content: document.getElementById('aiAnalyticsContent'),
      error: document.getElementById('aiAnalyticsError'),
      orders: document.getElementById('aiSummaryOrders'),
      ordersDelta: document.getElementById('aiSummaryOrdersDelta'),
      revenue: document.getElementById('aiSummaryRevenue'),
      revenueDelta: document.getElementById('aiSummaryRevenueDelta'),
      aov: document.getElementById('aiSummaryAov'),
      aovDelta: document.getElementById('aiSummaryAovDelta'),
      items: document.getElementById('aiSummaryItems'),
      itemsDelta: document.getElementById('aiSummaryItemsDelta'),
      windowLabel: document.getElementById('aiSummaryWindowLabel'),
      generatedAt: document.getElementById('aiGeneratedAtBadge'),
      insightsList: document.getElementById('aiInsightsList'),
      peaksList: document.getElementById('aiPeaksList'),
      regressionCard: document.getElementById('aiRegressionSummary'),
      predictionFooter: document.getElementById('aiPredictionFooter'),
    };

    const aiTables = {
      leaders: document.querySelector('#aiLeadersTable tbody'),
      laggers: document.querySelector('#aiLaggersTable tbody'),
      categories: document.querySelector('#aiCategoriesTable tbody'),
    };

    const aiChartState = {
      trendCanvas: document.getElementById('aiTrendChart'),
      paymentCanvas: document.getElementById('aiPaymentChart'),
      trendEmpty: document.getElementById('aiTrendEmpty'),
      paymentEmpty: document.getElementById('aiPaymentEmpty'),
      trendChart: null,
      paymentChart: null,
      trendCtx: null,
      paymentCtx: null,
    };

    if (aiChartState.trendCanvas) {
      aiChartState.trendCtx = aiChartState.trendCanvas.getContext('2d');
    }
    if (aiChartState.paymentCanvas) {
      aiChartState.paymentCtx = aiChartState.paymentCanvas.getContext('2d');
    }

    const aiState = {
      cache: null,
      hasLoaded: false,
      isLoading: false,
    };

    function aiFormatCurrency(value) {
      const num = Number(value || 0);
      return '₱' + num.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    function aiFormatCurrencyShort(value) {
      const num = Number(value || 0);
      const k = Math.round(num / 100) / 10; // one decimal place (e.g. 285.0 -> 285.0k)
      return '₱' + k.toLocaleString() + 'k';
    }

    function aiFormatNumber(value) {
      const num = Number(value || 0);
      return num.toLocaleString('en-US');
    }

    function aiFormatPercent(value) {
      if (value === null || typeof value === 'undefined' || Number.isNaN(Number(value))) {
        return '—';
      }
      const numeric = Number(value);
      const sign = numeric > 0 ? '+' : '';
      return sign + numeric.toFixed(1) + '%';
    }

    function aiEscapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    function setAiState(state, message) {
      if (!aiElements.loading || !aiElements.content || !aiElements.error) return;
      if (state === 'loading') {
        aiElements.loading.classList.remove('d-none');
        aiElements.content.classList.add('d-none');
        aiElements.error.classList.add('d-none');
        if (aiElements.loadingMessage) {
          aiElements.loadingMessage.textContent = message || 'Fetching system-wide order history...';
        }
        if (aiElements.regressionCard) {
          aiElements.regressionCard.classList.remove('regression-up', 'regression-down');
          aiElements.regressionCard.innerHTML = '<div class="fw-semibold">Regression Forecast</div><div class="small text-muted">Crunching trend data...</div>';
        }
        if (aiElements.predictionFooter) {
          aiElements.predictionFooter.textContent = 'Analyzing full order history for prediction...';
        }
      } else if (state === 'ready') {
        aiElements.loading.classList.add('d-none');
        aiElements.content.classList.remove('d-none');
        aiElements.error.classList.add('d-none');
      } else if (state === 'error') {
        aiElements.loading.classList.add('d-none');
        aiElements.content.classList.add('d-none');
        aiElements.error.classList.remove('d-none');
        aiElements.error.textContent = message || 'Unable to load analytics.';
        if (aiElements.predictionFooter) {
          aiElements.predictionFooter.textContent = 'Prediction unavailable because analytics failed to load.';
        }
      }
    }

    function setAiButtonBusy(label = 'Analyzing...') {
      if (!aiRefreshBtn) return;
      aiRefreshBtn.disabled = true;
      aiRefreshBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>' + label;
    }

    function setAiButtonReady(hasLoaded) {
      if (!aiRefreshBtn) return;
      aiRefreshBtn.disabled = false;
      aiRefreshBtn.innerHTML = hasLoaded
        ? '<i class="bi bi-arrow-repeat me-1"></i> Run Analysis Again'
        : '<i class="bi bi-arrow-repeat me-1"></i> Run Local AI';
    }

    function updateDeltaElement(element, delta) {
      if (!element) return;
      element.classList.remove('positive', 'negative');
      if (delta === null || typeof delta === 'undefined' || Number.isNaN(Number(delta))) {
        element.textContent = 'No comparison';
        return;
      }
      const numeric = Number(delta);
      if (numeric > 0.1) {
        element.textContent = '+' + numeric.toFixed(1) + '% vs prev';
        element.classList.add('positive');
      } else if (numeric < -0.1) {
        element.textContent = numeric.toFixed(1) + '% vs prev';
        element.classList.add('negative');
      } else {
        element.textContent = 'Flat vs prev';
      }
    }

    function renderAiProductTable(tbody, rows, emptyText) {
      if (!tbody) return;
      if (!Array.isArray(rows) || rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="4" class="text-center text-muted">' + aiEscapeHtml(emptyText) + '</td></tr>';
        return;
      }
      const html = rows.map(row => {
        return '<tr>'
          + '<td>' + aiEscapeHtml(row.name ?? 'Unnamed') + '</td>'
          + '<td>' + aiEscapeHtml(row.category ?? '—') + '</td>'
          + '<td class="text-end">' + aiFormatNumber(row.quantity) + '</td>'
          + '<td class="text-end">' + aiFormatPercent(row.growth_pct) + '</td>'
          + '</tr>';
      }).join('');
      tbody.innerHTML = html;
    }

    function renderAiCategories(rows) {
      const tbody = aiTables.categories;
      if (!tbody) return;
      if (!Array.isArray(rows) || rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="3" class="text-center text-muted">No category data yet.</td></tr>';
        return;
      }
      const html = rows.map(row => {
        const share = Number(row.share ?? 0).toFixed(1) + '%';
        return '<tr>'
          + '<td>' + aiEscapeHtml(row.category ?? 'Uncategorized') + '</td>'
          + '<td class="text-end">' + aiFormatNumber(row.quantity) + '</td>'
          + '<td class="text-end">' + share + '</td>'
          + '</tr>';
      }).join('');
      tbody.innerHTML = html;
    }

    function renderAiPeaksList(segments) {
      const list = aiElements.peaksList;
      if (!list) return;
      const items = [];
      if (segments && segments.best_day) {
        const bestDay = segments.best_day;
        items.push('<li><strong>Top day:</strong> ' + aiEscapeHtml(bestDay.label ?? '—') + ' • ' + aiFormatNumber(bestDay.orders) + ' orders (' + aiFormatCurrency(bestDay.revenue) + ')</li>');
      }
      if (segments && segments.best_hour && typeof segments.best_hour.hour !== 'undefined') {
        const hourValue = String(Number(segments.best_hour.hour) || 0).padStart(2, '0') + ':00';
        items.push('<li><strong>Peak hour:</strong> ' + hourValue + ' • ' + aiFormatNumber(segments.best_hour.orders) + ' orders</li>');
      }
      if (segments && Array.isArray(segments.payment_mix) && segments.payment_mix.length) {
        const payment = segments.payment_mix[0];
        items.push('<li><strong>Preferred payment:</strong> ' + aiEscapeHtml(payment.method ?? 'Unspecified') + ' (' + Number(payment.share ?? 0).toFixed(1) + '% of orders)</li>');
      }
      if (!items.length) {
        list.innerHTML = '<li class="text-muted">No demand peaks detected yet.</li>';
      } else {
        list.innerHTML = items.join('');
      }
    }

    function updateAiTrendChart(trendData) {
      if (!aiChartState.trendCtx || typeof Chart === 'undefined') return;
      if (aiChartState.trendChart) {
        aiChartState.trendChart.destroy();
        aiChartState.trendChart = null;
      }
      if (!Array.isArray(trendData) || trendData.length === 0) {
        if (aiChartState.trendEmpty) aiChartState.trendEmpty.classList.remove('d-none');
        return;
      }
      if (aiChartState.trendEmpty) aiChartState.trendEmpty.classList.add('d-none');
      
      const labels = trendData.map(item => item.label || '');
      const revenue = trendData.map(item => Number(item.revenue || 0));
      const orders = trendData.map(item => Number(item.orders || 0));
      
      const hasData = revenue.some(v => v > 0) || orders.some(v => v > 0);
      if (!hasData) {
        if (aiChartState.trendEmpty) {
          aiChartState.trendEmpty.textContent = 'Not enough revenue data to display.';
          aiChartState.trendEmpty.classList.remove('d-none');
        }
        return;
      }
      
      const totalRevenue = revenue.reduce((sum, val) => sum + val, 0);
      const palette = ['#6B4F3F', '#c1976b', '#8d6e63', '#b08968', '#cc9d76', '#deb887', '#c86b4f', '#a67c52', '#d4a574', '#e8c9a0'];
      const colors = labels.map((_, index) => palette[index % palette.length]);
      
      aiChartState.trendChart = new Chart(aiChartState.trendCtx, {
        type: 'pie',
        data: {
          labels,
          datasets: [
            {
              label: 'Revenue Distribution',
              data: revenue,
              backgroundColor: colors,
              borderColor: '#fff',
              borderWidth: 2,
              hoverOffset: 8
            }
          ],
        },
        options: {
          animation: {
            animateRotate: true,
            animateScale: true,
            duration: 1200,
            easing: 'easeInOutQuart'
          },
          responsive: true,
          maintainAspectRatio: false,
          layout: {
            padding: {
              top: 10,
              bottom: 10
            }
          },
          plugins: {
            legend: { 
              display: true, 
              position: 'right',
              labels: {
                padding: 10,
                font: {
                  size: 11
                }
              }
            },
            tooltip: {
              callbacks: {
                label(context) {
                  const value = context.parsed || 0;
                  const percentage = totalRevenue > 0 ? ((value / totalRevenue) * 100).toFixed(1) : 0;
                  return `${context.label}: ${aiFormatCurrency(value)} (${percentage}%)`;
                }
              }
            }
          }
        }
      });
    }

    // Basic linear regression over sequential revenue points to forecast the next period.
    function computeLinearRegression(points) {
      const n = points.length;
      if (n < 2) {
        return null;
      }

      let sumX = 0;
      let sumY = 0;
      let sumXY = 0;
      let sumXX = 0;

      points.forEach(({ x, y }) => {
        sumX += x;
        sumY += y;
        sumXY += x * y;
        sumXX += x * x;
      });

      const denominator = (n * sumXX) - (sumX * sumX);
      const safeDenominator = Math.abs(denominator) < 1e-9 ? 1e-9 : denominator;
      const slope = ((n * sumXY) - (sumX * sumY)) / safeDenominator;
      const intercept = (sumY - (slope * sumX)) / n;

      const meanY = sumY / n;
      let ssTot = 0;
      let ssRes = 0;
      points.forEach(({ x, y }) => {
        const predicted = (slope * x) + intercept;
        ssTot += Math.pow(y - meanY, 2);
        ssRes += Math.pow(y - predicted, 2);
      });

      const rSquared = ssTot <= 1e-9 ? 0 : Math.max(0, 1 - (ssRes / ssTot));
      return { slope, intercept, rSquared };
    }

    function updateAiRegression(trendData) {
      const container = aiElements.regressionCard;
      if (!container) return;

      const points = Array.isArray(trendData)
        ? trendData.map((item, index) => ({
            x: index,
            y: Number(item.revenue || 0),
          })).filter(point => Number.isFinite(point.y))
        : [];

      if (points.length < 2 || points.every(point => point.y <= 0)) {
        container.classList.remove('regression-up', 'regression-down');
        container.innerHTML = '<div class="fw-semibold">Regression Forecast</div><div class="small text-muted">Not enough revenue data yet.</div>';
        if (aiElements.predictionFooter) {
          aiElements.predictionFooter.textContent = 'No prediction yet. Keep recording orders to unlock forward-looking estimates.';
        }
        return;
      }

      const stats = computeLinearRegression(points);
      if (!stats) {
        container.classList.remove('regression-up', 'regression-down');
        container.innerHTML = '<div class="fw-semibold">Regression Forecast</div><div class="small text-muted">Unable to compute trend.</div>';
        if (aiElements.predictionFooter) {
          aiElements.predictionFooter.textContent = 'Prediction unavailable. Try reloading analytics once more.';
        }
        return;
      }

      const nextX = points.length;
      const forecast = Math.max(0, (stats.slope * nextX) + stats.intercept);
      const rSquaredPct = Math.min(1, Math.max(0, stats.rSquared)) * 100;

      container.classList.remove('regression-up', 'regression-down');
      let trendDescriptor = 'flat';
      if (stats.slope > 0.0001) {
        container.classList.add('regression-up');
        trendDescriptor = 'upward';
      } else if (stats.slope < -0.0001) {
        container.classList.add('regression-down');
        trendDescriptor = 'downward';
      }

      const confidenceLabel = rSquaredPct.toFixed(1) + '%';
      container.innerHTML = '<div class="fw-semibold">Regression Forecast (' + trendDescriptor + ' trend)</div>'
        + '<div class="small text-muted">Next period revenue: <strong>' + aiFormatCurrency(forecast) + '</strong></div>'
        + '<div class="small text-muted">Model confidence (R²): ' + confidenceLabel + '</div>';

      if (aiElements.predictionFooter) {
        const windowLabel = aiElements.windowLabel ? aiElements.windowLabel.textContent || '' : '';
        aiElements.predictionFooter.textContent = 'Projected revenue for the next period after ' + (windowLabel || 'the current window')
          + ' is ' + aiFormatCurrency(forecast) + ' with a ' + confidenceLabel + ' fit to recent performance (' + trendDescriptor + ' trend).';
      }
    }

    function updateAiPaymentChart(mixData) {
      if (!aiChartState.paymentCtx || typeof Chart === 'undefined') return;
      if (aiChartState.paymentChart) {
        aiChartState.paymentChart.destroy();
        aiChartState.paymentChart = null;
      }

      const sanitizedMix = Array.isArray(mixData)
        ? mixData.filter(item => Number(item.orders || 0) > 0)
        : [];

      if (!sanitizedMix.length) {
        if (aiChartState.paymentEmpty) {
          aiChartState.paymentEmpty.textContent = 'No payment breakdown recorded this window.';
          aiChartState.paymentEmpty.classList.remove('d-none');
        }
        return;
      }

      const labels = sanitizedMix.map(item => item.method || 'Unspecified');
      const orders = sanitizedMix.map(item => Number(item.orders || 0));
      const totalOrders = orders.reduce((sum, value) => sum + (Number.isFinite(value) ? value : 0), 0);

      if (!Number.isFinite(totalOrders) || totalOrders <= 0) {
        if (aiChartState.paymentEmpty) {
          aiChartState.paymentEmpty.textContent = 'No payment breakdown recorded this window.';
          aiChartState.paymentEmpty.classList.remove('d-none');
        }
        return;
      }

      if (aiChartState.paymentEmpty) aiChartState.paymentEmpty.classList.add('d-none');

      aiChartState.paymentChart = new Chart(aiChartState.paymentCtx, {
        type: 'polarArea',
        data: {
          labels,
          datasets: [{
            label: 'Payment Methods',
            data: orders,
            backgroundColor: [
              'rgba(107, 79, 63, 0.6)',
              'rgba(193, 151, 107, 0.6)',
              'rgba(141, 110, 99, 0.6)',
              'rgba(176, 137, 104, 0.6)',
              'rgba(204, 157, 118, 0.6)',
              'rgba(222, 184, 135, 0.6)',
              'rgba(200, 107, 79, 0.6)'
            ],
            borderColor: [
              '#6B4F3F',
              '#c1976b',
              '#8d6e63',
              '#b08968',
              '#cc9d76',
              '#deb887',
              '#c86b4f'
            ],
            borderWidth: 2
          }]
        },
        options: {
          animation: {
            animateRotate: true,
            animateScale: true,
            duration: 1000,
            easing: 'easeOutQuart'
          },
          responsive: true,
          maintainAspectRatio: false,
          scales: {
            r: {
              beginAtZero: true,
              ticks: {
                display: true,
                backdropColor: 'transparent',
                callback(value) { return aiFormatNumber(value); }
              },
              grid: {
                color: 'rgba(0, 0, 0, 0.1)'
              },
              animate: true
            }
          },
          plugins: {
            legend: { 
              display: true,
              position: 'bottom',
              labels: {
                padding: 8,
                font: {
                  size: 11
                }
              }
            },
            tooltip: {
              callbacks: {
                label(context) {
                  const value = orders[context.dataIndex] || 0;
                  const share = totalOrders > 0 ? ((value / totalOrders) * 100).toFixed(1) : 0;
                  return `${context.label}: ${aiFormatNumber(value)} orders (${share}%)`;
                }
              }
            }
          }
        }
      });
    }

    function renderAiAnalytics(data) {
      if (!data || typeof data !== 'object') {
        setAiState('error', 'Analytics data unavailable.');
        return;
      }

      const summary = data.summary || {};
      if (aiElements.orders) aiElements.orders.textContent = aiFormatNumber(summary.order_count || 0);
      updateDeltaElement(aiElements.ordersDelta, summary.growth_orders_pct);

      if (aiElements.revenue) aiElements.revenue.textContent = aiFormatCurrencyShort(summary.revenue || 0);
      updateDeltaElement(aiElements.revenueDelta, summary.growth_revenue_pct);

      if (aiElements.aov) aiElements.aov.textContent = aiFormatCurrency(summary.avg_order_value || 0);
      if (aiElements.aovDelta) {
        aiElements.aovDelta.classList.remove('positive', 'negative');
        aiElements.aovDelta.textContent = (summary.order_count || 0) > 0 ? 'Average per order' : 'No orders in window';
      }

      if (aiElements.items) {
        if (summary.has_item_data) {
          aiElements.items.textContent = aiFormatNumber(summary.total_items || 0);
          updateDeltaElement(aiElements.itemsDelta, summary.growth_items_pct);
        } else {
          aiElements.items.textContent = '—';
          if (aiElements.itemsDelta) {
            aiElements.itemsDelta.classList.remove('positive', 'negative');
            aiElements.itemsDelta.textContent = 'Enable product quantities to view.';
          }
        }
      }

      if (aiElements.windowLabel) {
        const start = summary.start_date_display || '';
        const end = summary.end_date_display || '';
        aiElements.windowLabel.textContent = (start && end)
          ? `${start} – ${end}`
          : `${summary.window_days || 90}-day window`;
      }

      if (aiElements.generatedAt) {
        const stamp = data.generated_at;
        if (stamp) {
          const generated = new Date(stamp.replace(' ', 'T'));
          aiElements.generatedAt.textContent = 'Updated ' + generated.toLocaleString('en-US', {
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit'
          });
        } else {
          aiElements.generatedAt.textContent = '—';
        }
      }

      if (aiElements.insightsList) {
        const insights = Array.isArray(data.insights) ? data.insights : [];
        if (!insights.length) {
          aiElements.insightsList.innerHTML = '<li class="text-muted">No insights generated.</li>';
        } else {
          aiElements.insightsList.innerHTML = insights.map(item => '<li>' + aiEscapeHtml(item) + '</li>').join('');
        }
      }

      renderAiProductTable(aiTables.leaders, data.leaders, 'No movers yet.');
      renderAiProductTable(aiTables.laggers, data.laggers, 'Nothing flagged right now.');

      const segments = data.segments && typeof data.segments === 'object' ? data.segments : {};
      const categoryBreakdown = Array.isArray(segments.category_breakdown) ? segments.category_breakdown : [];
      renderAiCategories(categoryBreakdown);
      renderAiPeaksList(segments);

      const trendData = Array.isArray(data.trend) ? [...data.trend] : [];
      trendData.sort((a, b) => {
        const startA = a && a.start_date ? new Date(a.start_date) : null;
        const startB = b && b.start_date ? new Date(b.start_date) : null;
        if (startA && startB) {
          return startA - startB;
        }
        return 0;
      });
      updateAiTrendChart(trendData);
      updateAiRegression(trendData);
      const paymentMix = Array.isArray(segments.payment_mix) ? segments.payment_mix : [];
      updateAiPaymentChart(paymentMix);

      setAiState('ready');
    }

    async function loadAiAnalytics(force = false) {
      if (aiState.isLoading) return;

      if (!force && aiState.cache) {
        renderAiAnalytics(aiState.cache);
        setAiButtonReady(aiState.hasLoaded);
        return;
      }

      if (!aiElements.loading || !aiElements.content || !aiElements.error) return;

      aiState.isLoading = true;
      setAiButtonBusy('Analyzing...');
      setAiState('loading', 'Fetching system-wide order history...');

      try {
        await new Promise(resolve => setTimeout(resolve, 3000));

        const response = await fetch('?action=ai-order-analytics');
        const text = await response.text();
        let result;
        try {
          result = JSON.parse(text);
        } catch (parseError) {
          console.error('AI analytics parse error:', text);
          throw new Error('Server returned invalid analytics response.');
        }

        if (!response.ok || result.status !== 'success') {
          throw new Error(result.message || 'Unable to generate analytics.');
        }

        const data = result.data || {};
        aiState.cache = data;
        aiState.hasLoaded = true;

        renderAiAnalytics(data);
        setAiButtonReady(true);
      } catch (error) {
        console.error('AI analytics error:', error);
        setAiState('error', error.message || 'Unable to load analytics.');
        setAiButtonReady(aiState.hasLoaded);
      } finally {
        aiState.isLoading = false;
      }
    }

    if (aiRefreshBtn) {
      setAiButtonReady(aiState.hasLoaded);
      aiRefreshBtn.addEventListener('click', () => {
        loadAiAnalytics(true);
      });
    }

    /* ---------- System History ---------- */
    const historyElements = {
      table: document.getElementById('historyTable'),
      tbody: document.getElementById('historyTableBody'),
      empty: document.getElementById('historyEmpty'),
      loading: document.getElementById('historyLoading'),
      updated: document.getElementById('historyUpdated'),
      type: document.getElementById('historyTypeFilter'),
      date: document.getElementById('historyDateFilter'),
      search: document.getElementById('historySearchInput'),
      searchBtn: document.getElementById('historySearchBtn'),
      refresh: document.getElementById('refreshHistory'),
      exportBtn: document.getElementById('exportHistory'),
    };

    const historyState = {
      isLoading: false,
      records: [],
      filters: {
        type: '',
        date: '',
        search: '',
      },
    };

    function escapeHistoryText(value) {
      const text = String(value ?? '');
      const map = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
      return text.replace(/[&<>"']/g, char => map[char] || char);
    }

    function historyIconFor(category) {
      switch ((category || '').toLowerCase()) {
        case 'inventory':
          return 'bi-box-seam';
        case 'orders':
          return 'bi-bag-check';
        case 'feedback':
          return 'bi-chat-dots';
        case 'reservations':
          return 'bi-calendar-check';
        default:
          return 'bi-clock-history';
      }
    }

    function historyPillFor(entry) {
      const action = (entry.action_type || '').toLowerCase();
      const category = (entry.event_category || '').toLowerCase();
      const label = entry.action_label || entry.event_summary || 'Update';

      if (category === 'inventory') {
        if (action === 'add') return { className: 'history-pill history-pill-add', label };
        if (action === 'remove') return { className: 'history-pill history-pill-remove', label };
        if (action === 'update') return { className: 'history-pill history-pill-update', label };
        return { className: 'history-pill history-pill-neutral', label };
      }

      if (category === 'orders') {
        if (action === 'completed' || action === 'confirmed') return { className: 'history-pill history-pill-add', label };
        if (action === 'cancelled') return { className: 'history-pill history-pill-remove', label };
        return { className: 'history-pill history-pill-neutral', label };
      }

      if (category === 'reservations') {
        if (action === 'confirmed' || action === 'completed') return { className: 'history-pill history-pill-add', label };
        if (action === 'cancelled') return { className: 'history-pill history-pill-remove', label };
        return { className: 'history-pill history-pill-neutral', label };
      }

      return { className: 'history-pill history-pill-neutral', label };
    }

    function historyFormatCurrency(value) {
      const amount = Number(value);
      if (!Number.isFinite(amount)) return '';
      return '₱' + amount.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    function setHistoryLoading(isLoading) {
      historyState.isLoading = isLoading;
      if (historyElements.loading) historyElements.loading.classList.toggle('d-none', !isLoading);
      if (historyElements.refresh) historyElements.refresh.disabled = isLoading;
      if (historyElements.searchBtn) historyElements.searchBtn.disabled = isLoading;
    }

    function updateHistoryUpdatedLabel() {
      if (!historyElements.updated) return;
      if (!historyState.records.length) {
        historyElements.updated.textContent = 'No activity recorded yet.';
        return;
      }
      const now = new Date();
      historyElements.updated.textContent = 'Last updated ' + now.toLocaleString('en-US', {
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
      });
    }

    function renderHistory(records) {
      if (!historyElements.tbody) return;

      if (!Array.isArray(records) || records.length === 0) {
        if (historyElements.table) historyElements.table.classList.add('d-none');
        if (historyElements.empty) historyElements.empty.classList.remove('d-none');
        return;
      }

      if (historyElements.table) historyElements.table.classList.remove('d-none');
      if (historyElements.empty) historyElements.empty.classList.add('d-none');

      const rows = records.map(entry => {
        const category = entry.event_category || 'Activity';
        const icon = historyIconFor(category);
        const pill = historyPillFor(entry);
        const headline = escapeHistoryText(entry.headline || entry.event_summary || 'Activity recorded');
        const notesValue = String(entry.notes || '').trim();
        const noteSegments = notesValue
          ? notesValue.split('|').map(part => part.trim()).filter(Boolean)
          : [];
        const performed = escapeHistoryText(entry.performed_by ?? entry.performed_by_masked ?? 'Hidden');
        const role = escapeHistoryText(entry.user_role || '');
        const timestampSource = String(entry.log_date_formatted || entry.log_date || '').trim();
        const metaParts = [];

        if (entry.event_category === 'Inventory') {
          if (typeof entry.quantity_changed === 'number' && entry.quantity_changed !== 0) {
            metaParts.push('Change: ' + (entry.change_label ?? entry.quantity_changed));
          }
          if (entry.current_stock !== null && entry.current_stock !== undefined && entry.current_stock !== '') {
            metaParts.push('Stock: ' + entry.current_stock);
          }
          if (entry.product_name) {
            metaParts.push('Product: ' + entry.product_name);
          }
        } else if (entry.event_category === 'Orders') {
          if (entry.order_amount !== undefined && entry.order_amount !== null) {
            metaParts.push('Amount: ' + historyFormatCurrency(entry.order_amount));
          }
          if (entry.order_items) {
            metaParts.push('Items: ' + entry.order_items);
          }
          if (entry.mode_payment) {
            metaParts.push('Payment: ' + entry.mode_payment);
          }
        } else if (entry.event_category === 'Feedback') {
          if (entry.rating) {
            metaParts.push('Rating: ' + entry.rating + ' star' + (entry.rating === 1 ? '' : 's'));
          }
          if (entry.product_name) {
            metaParts.push('Product: ' + entry.product_name);
          }
        } else if (entry.event_category === 'Reservations') {
          if (entry.product_id) {
            metaParts.push('Item ID: ' + entry.product_id);
          }
          if (entry.action_label) {
            metaParts.push('Status: ' + entry.action_label);
          }
        }

        const metaHtml = metaParts.length
          ? '<ul class="history-meta">' + metaParts.map(part => '<li>' + escapeHistoryText(part) + '</li>').join('') + '</ul>'
          : '';

        let dateMain = timestampSource;
        let timezoneLabel = '';
        const upperTimestamp = timestampSource.toUpperCase();
        if (upperTimestamp.endsWith(' PHT')) {
          dateMain = timestampSource.slice(0, -4).trim();
          timezoneLabel = 'PHT';
        } else if (upperTimestamp.endsWith(' PH TIME')) {
          dateMain = timestampSource.slice(0, -8).trim();
          timezoneLabel = 'PH Time';
        }

        let dateText = dateMain;
        let timeText = '';
        const bulletIndex = dateMain.indexOf('•');
        if (bulletIndex !== -1) {
          dateText = dateMain.slice(0, bulletIndex).trim();
          timeText = dateMain.slice(bulletIndex + 1).trim();
        }

        const dateDisplay = escapeHistoryText(dateText || 'Pending timestamp');
        const timeDisplay = escapeHistoryText(timeText);
        const timeHtml = timeDisplay ? '<div class="history-date-time">' + timeDisplay + '</div>' : '';
        const zoneHtml = timezoneLabel ? '<div class="history-date-zone">' + escapeHistoryText(timezoneLabel) + '</div>' : '';

        const notesHtml = noteSegments.length
          ? '<div class="history-note">' + noteSegments.map(line => '<div>' + escapeHistoryText(line) + '</div>').join('') + '</div>'
          : '<div class="history-note history-note-empty">No additional details recorded.</div>';

        const roleHtml = role ? '<span class="history-role-badge">' + role + '</span>' : '';

        const timestampHtml = '<div class="history-card-timestamp"><div class="history-date-date">' + dateDisplay + '</div>' + timeHtml + zoneHtml + '</div>';
        const tagsHtml = '<div class="history-card-tags"><span class="history-id-badge"><i class="bi ' + icon + '"></i><span>' + escapeHistoryText(category) + '</span></span><span class="' + pill.className + '">' + escapeHistoryText(pill.label) + '</span></div>';
        const userHtml = '<div class="history-user-main"><i class="bi bi-person-fill"></i><span>' + performed + '</span></div>';

        return `<tr class="history-row">
          <td colspan="4">
            <div class="history-card">
              <div class="history-card-top">
                ${tagsHtml}
                ${timestampHtml}
              </div>
              <div class="history-card-main">
                <div class="history-headline">${headline}</div>
                ${metaHtml}
                ${notesHtml}
              </div>
              <div class="history-card-footer">
                ${userHtml}
                ${roleHtml}
              </div>
            </div>
          </td>
        </tr>`;
      }).join('');

      historyElements.tbody.innerHTML = rows;
    }

    async function loadSystemHistory(force = true) {
      if (historyState.isLoading && !force) return;
      if (!historyElements.table || !historyElements.tbody) return;

      const params = new URLSearchParams();
      const { type, date, search } = historyState.filters;
      if (type) params.set('type', type);
      if (date) params.set('date', date);
      if (search) params.set('search', search);
      params.set('limit', '200');
      params.set('ts', Date.now().toString());

      if (historyElements.empty) historyElements.empty.classList.add('d-none');
      if (historyElements.loading) historyElements.loading.classList.remove('d-none');
      setHistoryLoading(true);

      try {
        const query = '?action=get_system_history' + (params.toString() ? '&' + params.toString() : '');
        const response = await fetch(query, { cache: 'no-store' });
        const text = await response.text();
        let result;
        try {
          result = JSON.parse(text);
        } catch (parseError) {
          console.error('History parse error:', text);
          throw new Error('Server returned an unreadable history response.');
        }

        if (!response.ok || result.status !== 'success' || !Array.isArray(result.data)) {
          throw new Error(result.message || 'Unable to load system history right now.');
        }

        historyState.records = result.data;
        renderHistory(result.data);
        updateHistoryUpdatedLabel();
      } catch (error) {
        console.error('History load failed:', error);
        if (historyElements.empty) {
          historyElements.empty.textContent = error.message || 'Unable to load history. Please try again.';
          historyElements.empty.classList.remove('d-none');
        }
        if (historyElements.table) historyElements.table.classList.add('d-none');
      } finally {
        setHistoryLoading(false);
      }
    }

    historyElements.type?.addEventListener('change', () => {
      historyState.filters.type = historyElements.type.value || '';
      loadSystemHistory();
    });

    historyElements.date?.addEventListener('change', () => {
      historyState.filters.date = historyElements.date.value || '';
      loadSystemHistory();
    });

    historyElements.search?.addEventListener('keydown', (event) => {
      if (event.key === 'Enter') {
        event.preventDefault();
        historyState.filters.search = historyElements.search.value.trim();
        loadSystemHistory();
      }
    });

    historyElements.searchBtn?.addEventListener('click', () => {
      historyState.filters.search = historyElements.search?.value.trim() || '';
      loadSystemHistory();
    });

    historyElements.refresh?.addEventListener('click', () => loadSystemHistory(true));

    historyElements.exportBtn?.addEventListener('click', () => {
      if (!historyState.records.length) {
        alert('No history entries to export yet.');
        return;
      }

      const header = ['Category', 'Action', 'Summary', 'Notes', 'User', 'Role', 'Timestamp'];
      const rows = historyState.records.map(entry => [
        entry.event_category || '',
        entry.action_label || entry.action_type || '',
        entry.headline || entry.event_summary || '',
        entry.notes || '',
        entry.performed_by || entry.performed_by_masked || '',
        entry.user_role || '',
        entry.log_date_formatted || entry.log_date || ''
      ]);

      const csv = [header, ...rows].map(columns => columns.map(value => {
        const text = String(value ?? '').replace(/"/g, '""');
        return '"' + text + '"';
      }).join(',')).join('\r\n');

      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = 'system-history-' + new Date().toISOString().slice(0, 19).replace(/[T:]/g, '-') + '.csv';
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      URL.revokeObjectURL(url);
    });

    /* ---------- Sidebar & Page Switch (CHANGES, 11-17-25) ---------- */
    const sidebarLinks = document.querySelectorAll('.sidebar .nav-link');
    const pages = document.querySelectorAll('.page');
    let historyRefreshTimer = null;

    function stopHistoryAutoRefresh() {
      if (historyRefreshTimer) {
        clearInterval(historyRefreshTimer);
        historyRefreshTimer = null;
      }
    }

    function startHistoryAutoRefresh() {
      stopHistoryAutoRefresh();
      historyRefreshTimer = setInterval(() => {
        const historyPage = document.getElementById('history');
        if (historyPage && historyPage.classList.contains('active') && typeof loadSystemHistory === 'function') {
          loadSystemHistory(false);
        }
      }, 5000);
    }

    function showPage(targetId, pushStateEnabled = true) {
      pages.forEach(p => p.classList.remove('active'));
      const targetPage = document.getElementById(targetId);
      if (targetPage) setTimeout(() => targetPage.classList.add('active'), 50);
      sidebarLinks.forEach(l => l.classList.remove('active'));
      const activeLink = document.querySelector(`.sidebar .nav-link[data-page="${targetId}"]`);
      if (activeLink) activeLink.classList.add('active');
      // Toggle staff button visibility
      const staffContainer = document.getElementById('staffButtonContainer');
      if (staffContainer) {
        staffContainer.style.display = targetId === 'dashboard' ? 'block' : 'none';
      }
      if (typeof loadAnnouncements === 'function' && targetId === 'dashboard') {
        loadAnnouncements();
      }
      if (targetId === 'history') {
        if (typeof loadSystemHistory === 'function') {
          loadSystemHistory();
        }
        startHistoryAutoRefresh();
      } else {
        stopHistoryAutoRefresh();
      }

      if (targetId === 'manage-staff') {
        if (typeof loadStaffList === 'function') loadStaffList();
      }
      if (targetId === 'ai-analytics' && typeof loadAiAnalytics === 'function') {
        loadAiAnalytics(false);
      }
      if (pushStateEnabled) {
        history.pushState({}, '', `?page=${targetId}`);
      }
    }
    sidebarLinks.forEach(link => {
      link.addEventListener('click', function (e) {
        const page = this.getAttribute('data-page');
        if (page) {
          e.preventDefault();
          showPage(page);
          // If mobile sidebar is open, close it when a link is clicked
          if (window.innerWidth <= 767) document.body.classList.remove('mobile-sidebar-open');
        }
      });
    });
    const dashboardStats = <?= json_encode($dashboardStats, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
    const ownerUserId = <?= (int)($current_user['User_ID'] ?? 0) ?>;
    const performanceData = <?= json_encode($productPerformance, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
    let inventory = <?= json_encode($inventoryData, JSON_HEX_TAG | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_HEX_AMP) ?>;
    if (!Array.isArray(inventory)) inventory = [];

    const announcementListEl = document.getElementById('announcementList');
    const announcementForm = document.getElementById('announcementForm');
    const announcementMessageInput = document.getElementById('announcementMessage');
    const announcementAudienceSelect = document.getElementById('announcementAudience');
    const announcementExpiresInput = document.getElementById('announcementExpiresAt');
    const announcementSubmitBtn = document.getElementById('announcementSubmitBtn');
    const announcementModalEl = document.getElementById('announcementModal');
    const announcementModal = announcementModalEl ? bootstrap.Modal.getOrCreateInstance(announcementModalEl) : null;

    const announcementEmptyMarkup = '<li class="announcement-empty">No announcements yet. Use “New Announcement” to post an update.</li>';

    function sanitizeAnnouncementText(value) {
      const text = String(value ?? '');
      const entityMap = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;'
      };
      const escaped = text.replace(/[&<>"']/g, char => entityMap[char] || char);
      return escaped.replace(/\n/g, '<br>');
    }

    function renderAnnouncements(items) {
      if (!announcementListEl) return;
      if (!Array.isArray(items) || items.length === 0) {
        announcementListEl.innerHTML = announcementEmptyMarkup;
        return;
      }

      const rows = items.map(item => {
        const messageHtml = sanitizeAnnouncementText(item.message || '');
        const metaParts = [];
        if (item.created_at_formatted) {
          metaParts.push('Posted ' + item.created_at_formatted);
        }
        if (item.expires_at_formatted) {
          metaParts.push('Expires ' + item.expires_at_formatted);
        }
        const metaHtml = metaParts.length
          ? `<div class="announcement-meta">${metaParts.map(sanitizeAnnouncementText).join(' • ')}</div>`
          : '';

        const id = Number(item.id) || 0;
        return `<li class="announcement-item" data-announcement-id="${id}">
          <div>
            <p class="announcement-text">${messageHtml}</p>
            ${metaHtml}
          </div>
          <div class="announcement-actions">
            <button type="button" class="announcement-action" data-action="archive-announcement" data-id="${id}">
              Archive
            </button>
          </div>
        </li>`;
      }).join('');

      announcementListEl.innerHTML = rows;
    }

    async function loadAnnouncements() {
      if (!announcementListEl) return;
      announcementListEl.innerHTML = '<li class="announcement-empty">Loading announcements...</li>';
      try {
        const response = await fetch('?action=list-announcements&limit=20');
        const text = await response.text();
        let result;
        try {
          result = JSON.parse(text);
        } catch (error) {
          console.error('Announcement list raw response:', text);
          throw new Error('Failed to load announcements.');
        }

        if (!response.ok || result.status !== 'success') {
          throw new Error(result.message || 'Unable to load announcements.');
        }

        renderAnnouncements(result.data || []);
      } catch (error) {
        console.error(error);
        const message = sanitizeAnnouncementText(error.message || 'Unable to load announcements.');
        announcementListEl.innerHTML = `<li class="announcement-empty">${message}</li>`;
      }
    }

    announcementListEl?.addEventListener('click', async (event) => {
      const target = event.target.closest('[data-action="archive-announcement"]');
      if (!target) return;

      const announcementId = parseInt(target.dataset.id || '0', 10);
      if (!announcementId) return;

      if (!confirm('Archive this announcement?')) {
        return;
      }

      target.disabled = true;
      try {
        const response = await fetch('?action=delete-announcement', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ announcement_id: announcementId })
        });
        const text = await response.text();
        let result;
        try {
          result = JSON.parse(text);
        } catch (error) {
          console.error('Announcement delete raw response:', text);
          throw new Error('Server error archiving announcement.');
        }

        if (!response.ok || result.status !== 'success') {
          throw new Error(result.message || 'Unable to archive announcement.');
        }

        if (typeof showSuccessMessage === 'function') {
          showSuccessMessage('Announcement archived.');
        }
        loadAnnouncements();
      } catch (error) {
        alert(error.message || 'Unable to archive announcement.');
      } finally {
        target.disabled = false;
      }
    });

    announcementForm?.addEventListener('submit', async (event) => {
      event.preventDefault();
      if (!announcementMessageInput) return;

      const message = announcementMessageInput.value.trim();
      if (message === '') {
        alert('Announcement message is required.');
        announcementMessageInput.focus();
        return;
      }

      const payload = {
        message,
        audience: announcementAudienceSelect?.value || 'customer',
        expires_at: announcementExpiresInput?.value || ''
      };

      if (announcementSubmitBtn) {
        announcementSubmitBtn.disabled = true;
        announcementSubmitBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Posting...';
      }

      try {
        const response = await fetch('?action=create-announcement', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(payload)
        });

        const text = await response.text();
        let result;
        try {
          result = JSON.parse(text);
        } catch (error) {
          console.error('Announcement create raw response:', text);
          throw new Error('Server error while posting announcement.');
        }

        if (!response.ok || result.status !== 'success') {
          throw new Error(result.message || 'Unable to post announcement.');
        }

        announcementForm.reset();
        if (announcementModal) announcementModal.hide();
        if (typeof showSuccessMessage === 'function') {
          showSuccessMessage('Announcement published.');
        }
        loadAnnouncements();
      } catch (error) {
        alert(error.message || 'Failed to post announcement.');
      } finally {
        if (announcementSubmitBtn) {
          announcementSubmitBtn.disabled = false;
          announcementSubmitBtn.innerHTML = '<i class="bi bi-megaphone-fill me-1"></i> Post Announcement';
        }
      }
    });

    announcementModalEl?.addEventListener('show.bs.modal', () => {
      announcementForm?.reset();
      if (announcementSubmitBtn) {
        announcementSubmitBtn.disabled = false;
        announcementSubmitBtn.innerHTML = '<i class="bi bi-megaphone-fill me-1"></i> Post Announcement';
      }
    });

    announcementModalEl?.addEventListener('shown.bs.modal', () => {
      setTimeout(() => announcementMessageInput?.focus(), 120);
    });

    loadAnnouncements();

    const urlParams = new URLSearchParams(window.location.search);
    const currentPage = urlParams.get('page') || 'dashboard';
    showPage(currentPage, false);
    const staffContainerInit = document.getElementById('staffButtonContainer');
    if (staffContainerInit) {
      staffContainerInit.style.display = currentPage === 'dashboard' ? 'block' : 'none';
    }

    /* ---------- Order Summary Tabs Logic ---------- */
    let currentPeriod = 'today';
    const orderTabs = document.querySelectorAll('.order-tab');
    const orderCountEl = document.getElementById('orderCount');
    const orderRevenueEl = document.getElementById('orderRevenue');
    const tabUnderline = document.querySelector('.order-tabs .underline');

    function updateOrderSummary(period) {
      currentPeriod = period;
      let orders = 0, revenue = 0;
      
      if (period === 'today') {
        orders = dashboardStats.orders_today || 0;
        revenue = dashboardStats.revenue_today || 0;
      } else if (period === 'weekly') {
        orders = dashboardStats.orders_weekly || 0;
        revenue = dashboardStats.revenue_weekly || 0;
      } else if (period === 'monthly') {
        orders = dashboardStats.orders_monthly || 0;
        revenue = dashboardStats.revenue_monthly || 0;
      }

      if (orderCountEl) orderCountEl.textContent = orders.toLocaleString();
      if (orderRevenueEl) {
        if (revenue >= 1000) {
          orderRevenueEl.textContent = aiFormatCurrencyShort(revenue);
        } else {
          orderRevenueEl.textContent = '₱' + revenue.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
        }
      }
    }

    orderTabs.forEach((tab, index) => {
      tab.addEventListener('click', function() {
        orderTabs.forEach(t => t.classList.remove('active'));
        this.classList.add('active');
        
        const period = this.getAttribute('data-period');
        updateOrderSummary(period);
        
        // Animate underline
        if (tabUnderline) {
          const tabWidth = this.offsetWidth;
          const tabLeft = this.offsetLeft;
          tabUnderline.style.width = tabWidth + 'px';
          tabUnderline.style.left = tabLeft + 'px';
        }
      });
    });

    /* ---------- Revenue Chart Logic ---------- */
    let revenueChart = null;
    const revenueChartCanvas = document.getElementById('revenueChart');
    const revenueChartPeriodSelect = document.getElementById('revenueChartPeriod');

    async function loadRevenueChart(period) {
      try {
        const response = await fetch(`?action=revenue-chart-${period}`);
        const rawText = await response.text();
        let result = null;
        try {
          result = rawText ? JSON.parse(rawText) : null;
        } catch (parseError) {
          console.error('Revenue chart endpoint returned non-JSON:', rawText);
          throw new Error('Revenue chart endpoint returned invalid JSON.');
        }
        
        if (!result || result.status !== 'success') {
          console.error('Failed to load chart data:', result);
          return;
        }

        const chartData = result.data;
        let labels = [];
        let revenueData = [];
        let ordersData = [];

        if (period === 'weekly') {
          chartData.forEach(item => {
            labels.push(item.day || item.date);
            revenueData.push(parseFloat(item.revenue) || 0);
            ordersData.push(parseInt(item.orders) || 0);
          });
        } else if (period === 'monthly') {
          chartData.forEach(item => {
            labels.push('Day ' + item.day);
            revenueData.push(parseFloat(item.revenue) || 0);
            ordersData.push(parseInt(item.orders) || 0);
          });
        } else if (period === 'yearly') {
          // Chart data for each month in the last 12 months
          const monthNames = ["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"];
          const monthMap = chartData.reduce((acc, it) => { acc[it.month] = it; return acc; }, {});
          const now = new Date();
          for (let i = 11; i >= 0; --i) {
            const d = new Date(now.getFullYear(), now.getMonth() - i, 1);
            const mm = d.getMonth();
            const yyyy = d.getFullYear();
            const key = yyyy + '-' + String(mm + 1).padStart(2, '0');
            labels.push(monthNames[mm]);
            if (monthMap[key]) {
              revenueData.push(parseFloat(monthMap[key].revenue) || 0);
              ordersData.push(parseInt(monthMap[key].orders) || 0);
            } else {
              revenueData.push(0);
              ordersData.push(0);
            }
          }
        }

        if (revenueChart) {
          revenueChart.destroy();
        }

        const ctx = revenueChartCanvas.getContext('2d');
        // Create a gradient for the revenue line and fill
        const gradient = ctx.createLinearGradient(0, 0, 0, revenueChartCanvas.height || 220);
        gradient.addColorStop(0, 'rgba(40,167,69,0.95)');
        gradient.addColorStop(0.6, 'rgba(92,184,92,0.6)');
        gradient.addColorStop(1, 'rgba(92,184,92,0.06)');

        // Plugin to draw the k-formatted labels above each revenue data point
        const pointLabelPlugin = {
          id: 'pointLabel',
          afterDatasetsDraw(chart) {
            const ctx = chart.ctx;
            chart.data.datasets.forEach((dataset, dsIndex) => {
              if (dsIndex !== 0) return; // only label the revenue dataset
              const meta = chart.getDatasetMeta(dsIndex);
              meta.data.forEach((point, index) => {
                const value = dataset.data[index] || 0;
                const k = Math.round((value / 1000) * 10) / 10; // show one decimal place where needed
                const label = '₱' + k.toLocaleString() + 'k';
                ctx.font = '600 11px Segoe UI, Tahoma, sans-serif';
                ctx.fillStyle = '#1b6b2b';
                ctx.textAlign = 'center';
                ctx.textBaseline = 'bottom';
                ctx.fillText(label, point.x, point.y - 8);
              });
            });
          }
        };
        revenueChart = new Chart(ctx, {
          type: 'line',
          data: {
            labels: labels,
            datasets: [{
              label: 'Revenue (₱)',
              data: revenueData,
              borderColor: gradient,
              backgroundColor: gradient,
              borderWidth: 3,
              tension: 0,
              spanGaps: false,
              fill: true,
              pointRadius: 5,
              pointHoverRadius: 7,
              pointBackgroundColor: '#ffffff',
              pointBorderColor: '#28a745',
              pointBorderWidth: 2,
              yAxisID: 'y'
            }, {
              label: 'Orders',
              data: ordersData,
              borderColor: '#4d2e00',
              backgroundColor: 'rgba(77, 46, 0, 0.1)',
              borderWidth: 2,
              tension: 0,
              spanGaps: false,
              fill: false,
              yAxisID: 'y1'
            }]
          },
          plugins: [pointLabelPlugin],
          options: {
            responsive: true,
            maintainAspectRatio: false,
            interaction: {
              mode: 'index',
              intersect: false,
            },
            plugins: {
              legend: {
                display: true,
                position: 'top',
              },
              tooltip: {
                callbacks: {
                  label: function(context) {
                    let label = context.dataset.label || '';
                    if (label) label += ': ';
                    if (context.parsed.y !== null) {
                      if (context.datasetIndex === 0) {
                        // Show full value in tooltip
                        label += '₱' + context.parsed.y.toLocaleString('en-US', { minimumFractionDigits: 2 });
                      } else {
                        label += context.parsed.y.toLocaleString();
                      }
                    }
                    return label;
                  }
                }
              }
            },
            scales: {
              y: {
                type: 'linear',
                display: true,
                position: 'left',
                title: {
                  display: true,
                  text: 'In thousands (₱)'
                },
                ticks: {
                  callback: function(value) {
                    // Convert to thousands for display and add k suffix
                    const k = value / 1000;
                    if (k === 0) return '0';
                    return '₱' + k.toLocaleString() + 'k';
                  }
                }
              },
              y1: {
                type: 'linear',
                display: true,
                position: 'right',
                title: {
                  display: true,
                  text: 'Orders'
                },
                grid: {
                  drawOnChartArea: false,
                },
              },
            }
          }
        });
      } catch (error) {
        console.error('Error loading revenue chart:', error);
      }
    }

    // Load initial chart
    loadRevenueChart('yearly');

    // Chart period change handler
    if (revenueChartPeriodSelect) {
      revenueChartPeriodSelect.value = 'yearly';
      revenueChartPeriodSelect.addEventListener('change', function() {
      loadRevenueChart(this.value);
      });
    }

    /* ---------- Funding Projections Logic ---------- */
    let projectionChart = null;

    function formatCurrency(value) {
      const num = Number(value);
      const safe = Number.isFinite(num) ? num : 0;
      return '₱' + safe.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 });
    }

    function toSafeNumber(value) {
      const num = Number(value);
      return Number.isFinite(num) ? num : 0;
    }

    async function loadFundingProjections() {
      try {
        const response = await fetch('?action=funding-projections');
        const result = await response.json();

        if (!result || result.status !== 'success') {
          console.error('Failed to load funding projections:', result);
          return;
        }

        const data = result.data || {};

        const currentRevenue = toSafeNumber(data.current_month_revenue);
        const projectedNext = toSafeNumber(data.projected_next_month);
        const projected3 = toSafeNumber(data.projected_3_months);
        const projected6 = toSafeNumber(data.projected_6_months);
        const avgMonthly = toSafeNumber(data.average_monthly_revenue);
        const growthRate = toSafeNumber(data.growth_rate);
        const dataPoints = toSafeNumber(data.data_points);
        const confidence = typeof data.confidence === 'string' ? data.confidence.toLowerCase() : 'low';
        const historicalData = Array.isArray(data.historical_data) ? data.historical_data : [];

        const currentMonthEl = document.getElementById('currentMonthRevenue');
        if (currentMonthEl) currentMonthEl.textContent = formatCurrency(currentRevenue);

        const projectedNextEl = document.getElementById('projectedNextMonth');
        if (projectedNextEl) projectedNextEl.textContent = formatCurrency(projectedNext);

        const projected3El = document.getElementById('projected3Months');
        if (projected3El) projected3El.textContent = formatCurrency(projected3);

        const projected6El = document.getElementById('projected6Months');
        if (projected6El) projected6El.textContent = formatCurrency(projected6);

        const growthBadge = document.getElementById('growthRateBadge');
        if (growthBadge) {
          growthBadge.textContent = growthRate.toFixed(2) + '%';
          growthBadge.className = 'badge ' + (growthRate >= 0 ? 'bg-success' : 'bg-danger');
          growthBadge.style.fontSize = '14px';
        }

        const avgRevenueEl = document.getElementById('avgMonthlyRevenue');
        if (avgRevenueEl) avgRevenueEl.textContent = formatCurrency(avgMonthly);

        const dataPointsEl = document.getElementById('dataPoints');
        if (dataPointsEl) dataPointsEl.textContent = `${dataPoints} months`;

        const confidenceBadge = document.getElementById('confidenceBadge');
        if (confidenceBadge) {
          const confidenceColors = {
            high: 'bg-success',
            medium: 'bg-warning',
            low: 'bg-secondary'
          };
          const label = confidence.charAt(0).toUpperCase() + confidence.slice(1);
          confidenceBadge.textContent = label;
          confidenceBadge.className = 'badge ' + (confidenceColors[confidence] || 'bg-secondary');
        }

        updateHistoricalTable(historicalData);
        updateProjectionChart({
          ...data,
          current_month_revenue: currentRevenue,
          projected_next_month: projectedNext,
          projected_3_months: projected3,
          projected_6_months: projected6,
          average_monthly_revenue: avgMonthly,
          growth_rate: growthRate,
          data_points: dataPoints,
          confidence,
          historical_data: historicalData
        });

      } catch (error) {
        console.error('Error loading funding projections:', error);
      }
    }

    function updateHistoricalTable(historicalData) {
      const tbody = document.getElementById('historicalTableBody');
      if (!tbody) return;

      const rows = Array.isArray(historicalData) ? historicalData : [];

      if (rows.length === 0) {
        tbody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No historical data available</td></tr>';
        return;
      }

      let html = '';
      let previousRevenue = null;

      rows.forEach(item => {
        const revenue = toSafeNumber(item && item.revenue);
        const orders = toSafeNumber(item && item.orders);
        const avgOrderValue = toSafeNumber(item && item.avg_order_value);
        const monthName = item && item.month_name ? item.month_name : 'Unknown';

        let growthHtml = '-';
        if (previousRevenue !== null && Number.isFinite(previousRevenue) && previousRevenue > 0) {
          const growth = ((revenue - previousRevenue) / previousRevenue) * 100;
          const growthClass = growth >= 0 ? 'text-success' : 'text-danger';
          const growthIcon = growth >= 0 ? 'bi-arrow-up' : 'bi-arrow-down';
          growthHtml = `<span class="${growthClass}"><i class="bi ${growthIcon}"></i> ${Math.abs(growth).toFixed(1)}%</span>`;
        }

        html += `
          <tr>
            <td><strong>${monthName}</strong></td>
            <td class="text-end">${orders.toLocaleString()}</td>
            <td class="text-end">${formatCurrency(revenue)}</td>
            <td class="text-end">${formatCurrency(avgOrderValue)}</td>
            <td class="text-end">${growthHtml}</td>
          </tr>
        `;
        previousRevenue = revenue;
      });

      tbody.innerHTML = html;
    }

    function updateProjectionChart(data) {
      const canvas = document.getElementById('projectionChart');
      if (!canvas) return;

      const historical = Array.isArray(data.historical_data) ? data.historical_data : [];
      const historicalLabels = historical.map(item => item?.month_name || '');
      const historicalRevenue = historical.map(item => toSafeNumber(item?.revenue));

      const projectionLabels = ['Next Month', '+2 Months', '+3 Months', '+4 Months', '+5 Months', '+6 Months'];
      const labels = [...historicalLabels, ...projectionLabels];

      const baseRevenue = toSafeNumber(data.current_month_revenue);
      const growthMultiplier = 1 + (toSafeNumber(data.growth_rate) / 100);

      const projectedValues = projectionLabels.map((_, index) => baseRevenue * Math.pow(growthMultiplier, index + 1));
      const projectedRevenue = [
        ...Array(historicalRevenue.length).fill(null),
        ...projectedValues
      ];

      const paddedHistorical = [
        ...historicalRevenue,
        ...Array(projectionLabels.length).fill(null)
      ];

      if (projectionChart) {
        projectionChart.destroy();
      }

      const ctx = canvas.getContext('2d');
      projectionChart = new Chart(ctx, {
        type: 'line',
        data: {
          labels: labels,
          datasets: [{
            label: 'Historical Revenue',
            data: paddedHistorical,
            borderColor: '#4d2e00',
            backgroundColor: 'rgba(77, 46, 0, 0.1)',
            borderWidth: 3,
            tension: 0,
            spanGaps: true,
            fill: false,
            pointRadius: 5,
            pointHoverRadius: 7
          }, {
            label: 'Projected Revenue',
            data: projectedRevenue,
            borderColor: '#28a745',
            backgroundColor: 'rgba(40, 167, 69, 0.1)',
            borderWidth: 3,
            borderDash: [10, 5],
            tension: 0,
            spanGaps: true,
            fill: false,
            pointRadius: 5,
            pointHoverRadius: 7
          }]
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: {
            mode: 'index',
            intersect: false,
          },
          plugins: {
            legend: {
              display: true,
              position: 'top',
            },
            tooltip: {
              callbacks: {
                label: function(context) {
                  let label = context.dataset.label || '';
                  if (label) label += ': ';
                  if (context.parsed.y !== null) {
                    label += '₱' + context.parsed.y.toLocaleString('en-US', { minimumFractionDigits: 2 });
                  }
                  return label;
                }
              }
            }
          },
          scales: {
            y: {
              beginAtZero: true,
              title: {
                display: true,
                text: 'Revenue (₱)'
              },
              ticks: {
                callback: function(value) {
                  return '₱' + value.toLocaleString();
                }
              }
            }
          }
        }
      });
    }

    // Load projections when funding page is shown
    const fundingLink = document.querySelector('.sidebar .nav-link[data-page="funding"]');
    if (fundingLink) {
      fundingLink.addEventListener('click', function() {
        setTimeout(() => loadFundingProjections(), 100);
      });
    }

    // Load on page load if funding page is active
    if (window.location.search.includes('page=funding')) {
      setTimeout(() => loadFundingProjections(), 500);
    }

    /* ---------- Live Clock ( Welcome Back, Owner) ---------- */
    function updateDateTime() {
      const now = new Date();
      const options = {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit',
        timeZone: 'Asia/Manila'
      };
      document.getElementById('datetime').textContent = now.toLocaleString('en-US', options);
    }
    setInterval(updateDateTime, 1000);
    updateDateTime();
    // --- Owner user icon dropdown logic (like staff) ---
    document.addEventListener("DOMContentLoaded", function () {
      const userIcon = document.getElementById("userIcon");
      const dropdown = document.getElementById("userDropdown");
      if (userIcon && dropdown) {
        userIcon.addEventListener("click", e => {
          e.stopPropagation();
          dropdown.classList.toggle("show");
        });
        document.addEventListener("click", () => dropdown.classList.remove("show"));
        dropdown.addEventListener("click", e => e.stopPropagation());
      }
      // Open profile overlay from dropdown
      const profileOverlay = document.getElementById('profile-overlay');
      const profileLink = document.getElementById('openProfileLink');
      if (profileLink && profileOverlay) {
        profileLink.addEventListener('click', function(e) {
          e.preventDefault();
          profileOverlay.style.display = 'flex';
          dropdown.classList.remove("show");
        });
      }
      // Close overlay (fix: use correct id 'close-profile')
      document.getElementById('close-profile')?.addEventListener('click', function() {
        if (profileOverlay) {
          profileOverlay.style.display = 'none';
        }
      });
    });
    const profileForm = document.getElementById('profile-form');
    const profileOverlayEl = document.getElementById('profile-overlay');
    const profileCloseBtn = document.getElementById('profileCloseBtn');
    const ownerNameDisplay = document.getElementById('ownerNameDisplay');
    const ownerEmailDisplay = document.getElementById('ownerEmailDisplay');
    const ownerWelcomeName = document.getElementById('ownerWelcomeName');

    // Since the owner profile is read-only, Close button simply hides the overlay
    profileCloseBtn?.addEventListener('click', function() {
      if (profileOverlayEl) profileOverlayEl.style.display = 'none';
    });
    /* ---------- Success Message Functions ---------- */
    function showSuccessMessage(message) {
      const successDiv = document.getElementById('successMessage');
      const successText = document.getElementById('successText');
      successText.textContent = message;
      successDiv.style.display = 'block';
      successDiv.classList.add('show');
      setTimeout(() => {
        hideSuccessMessage();
      }, 3000); // Auto-hide after 3 seconds
    }
    function hideSuccessMessage() {
      const successDiv = document.getElementById('successMessage');
      successDiv.classList.remove('show');
      setTimeout(() => {
        successDiv.style.display = 'none';
      }, 150); // Wait for fade out
    }

    /* ---------- HAMBURGER TOGGLE LOGIC (ADDED) ---------- */
    const hamburger = document.getElementById('hamburger');
    const sidebarOverlay = document.getElementById('sidebarOverlay');
    function isMobile() { return window.innerWidth <= 767; }
    // Toggle behavior:
    // - Desktop (>=768px): toggle body.sidebar-collapsed (sidebar slides out and content shifts)
    // - Mobile (<768px): toggle body.mobile-sidebar-open (sidebar slides over content + overlay)
    hamburger?.addEventListener('click', function(e) {
      e.stopPropagation();
      if (isMobile()) {
        document.body.classList.toggle('mobile-sidebar-open');
      } else {
        document.body.classList.toggle('sidebar-collapsed');
      }
    });
    // Clicking overlay closes mobile sidebar
    sidebarOverlay?.addEventListener('click', function() {
      document.body.classList.remove('mobile-sidebar-open');
    });
    // Close mobile sidebar when resizing to desktop
    window.addEventListener('resize', function() {
      if (!isMobile()) {
        document.body.classList.remove('mobile-sidebar-open');
      } else {
        // If resizing to mobile, ensure the desktop collapsed state is removed
        // so it doesn't interfere with mobile's logic.
        document.body.classList.remove('sidebar-collapsed');
      }
    });

    // On initial load, if it's desktop, collapse the sidebar by default.
    if (!isMobile()) {
      document.body.classList.add('sidebar-collapsed');
    }

    /* ---------- Product Performance Logic ---------- */
    const productContainer = document.getElementById('products-list');
    const paginationEl = document.getElementById('pagination');
    const performanceCategoryFilter = document.getElementById('performance-category-filter');
    let activeCat = 'All';

    const fallbackProducts = [
      { id: 1, name: "Spicy Tuna Pasta", cat: "Pasta", price: 160, sales: 245, rating: 4.5, reviews: 89 },
      { id: 2, name: "Margherita Pizza", cat: "Pizza", price: 320, sales: 412, rating: 4.8, reviews: 156 },
      { id: 3, name: "Chocolate Cake Slice", cat: "Cakes", price: 120, sales: 189, rating: 4.7, reviews: 67 },
      { id: 4, name: "Iced Latte", cat: "Coffee Beverages", price: 130, sales: 567, rating: 4.6, reviews: 210 },
      { id: 5, name: "Ham & Cheese Sandwich", cat: "Sandwiches & Salad", price: 95, sales: 134, rating: 4.3, reviews: 45 },
      { id: 6, name: "Lemon Bar", cat: "Pie, Cookies, Bar", price: 80, sales: 98, rating: 4.4, reviews: 32 }
    ];

    const hasServerPerformance = Array.isArray(performanceData);
    const baseProducts = hasServerPerformance ? performanceData : fallbackProducts;
    const usingFallbackProducts = !hasServerPerformance;

    function escapeHtml(value) {
      return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
    }

    const productDataset = Array.isArray(baseProducts)
      ? baseProducts.map(item => {
          const ratingValue = Number(item.rating ?? item.avg_rating ?? 0);
          const clampedRating = Number.isFinite(ratingValue) ? Math.min(5, Math.max(0, ratingValue)) : 0;
          const reviewsCount = Number(item.reviews ?? item.total_reviews ?? 0);
          const positiveCount = Number(item.positive_reviews ?? item.positive ?? 0);
          return {
            id: item.id ?? item.Product_ID ?? null,
            name: item.name ?? item.Product_Name ?? 'Unnamed Product',
            cat: item.cat ?? item.Category ?? 'Uncategorized',
            price: Number(item.price ?? item.Price ?? 0) || 0,
            sales: Number(item.sales ?? item.total_quantity ?? 0) || 0,
            rating: clampedRating,
            reviews: Number.isFinite(reviewsCount) && reviewsCount > 0 ? reviewsCount : 0,
            positive: Number.isFinite(positiveCount) && positiveCount > 0 ? positiveCount : 0,
            image: typeof item.image === 'string' && item.image.length
              ? item.image
              : (typeof item.Image === 'string' && item.Image.length ? item.Image : null)
          };
        })
      : [];

    function renderStars(ratingValue) {
      const rounded = Math.round(Math.min(5, Math.max(0, Number(ratingValue) || 0)));
      return '★'.repeat(rounded) + '☆'.repeat(5 - rounded);
    }

    function renderProducts(filter = 'All') {
      const isAll = filter === 'All';
      const filtered = isAll ? productDataset : productDataset.filter(p => p.cat === filter);

      if (filtered.length === 0) {
        const emptyMessage = usingFallbackProducts
          ? 'No products in this category yet'
          : filter === 'All'
            ? 'No products with positive customer feedback yet.'
            : 'No products with positive customer feedback in this category.';
        productContainer.innerHTML = `<div class="empty-msg"><i class="bi bi-inbox"></i><div>${emptyMessage}</div></div>`;
        paginationEl.style.display = 'none';
        return;
      }

      const html = filtered.map(p => {
        const reviewLabel = p.reviews === 1 ? 'review' : 'reviews';
        const ratingHtml = p.reviews > 0
          ? `<div class="rating">${renderStars(p.rating)} ${p.rating.toFixed(1)} / 5 (${p.reviews} ${reviewLabel})</div>`
          : '<div class="rating text-muted">No feedback yet</div>';
        const safeName = escapeHtml(p.name);
        const imageHtml = p.image
          ? `<div class="product-img loaded"><img src="${p.image}" alt="${safeName}"></div>`
          : '<div class="product-img placeholder">🍽️</div>';
        const totalSales = Number.isFinite(p.sales) ? p.sales : 0;
        const salesText = totalSales.toLocaleString('en-US') + ' Total Sales';

        return `
        <div class="product-card">
          ${imageHtml}
          <div class="product-info">
            <div class="product-name">${safeName}</div>
            <div class="product-sales">${salesText}</div>
            ${ratingHtml}
          </div>
          <div class="quantity">${totalSales} pcs</div>
        </div>`;
      }).join('');

      productContainer.innerHTML = html;
      paginationEl.style.display = filtered.length >= 6 ? 'flex' : 'none';
    }

    performanceCategoryFilter.addEventListener('change', function() {
      activeCat = this.value;
      renderProducts(activeCat);
    });

    renderProducts();
    /* ---------- Inventory Logic ---------- */
    const productIdField = document.getElementById('productID');
    const inventoryTable = document.getElementById('inventory-table');
    const categoryFilter = document.getElementById('category-filter');
    const modal = new bootstrap.Modal(document.getElementById('productModal'));
    const modalTitle = document.getElementById('modalTitle');
    const productForm = document.getElementById('productForm');
    const saveBtn = document.getElementById('saveProductBtn');
    // Robust inventory helpers & fixes for category mismatches and edit form behavior.
// Include this after your main dashboard script (or replace the current inventory-related script).
(function () {
  // If inventory isn't defined (safety), exit.
  if (typeof inventory === 'undefined') return;
  // Normalize category for comparison: trim, collapse whitespace, lowercase.
  function normalizeCategoryForCompare(cat) {
    if (cat === null || typeof cat === 'undefined') return '';
    return String(cat).trim().replace(/\s+/g, ' ').toLowerCase();
  }
  // Ensure the select element contains an option with the exact value, add if missing.
  function ensureSelectHasOption(selectEl, value) {
    if (!selectEl || typeof value === 'undefined' || value === null) return;
    const optExists = Array.from(selectEl.options).some(opt => opt.value === value);
    if (!optExists) {
      const opt = document.createElement('option');
      opt.value = value;
      opt.text = value;
      selectEl.appendChild(opt);
    }
  }
  // Get table and tbody; create tbody if missing
  const inventoryTableEl = document.getElementById('inventory-table');
  if (!inventoryTableEl) return;
  let inventoryTbody = inventoryTableEl.querySelector('tbody');
  if (!inventoryTbody) {
    inventoryTbody = document.createElement('tbody');
    inventoryTableEl.appendChild(inventoryTbody);
  }
  // Reuse your computeStockAlert if present, otherwise re-declare
  if (typeof computeStockAlert !== 'function') {
    window.computeStockAlert = function(stock) {
      if (stock >= 20) return 'Safe';
      if (stock >= 10) return 'Low';
      if (stock >= 1) return 'Critical';
      return 'Out of Stock';
    };
  }
  function normalizeProduct(product) {
    const id = Number.parseInt(product.Product_ID ?? product.product_id ?? 0, 10) || 0;
    const nameValue = (product.Product_Name ?? product.product_name ?? 'Unnamed Product').toString().trim();
    const description = (product.Description ?? product.description ?? '').toString().trim() || null;
    // Keep original Category string for display, but also compute a normalized form for comparisons
    const rawCategory = (product.Category ?? product.category ?? '').toString().trim();
    const subCategory = (product.Sub_category ?? product.sub_category ?? '').toString().trim() || null;
    const price = Number(product.Price ?? product.price ?? 0) || 0;
    const stock = Number.parseInt(product.Stock_Quantity ?? product.stock_quantity ?? 0, 10) || 0;
    // If low alert provided use it, otherwise compute
    const lowAlertRaw = (product.Low_Stock_Alert ?? product.low_stock_alert ?? '').toString().trim();
    const lowAlert = lowAlertRaw ? lowAlertRaw : computeStockAlert(stock);
    const image = product.Image ?? null;
    return {
      Product_ID: id,
      Product_Name: nameValue === '' ? 'Unnamed Product' : nameValue,
      Description: description,
      Category: rawCategory, // keep original display value
      Category_norm: normalizeCategoryForCompare(rawCategory), // for comparisons
      Sub_category: subCategory,
      Price: price,
      Stock_Quantity: Number.isInteger(stock) ? stock : 0,
      Low_Stock_Alert: lowAlert,
      Image: image,
    };
  }
  // Re-normalize incoming inventory array using the new normalizer
  inventory = Array.isArray(inventory) ? inventory.map(normalizeProduct) : [];
  function showEmptyState(message = 'There are no products in inventory yet.') {
    inventoryTbody.innerHTML = `
      <tr>
        <td colspan="8" class="text-center py-5 text-muted">
          <i class="bi bi-inbox" style="font-size:2.5rem;color:#d7b79a;display:block;margin-bottom:10px;"></i>
          ${message}
        </td>
      </tr>`;
  }
  function renderInventory(filter = '') {
    const filterNorm = normalizeCategoryForCompare(filter || '');
    const filtered = filter ? inventory.filter(p => p.Category_norm === filterNorm) : [...inventory];
    if (!filtered.length) {
      const message = filter ? 'No products found in this category.' : 'There are no products in inventory yet.';
      showEmptyState(message);
      return;
    }
    const rows = filtered.map(p => {
      const lowClass = ['low', 'critical'].includes((p.Low_Stock_Alert || '').toLowerCase()) ? 'stock-low' : '';
      const imageHtml = p.Image ? `<img src="${p.Image}" alt="${p.Product_Name}" style="max-width:50px; max-height:50px;">` : 'No Image';
      return `
      <tr data-id="${p.Product_ID}">
        <td>#${p.Product_ID}</td>
        <td>${imageHtml}</td>
        <td>${escapeHtml(p.Product_Name)}</td>
        <td>${escapeHtml(p.Category || 'Uncategorized')}</td>
        <td>₱${Number(p.Price).toFixed(2)}</td>
        <td>${p.Stock_Quantity}</td>
        <td class="${lowClass}">${p.Low_Stock_Alert}</td>
        <td>
          <button type="button" class="action-btn edit" title="Edit"><i class="bi bi-pencil"></i></button>
          <button type="button" class="action-btn delete" title="Delete"><i class="bi bi-trash"></i></button>
        </td>
      </tr>`;
    }).join('');
    inventoryTbody.innerHTML = rows;
  }
  // Simple escape to avoid injecting HTML from product names/descriptions
  function escapeHtml(s) {
    if (s === null || s === undefined) return '';
    return String(s)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }
  // Wire up the existing UI elements (categoryFilter, modal and form references)
  const categoryFilter = document.getElementById('category-filter');
  const modalEl = document.getElementById('productModal');
  const modal = modalEl ? new bootstrap.Modal(modalEl) : null;
  const modalTitle = document.getElementById('modalTitle');
  const productForm = document.getElementById('productForm');
  const productIdField = document.getElementById('productID');
  // When category filter changes, render using normalized comparison
  if (categoryFilter) {
    categoryFilter.addEventListener('change', () => renderInventory(categoryFilter.value));
  }
  // Add event delegation for edit/delete (same approach as before)
  document.addEventListener('click', async e => {
    if (!e.target.closest('#inventory-table')) return;
    const row = e.target.closest('tr');
    if (!row || !row.dataset.id) return;
    const id = Number.parseInt(row.dataset.id, 10);
    if (!Number.isInteger(id)) return;
    const editBtn = e.target.closest('.edit');
    const deleteBtn = e.target.closest('.delete');
    if (editBtn) {
      const product = inventory.find(item => item.Product_ID === id);
      if (!product) return;
      modalTitle.textContent = 'Edit Product';
      productIdField.value = product.Product_ID;
      productForm.Product_Name.value = product.Product_Name;
      productForm.Description.value = product.Description || '';
      // Ensure the select contains this category value (so the current category is selectable)
      ensureSelectHasOption(productForm.Category, product.Category || '');
      productForm.Category.value = product.Category || '';
      productForm.Sub_category.value = product.Sub_category || '';
      productForm.Price.value = product.Price;
      productForm.Stock_Quantity.value = product.Stock_Quantity;
      if (product.Image) {
        const img = document.getElementById('imagePreview');
        if (img) img.src = product.Image;
        const cur = document.getElementById('currentImage');
        if (cur) cur.style.display = 'block';
      } else {
        const cur = document.getElementById('currentImage');
        if (cur) cur.style.display = 'none';
      }
      if (modal) modal.show();
      return;
    }
    if (deleteBtn && confirm('Delete this product permanently?')) {
      try {
        // Attempt API call; keep your existing callInventoryApi if you have it
        if (typeof callInventoryApi === 'function') {
          await callInventoryApi('delete-product', { Product_ID: id });
        } else {
          // fallback: POST to current location
          await fetch(`${window.location.pathname}?action=delete-product`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ Product_ID: id })
          });
        }
        inventory = inventory.filter(item => item.Product_ID !== id);
        renderInventory(categoryFilter ? categoryFilter.value : '');
        if (typeof showSuccessMessage === 'function') showSuccessMessage('Product deleted successfully.');
      } catch (error) {
        alert(error.message || 'Unable to delete product.');
      }
    }
  });
  // Before saving, recompute Low_Stock_Alert and normalize Category field
  const saveBtn = document.getElementById('saveProductBtn');
  if (saveBtn) {
    saveBtn.addEventListener('click', async () => {
      // Build payload from the form (this mirrors your existing logic)
      const formData = new FormData(productForm);
      const payload = {
        Product_ID: formData.get('Product_ID') || null,
        Product_Name: (formData.get('Product_Name') || '').trim(),
        Description: (formData.get('Description') || '').trim() || null,
        Category: (formData.get('Category') || '').trim(),
        Sub_category: (formData.get('Sub_category') || '').trim() || null,
        Price: parseFloat(formData.get('Price')) || 0,
        Stock_Quantity: Math.max(0, parseInt(formData.get('Stock_Quantity'), 10) || 0),
      };
      if (!payload.Product_Name) return alert('Product name is required!');
      if (!payload.Category) return alert('Please select a category!');
      if (payload.Price <= 0) return alert('Invalid price!');
      payload.Low_Stock_Alert = computeStockAlert(payload.Stock_Quantity);
      const isUpdate = !!payload.Product_ID;
      try {
        saveBtn.disabled = true;
        saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';
        const action = isUpdate ? 'update-product' : 'create-product';
        const response = await fetch(`${window.location.pathname}?action=${action}`, {
          method: 'POST',
          body: formData
        });
        const text = await response.text();
        let result;
        try {
          result = JSON.parse(text);
        } catch (e) {
          console.error("Server response:", text);
          throw new Error("Server error. Open console and copy the red text.");
        }
        if (!response.ok || result.status !== 'success') {
          throw new Error(result.message || 'Hindi na-save.');
        }
        const savedId = isUpdate ? payload.Product_ID : (result.data?.Product_ID ?? Date.now());
        const savedImage = isUpdate
          ? (inventory.find(p => p.Product_ID == payload.Product_ID)?.Image || null)
          : (result.data?.Image || null);
        const savedProduct = normalizeProduct({
          ...payload,
          Product_ID: savedId,
          Image: savedImage
        });
        if (isUpdate) {
          const index = inventory.findIndex(p => p.Product_ID == payload.Product_ID);
          if (index !== -1) inventory[index] = savedProduct;
        } else {
          inventory.push(savedProduct);
        }
        inventory.sort((a, b) => a.Product_ID - b.Product_ID);
        renderInventory(categoryFilter ? categoryFilter.value : '');
        if (typeof showSuccessMessage === 'function') {
          showSuccessMessage(isUpdate ? 'Update Successfully' : 'Update Successfully');
        }
        if (modal) modal.hide();
        productForm.reset();
        const cur = document.getElementById('currentImage');
        if (cur) cur.style.display = 'none';
      } catch (err) {
        alert(err.message);
      } finally {
        saveBtn.disabled = false;
        saveBtn.innerHTML = 'Save Product';
      }
    });
  }
  // Initial render
  renderInventory();
})();
//<!-- correct: end of inventory script must be here -->
</script>
<script>
  async function loadStaffList() {
    const body = document.getElementById('staffTableBody');
    const searchInput = document.getElementById('searchStaffInput');
    if (!body) return;
    body.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Loading staff list...</td></tr>`;
    try {
      const resp = await fetch('?action=get_staff_list');
      if (!resp.ok) throw new Error(`Request failed (${resp.status})`);
      const result = await resp.json();
      if (result.status !== 'success' || !Array.isArray(result.data)) {
        body.innerHTML = `<tr><td colspan="6" class="text-center text-muted">${result.message || 'No staff data available.'}</td></tr>`;
        return;
      }
      const staff = result.data;
      const query = (searchInput?.value || '').toLowerCase().trim();
      const filtered = staff.filter(s => {
        if (!query) return true;
        return (s.Name || '').toLowerCase().includes(query) || (s.Username || '').toLowerCase().includes(query) || (s.Email || '').toLowerCase().includes(query);
      });
      if (!filtered.length) {
        body.innerHTML = `<tr><td colspan="6" class="text-center text-muted">No staff found.</td></tr>`;
        return;
      }
      body.innerHTML = filtered.map(s => `
        <tr data-user-id="${s.User_ID}">
          <td>${escapeHtml(s.Name)}</td>
          <td>${escapeHtml(s.Username)}</td>
          <td>${escapeHtml(s.Email)}</td>
          <td>${escapeHtml(s.Phonenumber || '')}</td>
          <td>${escapeHtml(s.Date_Created || '')}</td>
          <td>
            <div class="d-flex gap-2">
              <button class="btn btn-sm btn-secondary edit-staff-btn" data-id="${s.User_ID}">Edit</button>
              <button class="btn btn-sm btn-danger delete-staff-btn" data-id="${s.User_ID}">Delete</button>
            </div>
          </td>
        </tr>
      `).join('');
    } catch (err) {
      console.error('Failed to load staff list:', err);
      body.innerHTML = `<tr><td colspan="6" class="text-center text-danger">Unable to load staff data right now.</td></tr>`;
    }
  }

  document.getElementById('refreshStaffBtn')?.addEventListener('click', () => loadStaffList());
  document.getElementById('searchStaffBtn')?.addEventListener('click', () => loadStaffList());
  document.getElementById('searchStaffInput')?.addEventListener('keyup', (e) => { if (e.key === 'Enter') loadStaffList(); });

  // Delegate table row actions
  document.getElementById('staffTable')?.addEventListener('click', function (e) {
    const editBtn = e.target.closest('.edit-staff-btn');
    if (editBtn) {
      const id = parseInt(editBtn.dataset.id || 0);
      const row = document.querySelector(`#staffTable tbody tr[data-user-id="${id}"]`);
      if (!row) return;
      const name = row.children[0].textContent.trim();
      const username = row.children[1].textContent.trim();
      const email = row.children[2].textContent.trim();
      const phone = row.children[3].textContent.trim();
      document.getElementById('editUserId').value = id;
      document.getElementById('editName').value = name;
      document.getElementById('editUsername').value = username;
      document.getElementById('editEmail').value = email;
      document.getElementById('editPhone').value = phone;
      document.getElementById('editUserRole').value = 'Staff';
      bootstrap.Modal.getOrCreateInstance(document.getElementById('editStaffModal')).show();
      return;
    }
  });

  // Open Add Staff modal from Manage Staff page
  document.getElementById('openStaffModalBtn')?.addEventListener('click', () => bootstrap.Modal.getOrCreateInstance(document.getElementById('staffModal')).show());

  // Load staff list on initial manage-staff page render if active
  if (document.querySelector('.sidebar .nav-link[data-page="manage-staff"]')?.classList.contains('active')) {
    loadStaffList();
  }
</script>
<!-- ADD NEW STAFF -->
<!-- Floating Add New Staff button removed per your instruction.
     The staff modal and its scripts remain unchanged. -->
<div class="modal fade" id="staffModal" tabindex="-1">
  <div class="modal-dialog modal-lg">
    <div class="modal-content" style="border-radius:16px;">
      <div class="modal-header border-0">
        <h5 class="modal-title fw-bold">Add New Staff</h5>
        <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
      </div>
      <div class="modal-body">
        <div id="staffFormContainer">
          <form id="staffForm">
            <div class="mb-3"><label class="form-label">Name <span class="text-danger">*</span></label><input type="text" class="form-control" name="Name" required></div>
            <div class="row g-3">
              <div class="col-md-6"><label class="form-label">Username <span class="text-danger">*</span></label><input type="text" class="form-control" name="Username" required></div>
              <div class="col-md-6"><label class="form-label">Password <span class="text-danger">*</span></label><input type="password" class="form-control" name="Password" required></div>
            </div>
            <div class="row g-3 mt-2">
              <div class="col-md-6"><label class="form-label">Email <span class="text-danger">*</span></label><input type="email" class="form-control" name="Email" required></div>
              <div class="col-md-6"><label class="form-label">Phone Number</label><input type="text" class="form-control" name="Phonenumber" placeholder="09xxxxxxxxx" inputmode="numeric" pattern="[0-9]{11}" maxlength="11"></div>
            </div>
      <div class="mt-3">
        <label class="form-label">User Role <span class="text-danger">*</span></label>
        <!-- Hidden input so existing JS (f.User_Role.value) keeps working -->
        <input type="hidden" name="User_Role" value="Staff">
        <!-- Visible readonly field so the user sees the role is fixed -->
        <input type="text" class="form-control" value="Staff" readonly>
      </div>
          </form>
        </div>
        <div id="verificationContainer" style="display:none;">
          <p class="text-center mb-3" id="verificationMessage">Verification code sent. Enter the 6-digit code:</p>
          <input type="text" class="form-control text-center mx-auto" id="verificationCode" maxlength="6" placeholder="000000" style="max-width:150px;">
        </div>
      </div>
      <div class="modal-footer border-0">
        <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
        <button type="button" class="btn btn-success fw-bold" id="saveStaffBtn" data-mode="send">
          <span class="spinner-border spinner-border-sm me-2 d-none" role="status" id="staffSpinner"></span>
          <span id="saveStaffBtnLabel">Send Verification Code</span>
        </button>
      </div>
    </div>
    </div>
    </div>
    <!-- EDIT STAFF MODAL -->
    <div class="modal fade" id="editStaffModal" tabindex="-1">
      <div class="modal-dialog modal-lg">
        <div class="modal-content" style="border-radius:16px;">
          <div class="modal-header border-0">
            <h5 class="modal-title fw-bold">Edit Staff</h5>
            <button type="button" class="btn-close" data-bs-dismiss="modal"></button>
          </div>
          <div class="modal-body">
            <form id="editStaffForm">
              <input type="hidden" name="User_ID" id="editUserId">
              <div class="mb-3"><label class="form-label">Name <span class="text-danger">*</span></label><input type="text" class="form-control" name="Name" id="editName" required></div>
              <div class="row g-3">
                <div class="col-md-6"><label class="form-label">Username <span class="text-danger">*</span></label><input type="text" class="form-control" name="Username" id="editUsername" required></div>
                <div class="col-md-6"><label class="form-label">Email</label><input type="email" class="form-control" name="Email" id="editEmail" readonly></div>
              </div>
              <div class="row g-3 mt-2">
                <div class="col-md-6"><label class="form-label">Phone Number</label><input type="text" class="form-control" name="Phonenumber" id="editPhone" placeholder="09xxxxxxxxx" readonly></div>
                <div class="col-md-6"><label class="form-label">Role</label><input type="text" class="form-control" name="User_Role" id="editUserRole" value="Staff" readonly></div>
              </div>
              <div class="mt-3">
                <small class="text-muted"><i class="bi bi-info-circle"></i> Note: Email, phone number, and password cannot be changed here. Contact the administrator for these changes.</small>
              </div>
            </form>
          </div>
          <div class="modal-footer border-0">
            <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
            <button type="button" class="btn btn-danger" id="deleteStaffBtn">Delete</button>
            <button type="button" class="btn btn-success fw-bold" id="saveEditStaffBtn">Save changes</button>
          </div>
        </div>
      </div>
     </div>
    <script>
    {
  // Edit Staff Modal - Delete button handler
  const deleteStaffBtn = document.getElementById('deleteStaffBtn');
  if (deleteStaffBtn) {
    deleteStaffBtn.addEventListener('click', async function() {
      const id = parseInt(document.getElementById('editUserId').value || 0);
      const ownerUserId = <?php echo (int)($_SESSION['user_id'] ?? 0); ?>;
      if (id === ownerUserId) {
        alert('You cannot delete your own owner account.');
        return;
      }
      if (!confirm('Are you sure you want to remove this staff? This action cannot be undone.')) return;
      
      const deleteBtn = this;
      const originalText = deleteBtn.innerHTML;
      
      // Disable button and show loading state
      deleteBtn.disabled = true;
      deleteBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Deleting...';
      
      try {
        const fd = new FormData();
        fd.append('action', 'delete_staff');
        fd.append('User_ID', String(id));
        const resp = await fetch('?action=delete_staff', { method: 'POST', body: fd });
        const res = await resp.json().catch(() => null);
        if (!resp.ok || !res || res.status !== 'success') {
          const message = res?.message || `Unable to delete staff (code ${resp.status}).`;
          alert(message);
          deleteBtn.disabled = false;
          deleteBtn.innerHTML = originalText;
          return;
        }
        bootstrap.Modal.getInstance(document.getElementById('editStaffModal'))?.hide();
        showSuccessMessage(res.message || 'Staff removed successfully');
        await loadStaffList();
        deleteBtn.disabled = false;
        deleteBtn.innerHTML = originalText;
      } catch (err) { 
        console.error('Error removing staff:', err); 
        alert('Error removing staff. Check console.');
        deleteBtn.disabled = false;
        deleteBtn.innerHTML = originalText;
      }
    });
  }

  // Edit Staff Modal - Save changes button handler
  const saveEditStaffBtn = document.getElementById('saveEditStaffBtn');
  if (saveEditStaffBtn) {
    saveEditStaffBtn.addEventListener('click', async function() {
      const saveBtn = this;
      const id = parseInt(document.getElementById('editUserId').value || 0);
      const name = (document.getElementById('editName').value || '').trim();
      const username = (document.getElementById('editUsername').value || '').trim();
      const email = (document.getElementById('editEmail').value || '').trim();
      const phone = (document.getElementById('editPhone').value || '').trim();
      if (!name || !username) { alert('Name and username are required'); return; }
      if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) { alert('Invalid email address'); return; }
      if (phone && phone !== '' && !/^\d{11}$/.test(phone)) { alert('Phone must be 11 digits'); return; }
      
      // Disable button and show loading state
      saveBtn.disabled = true;
      const originalText = saveBtn.innerHTML;
      saveBtn.innerHTML = '<span class="spinner-border spinner-border-sm me-2"></span>Saving...';
      
      try {
        const fd = new FormData();
        fd.append('action', 'update_staff');
        fd.append('User_ID', String(id));
        fd.append('Name', name);
        fd.append('Username', username);
        fd.append('Email', email);
        fd.append('Phonenumber', phone);
        const resp = await fetch('?action=update_staff', { method: 'POST', body: fd });
        const res = await resp.json().catch(() => null);
        if (!resp.ok || !res || res.status !== 'success') { 
          const message = res?.message || `Unable to update staff (code ${resp.status}).`;
          alert(message); 
          saveBtn.disabled = false;
          saveBtn.innerHTML = originalText;
          return; 
        }
        bootstrap.Modal.getInstance(document.getElementById('editStaffModal'))?.hide();
        showSuccessMessage(res.message || 'Staff updated successfully');
        await loadStaffList();
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;
      } catch (err) {
        console.error('Failed to update staff:', err); 
        alert('Error updating staff. Check console.');
        saveBtn.disabled = false;
        saveBtn.innerHTML = originalText;
      }
    });
  }

  // Add Staff Modal code
  const staffModalEl = document.getElementById('staffModal');
  const staffForm = document.getElementById('staffForm');
  const saveBtn = document.getElementById('saveStaffBtn');
  const saveBtnLabel = document.getElementById('saveStaffBtnLabel');
  const spinner = document.getElementById('staffSpinner');
  const formContainer = document.getElementById('staffFormContainer');
  const verificationContainer = document.getElementById('verificationContainer');
  const verificationCode = document.getElementById('verificationCode');
  const verificationMessage = document.getElementById('verificationMessage');
  const openStaffBtn = document.getElementById('openStaffQuick');

  function setButtonState(mode, label) {
    if (!saveBtn) return;
    saveBtn.dataset.mode = mode;
    if (saveBtnLabel) saveBtnLabel.textContent = label;
  }

  function prepareStaffModal() {
    if (!staffModalEl || !staffForm || !formContainer || !verificationContainer) return;
    staffForm.reset();
    const roleField = staffForm.querySelector('[name="User_Role"]');
    if (roleField) roleField.value = 'Staff';
    formContainer.style.display = 'block';
    verificationContainer.style.display = 'none';
    if (verificationCode) verificationCode.value = '';
    if (spinner) spinner.classList.add('d-none');
    setButtonState('send', 'Send Verification Code');
  }

  openStaffBtn?.addEventListener('click', prepareStaffModal);
  staffModalEl?.addEventListener('show.bs.modal', prepareStaffModal);

  saveBtn?.addEventListener('click', async () => {
    if (!staffForm) return;
    const mode = saveBtn.dataset.mode || 'send';

    if (mode === 'verify') {
      const code = verificationCode?.value.trim() || '';
      if (!code) {
        alert('Please enter the verification code');
        return;
      }
      spinner.classList.remove('d-none');
      const fd = new FormData();
      fd.append('action', 'verify_staff');
      fd.append('verification_code', code);
      try {
        const response = await fetch('', { method: 'POST', body: fd });
        let res;
        try {
          res = await response.json();
        } catch (parseErr) {
          const text = await response.text();
          console.error('Verify Staff: Expected JSON response but got:', text);
          alert('Unexpected server response. Check console (F12) for details.');
          spinner.classList.add('d-none');
          return;
        }
        if (res.status === 'success') {
          showSuccessMessage(res.message);
          bootstrap.Modal.getInstance(staffModalEl)?.hide();
          staffForm.reset();
          if (verificationCode) verificationCode.value = '';
          formContainer.style.display = 'block';
          verificationContainer.style.display = 'none';
          setButtonState('send', 'Send Verification Code');
        } else {
          alert(res.message || 'Verification failed.');
        }
      } catch (error) {
        console.error('Verify staff request failed:', error);
        alert('An error occurred while verifying. Check the console (F12) for details.');
      } finally {
        spinner.classList.add('d-none');
      }
      return;
    }

    if (!staffForm.Name.value.trim() || !staffForm.Username.value.trim() || !staffForm.Password.value || !staffForm.Email.value.trim()) {
      alert('Fill up Name, Username, Password & Email!');
      return;
    }
    // Validate phone number if set: must be exactly 11 digits
    const phoneVal = (staffForm.Phonenumber?.value || '').trim();
    if (phoneVal !== '' && !/^[0-9]{11}$/.test(phoneVal)) {
      alert('Phone number must be exactly 11 numeric digits (e.g. 09123456789).');
      return;
    }
    spinner.classList.remove('d-none');
    const fd = new FormData();
    fd.append('action', 'add_staff');
    fd.append('Name', staffForm.Name.value.trim());
    fd.append('Username', staffForm.Username.value.trim());
    fd.append('Password', staffForm.Password.value);
    fd.append('Email', staffForm.Email.value.trim());
    fd.append('Phonenumber', staffForm.Phonenumber.value.trim());
    fd.append('User_Role', staffForm.User_Role.value);
    try {
      const response = await fetch('', { method: 'POST', body: fd });
      let res;
      try {
        res = await response.json();
      } catch (parseErr) {
        const text = await response.text();
        console.error('Add Staff: Expected JSON response but got:', text);
        alert('Unexpected server response. Check console (F12) for details.');
        spinner.classList.add('d-none');
        return;
      }
      if (res.status === 'verification_sent') {
        formContainer.style.display = 'none';
        verificationContainer.style.display = 'block';
        if (verificationMessage) verificationMessage.textContent = res.message || 'Verification code sent. Enter the 6-digit code:';
        verificationCode?.focus();
        setButtonState('verify', 'Verify');
        showSuccessMessage('Verification code sent to email.');
      } else {
        alert(res.message || 'Failed to send verification code.');
      }
    } catch (error) {
      console.error('Add staff request failed:', error);
      alert('An error occurred while sending the request. Check the console (F12) for details.');
    } finally {
      spinner.classList.add('d-none');
    }
  });
}
</script>
</body>
</html>
