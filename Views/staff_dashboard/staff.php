<?php
session_start();

// Check if user is logged in and is staff
if (!isset($_SESSION['user_role']) || strtolower($_SESSION['user_role']) !== 'staff') {
    // Redirect to landing page if not authenticated
    header('Location: ../../Views/landing/index.php');
    exit;
}

require_once __DIR__ . '/../../Controllers/StaffController.php';
require_once __DIR__ . '/../../Controllers/Security/DdosGuard.php';

if (isset($_GET['action']) || isset($_POST['action'])) {
    if (!DdosGuard::protect([
        'scope' => 'staff_dashboard',
        'max_requests' => (int)(getenv('STAFF_DDOS_MAX_REQUESTS') ?: 120),
        'window_seconds' => (int)(getenv('STAFF_DDOS_WINDOW_SECONDS') ?: 60),
        'block_seconds' => (int)(getenv('STAFF_DDOS_BLOCK_SECONDS') ?: 180),
        'request_methods' => ['GET', 'POST'],
        'response_type' => 'json',
        'message' => 'Too many staff requests detected. Please wait and try again.',
        'exit_on_block' => false,
    ])) {
        exit;
    }

    ob_start();
    $controller = new StaffController();
    $controller->handleAjax();
    exit;
}
// Load products for inventory
$controller = new StaffController();
$products = $controller->getInventoryProducts();

// Fetch staff info from database if logged in
$staffFullname = '';
$staffUsername = '';
$staffEmail = '';
$staffPhone = '';

if (isset($_SESSION['user_id'])) {
    $staffId = (int)$_SESSION['user_id'];
    require_once __DIR__ . '/../../Config.php';
    global $conn;
    
    $stmt = $conn->prepare("SELECT Name, Username, Email, Phonenumber FROM users WHERE User_ID = ? AND User_Role = 'Staff' LIMIT 1");
    $stmt->bind_param('i', $staffId);
    $stmt->execute();
    $result = $stmt->get_result();
    
    if ($row = $result->fetch_assoc()) {
        $staffFullname = $row['Name'] ?? '';
        $staffUsername = $row['Username'] ?? '';
        $staffEmail = $row['Email'] ?? '';
        $staffPhone = $row['Phonenumber'] ?? '';
    }
    $stmt->close();
}
?>
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Guillermo’s Staff Dashboard</title>

  <link rel="icon" type="image/x-icon" href="../../guillermos.ico">
  <link rel="shortcut icon" type="image/x-icon" href="../../guillermos.ico">

  <!-- Bootstrap 5 CDN -->
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/css/bootstrap.min.css" rel="stylesheet">
  <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css">
  <link href="https://fonts.googleapis.com/css2?family=Poppins:wght@400;500;600;700&family=Playfair+Display:wght@400;600;700&display=swap" rel="stylesheet">

  <style>
     /* Set page background to wallpaper.jpg located in bg/ */
     body {
       font-family:'Poppins',sans-serif;
       margin:0;
       padding:0;
       background-image: url('bg/wallpaper.jpg');
       background-size: cover;
       background-position: center;
       background-repeat: no-repeat;
       background-attachment: fixed;
       /* fallback color */
       background-color: #fefcf7;
       color: #222;
     }

    /* Header retains same color but blurs the background underneath */
    .header{
      background-color: rgba(107,79,63,0.72); /* #6B4F3F with transparency so backdrop-filter applies */
      color:#fff;
      padding:20px 40px;
      position:fixed;
      left:0;
      right:0;
      top:0;
      z-index:10;
      box-shadow:0 2px 10px rgba(0,0,0,.1);
      display:flex;
      justify-content:space-between;
      align-items:center;

      /* blur the background image behind the header while keeping header color */
      -webkit-backdrop-filter: blur(6px);
      backdrop-filter: blur(6px);
      /* ensure the semi-transparent header shows the blur */
      border-bottom: 1px solid rgba(0,0,0,0.06);
    }

    .header .title p{margin:0;font-size:1rem;}
    .content{
      margin-left:0;
      margin-top:100px;          
      padding:20px 40px;
      transition:margin-left .3s;
      /* keep content readable over wallpaper */
    }
    .card-custom{background:#d7b79a;color:#3b2c23;border:none;border-radius:10px;text-align:center;padding:1.5rem;}
    /* Match the card headings in Process Bulk to the dashboard card text color */
    .card-custom h5{margin-top:.5rem; color: #4d2e00; }

    /* QUICK ADD CARD */
    .quick-add {
  background: #fff;
  background-color: #f5e6d3;
  border: 1px solid #b9af7eff;
  border-radius: 16px; /* slightly more modern */
  padding: 1.75rem;
  text-align: center;
  box-shadow: 0 4px 15px rgba(0, 0, 0, 0.08);
  
  /* Smooth ease-out for entrance, ease-in for exit */
  transition: all 0.45s cubic-bezier(0.25, 0.8, 0.25, 1);
  
  /* Subtle inner glow on hover */
  position: relative;
  overflow: hidden;
  cursor: pointer;
}

/* Optional: add a soft colored top border that expands on hover */
.quick-add::before {
  content: '';
  position: absolute;
  top: 0;
  left: 0;
  right: 0;
  height: 4px;
  background: linear-gradient(90deg, #f4a261, #e76f51);
  transform: scaleX(0);
  transform-origin: left;
  transition: transform 0.5s cubic-bezier(0.4, 0, 0.2, 1);
}

/* Main hover state */
.quick-add:hover {
  transform: translateY(-6px) scale(1.02); /* lift + very subtle scale */
  box-shadow: 0 20px 40px rgba(0, 0, 0, 0.15);
  border-color: #e76f51;
}

/* Expand the accent bar */
.quick-add:hover::before {
  transform: scaleX(1);
}

/* Optional: add a subtle inner glow */
.quick-add::after {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 16px;
  padding: 2px;
  background: linear-gradient(135deg, #f4a26133, transparent);
  opacity: 0;
  transition: opacity 0.4s ease;
  pointer-events: none;
  mask: linear-gradient(#fff 0 0) padding-box, linear-gradient(#fff 0 0);
  mask-composite: exclude;
  -webkit-mask-composite: destination-out;
}

.quick-add:hover::after {
  opacity: 1;
}

.quick-add.premium:hover {
  transform: translateY(-8px) scale(1.03) perspective(1000px) rotateX(4deg);
  transition: all 0.6s cubic-bezier(0.22, 1, 0.36, 1);
}

    .btn-quick{
      background:#6f4e37;
      color:#fff;
      border-radius:30px;
      padding:10px 28px;
      font-weight:500;
    }
    
    .btn-quick:hover{
      background:#c1976b;
      color:#fff;
      transform:scale(1.03);
      transition:all .2s;}

    .product-card {
  border: 1px solid #eee;
  border-radius: 14px;
  overflow: hidden;
  cursor: pointer;
  text-align: center;
  position: relative;
  background: #fff;
  transition: all 0.5s cubic-bezier(0.23, 1, 0.32, 1);
  transform: translateZ(0); /* enables hardware acceleration */
  
  /* Subtle inner shadow for depth */
  box-shadow: 0 4px 15px rgba(0,0,0,0.06);
}

.product-card::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 4px;
  background: linear-gradient(90deg, #c98a5b, #e76f51);
  transform: scaleX(0);
  transform-origin: left;
  transition: transform 0.55s cubic-bezier(0.4, 0, 0.2, 1);
}

.product-card img {
  width: 100%;
  height: 180px;             /* increased for better visuals */
  object-fit: cover;
  transition: transform 0.7s cubic-bezier(0.23, 1, 0.32, 1);
}

.product-card .price {
  font-weight: bold;
  color: #6f4e37;
  font-size: 1.1em;
  transition: all 0.4s ease;
}

/* HOVER MAGIC */
.product-card:hover {
  transform: translateY(-10px) translateZ(30px);
  box-shadow: 0 24px 50px rgba(0,0,0,0.18);
  border-color: #e76f51;
}

.product-card:hover::before {
  transform: scaleX(1);
}

.product-card:hover img {
  transform: scale(1.08);   /* gentle zoom on the image */
}

.product-card:hover .price {
  color: #e76f51;
  transform: scale(1.1);
}

/* Optional: tiny 3D tilt on mouse move (very premium feel) */
.product-card.tilt {
  transition: all 0.6s cubic-bezier(0.23, 1, 0.32, 1);
  transform: perspective(1000px) rotateX(0deg) rotateY(0deg) translateZ(0);
}

.product-card.tilt:hover {
  transform: perspective(1000px) rotateX(6deg) rotateY(-4deg) translateY(-8px) translateZ(40px);
}

.product-card.product-card-out {
  cursor: not-allowed;
  filter: grayscale(0.55);
  opacity: 0.6;
  transform: none !important;
  box-shadow: 0 4px 12px rgba(0,0,0,0.06);
  border-color: #ddd;
}

.product-card.product-card-out::after {
  content: 'Out of stock';
  position: absolute;
  inset: 0;
  display: flex;
  align-items: center;
  justify-content: center;
  font-weight: 700;
  font-size: 1rem;
  letter-spacing: 0.04em;
  color: #fff;
  background: rgba(0,0,0,0.55);
  border-radius: 14px;
  text-transform: uppercase;
  pointer-events: none;
}

/* Keep your table style untouched */
.order-summary-table th {
  background: #6f4e37;
  color: #fff;
}

/* Make order summary scrollable after 4 items */
#order-items-container {
  max-height: 200px; /* Approx height for 4 items */
  overflow-y: auto;
}

/* Flex row for Change and Total Amount */
.order-total-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-top: 1rem;
}

.order-total-row .total-amount {
  text-align: left;
  font-weight: 600;
}

.order-total-row .change-display {
  text-align: right;
  font-weight: 600;
}

/* === Adjustments to enlarge stat cards while keeping them on a single horizontal line === */
#dashboardStats {
  display: flex;              /* ensure flex layout */
  flex-wrap: nowrap;         /* keep all stat cards on one horizontal line */
  gap: 1rem;                 /* spacing between cards */
  overflow-x: auto;         /* allow horizontal scrolling on small screens */
  padding-bottom: 6px;
}

/* larger stat-card */
.stat-card {
  background: linear-gradient(135deg, #d7b79a 0%, #c1976b 100%);
  color: #4d2e00;
  border: none;
  border-radius: 16px;
  min-height: 150px;        /* increased height */
  min-width: 280px;         /* increased width */
  padding: 1.25rem 1.25rem; /* more interior space */
  transition: box-shadow 0.3s, transform 0.3s;
  box-shadow: 0 6px 22px rgba(111,78,55,0.10);
  cursor: pointer;
  display: flex;
  align-items: center;
}

/* bigger icon area */
.stat-card .icon-wrapper {
  width: 72px;
  height: 72px;
  display: flex;
  align-items: center;
  justify-content: center;
  background: linear-gradient(135deg, #f4a261 0%, #e76f51 100%);
  border-radius: 14px;
  margin-right: 14px;
  color: #fff;
  box-shadow: 0 4px 14px rgba(231,111,81,0.14);
}

/* larger icon size */
.stat-card .icon-wrapper i {
  font-size: 2.6rem;
}

/* larger metric number */
.stat-card .fs-4 {
  font-size: 1.9rem !important;
  line-height: 1;
}

/* label tweak */
.stat-card h6 {
  font-size: 1.05rem;
  margin-bottom: 6px;
  font-weight: 700;
}

/* ensure cards don't wrap content */
.stat-card > div:last-child { display: flex; flex-direction: column; justify-content: center; align-items: flex-start; }

/* small screens — allow scrolling but keep single row */
@media (max-width: 1199px) {
  #dashboardStats { gap: .75rem; }
  .stat-card { min-width: 240px; min-height:140px; }
  .stat-card .icon-wrapper { width:60px; height:60px; }
  .stat-card .icon-wrapper i { font-size:2.2rem; }
  .stat-card .fs-4 { font-size:1.6rem !important; }
}

/* Maintain tighter spacing around the stat cards on the dashboard */
#dashboardStats { margin-top: -8px; }

/* The rest of your CSS remains unchanged (kept intact) */

/* QUICK NOTE: The remaining styles from the original file are preserved below, unchanged. */

/* ─── Gorgeous Animated Inline Order Card ─── */
#inlineOrderCard {
  display: block;
  margin-top: 2rem;
  background: #ffffff;
  background: linear-gradient(135deg, #fff 0%, #fdf8f4 100%);
  border-radius: 20px;
  padding: 2.5rem 2rem;
  border: 1px solid #e8d9cc;
  box-shadow: 
    0 8px 30px rgba(111, 78, 55, 0.1),
    0 0 0 1px rgba(231, 111, 81, 0.08);
  position: relative;
  overflow: hidden;
  opacity: 1;
  transform: translateY(0) scale(1);
  transition: all 0.4s ease;
}

#inlineOrderCard.show {
  display: block;
  opacity: 1;
  transform: translateY(0) scale(1);
}

/* Beautiful top accent bar that slides in */
#inlineOrderCard::before {
  content: '';
  position: absolute;
  top: 0; left: 0; right: 0;
  height: 6px;
  background: linear-gradient(90deg, #f4a261, #e76f51, #d95f3e);
  transform: scaleX(0);
  transform-origin: left;
  transition: transform 0.8s cubic-bezier(0.4, 0, 0.2, 1);
  transition-delay: 0.2s;
}

#inlineOrderCard.show::before {
  transform: scaleX(1);
}

/* Subtle inner glow on appear */
#inlineOrderCard::after {
  content: '';
  position: absolute;
  inset: 0;
  border-radius: 20px;
  background: radial-gradient(circle at 30% 30%, rgba(244, 162, 97, 0.15), transparent 60%);
  opacity: 0;
  transition: opacity 0.9s ease;
  pointer-events: none;
}

#inlineOrderCard.show::after {
  opacity: 1;
}

/* Optional: tiny bounce-in for extra joy */
#inlineOrderCard.bounce-in.show {
  animation: bounceIn 0.9s cubic-bezier(0.68, -0.55, 0.27, 1.55);
}


@keyframes bounceIn {
  0%   { opacity: 0; transform: translateY(60px) scale(0.9); }
  60%  { opacity: 1; transform: translateY(-15px) scale(1.03); }
  100% { transform: translateY(0) scale(1); }
}

/* Scrollable product list */
.product-list-wrapper{max-height:500px;overflow-y:auto;padding-right:8px;}
.product-list-wrapper::-webkit-scrollbar{width:6px;}
.product-list-wrapper::-webkit-scrollbar-thumb{background:#c1976b;border-radius:3px;}

/* Category filter */
.category-filter{margin-bottom:1rem;}
.category-filter select{width:100%;max-width:300px;}

    /* Pending Orders Table Enhancements */
#recentOrdersCard .table tbody tr {
  transition: background-color 0.2s ease;
}
#recentOrdersCard .table tbody tr:hover {
  background-color: #fffbf7;
}
#recentOrdersCard .btn-success {
  transition: all 0.3s ease;
}
#recentOrdersCard .btn-success:hover {
  transform: scale(1.05);
  box-shadow: 0 4px 12px rgba(40, 167, 69, 0.3);
}
#recentOrdersCard .spinner-border {
  animation: spin 1s linear infinite;
}
@keyframes spin {
  0% { transform: rotate(0deg); }
  100% { transform: rotate(360deg); }
}

    /* Inventory Table Enhancements */
#inventory-section {
  animation: fadeIn 0.6s ease forwards;
  opacity: 0;
}#inventory-section h4 {
  font-weight: 700;
  color: #4d2e00;
  letter-spacing: 0.5px;
  position: relative;
}
#inventory-section h4::after {
  content: '';
  display: block;
  width: 50px;
  height: 3px;
  background: #f9c74f;
  margin-top: 5px;
  border-radius: 2px;
}

.inventory-table {
  border-collapse: separate;
  border-spacing: 0 8px;
  overflow: hidden;
}
.inventory-table thead th {
  background: #e9c9a4d3;
  color: #4d2e00;
  font-weight: 600;
  border: none;
}
.inventory-table tbody tr {
  background: #fff;
  border-radius: 6px;
  transition: transform 0.2s, box-shadow 0.2s;
  cursor: default;
}
.inventory-table tbody tr:hover {
  transform: translateY(-3px);
  box-shadow: 0 6px 12px rgba(0,0,0,0.08);
}

.stock-badge {
  padding: 4px 8px;
  border-radius: 12px;
  display: inline-block;
  min-width: 28px;
  text-align: center;
  transition: all 0.3s;
}
.stock-badge.text-danger {
  background: #ffe3e3;
  color: #d32f2f;
}
.stock-badge.text-warning {
  background: #fff4e5;
  color: #f57c00;
}
.stock-badge.text-success {
  background: #e6f4ea;
  color: #388e3c;
}

.badge.bg-danger {
  background: #d32f2f !important;
  color: #fff;
  font-weight: 500;
}
.badge.bg-warning {
  background: #f57c00 !important;
  color: #fff;
  font-weight: 500;
}
.badge.bg-success {
  background: #388e3c !important;
  color: #fff;
  font-weight: 500;
}

.empty-state {
  text-align: center;
  color: #999;
  margin-top: 30px;
  font-size: 18px;
  animation: fadeInUp 0.5s ease forwards;
}
.empty-state i {
  font-size: 50px;
  color: #f9c74f;
  margin-bottom: 10px;
}

@keyframes fadeIn {
  0% { opacity: 0; transform: translateY(10px); }
  100% { opacity: 1; transform: translateY(0); }
}
@keyframes fadeInUp {
  0% { opacity: 0; transform: translateY(15px); }
  100% { opacity: 1; transform: translateY(0); }
}

/* Dropdown animation */
.dropdown-menu {
    opacity: 0;
    transform: translateY(-10px);
    transition: opacity 0.3s ease, transform 0.3s ease;
    display: block;
    visibility: hidden;
    min-width: 280px;
    padding: 0.5rem 0;
    border-radius: 0.5rem;
    box-shadow: 0 5px 15px rgba(0,0,0,0.2);
    background-color: #fff;
}
.dropdown.show .dropdown-menu {
    opacity: 1;
    transform: translateY(0);
    visibility: visible;
}

/* Bell animation */
#notifBell {
  display: inline-block;
  transform-origin: 50% 40%;
}
.bell-shake { animation: bell-wiggle 1s ease-in-out infinite; }
#notifCount { animation: pulse 1.6s infinite; }

@keyframes bell-wiggle {
  0%   { transform: rotate(0deg); }
  15%  { transform: rotate(-12deg); }
  30%  { transform: rotate(10deg); }
  45%  { transform: rotate(-8deg); }
  60%  { transform: rotate(6deg); }
  75%  { transform: rotate(-4deg); }
  100% { transform: rotate(0deg); }
}
@keyframes pulse {
    0% { transform: scale(1); }
    50% { transform: scale(1.2); }
    100% { transform: scale(1); }
}

/* Individual notification items */
.dropdown-item {
    display: flex;
    flex-direction: column;
    padding: 0.5rem 1rem;
    margin: 0.2rem 0;
    border-radius: 0.5rem;
    transition: background 0.2s ease;
}
.dropdown-item:hover { background-color: #ffe6e6; }
.dropdown-item strong { color: #d9534f; font-size: 0.95rem; }
.dropdown-item span { font-size: 0.85rem; color: #555; }
.dropdown-item.text-muted { text-align: center; font-style: italic; color: #888; }

/* Floating logo: improved font and white color as requested */
.floating-logo {
    font-family: 'Playfair Display', 'Franklin Gothic Medium', 'Arial Narrow', Arial, sans-serif;
    font-size: 2rem;
    color: #ffffff; /* changed to white */
    display: inline-block;
    animation: float 3s ease-in-out infinite;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-shadow: 0 2px 6px rgba(0,0,0,0.35);
  }
@keyframes float {
  0% { transform: translateY(0px); }
  50% { transform: translateY(-8px); }
  100% { transform: translateY(0px); }
}

/* === Hamburger menu + right-to-left dropdown === */
.menu-wrapper { position: relative; display: inline-block; z-index: 50; }
#menuBtn { background: transparent; border: none; color: #fff; font-size: 1.3rem; padding: 6px 10px; border-radius: 8px; cursor: pointer; }
#menuBtn:focus { outline: none; box-shadow: 0 0 0 3px rgba(255,255,255,0.06); }
#menuPanel {
  position: absolute;
  top: calc(100% + 8px);
  right: 0;
  min-width: 220px;
  background: #fff;
  border-radius: 10px;
  box-shadow: 0 10px 30px rgba(0,0,0,0.12);
  padding: 8px;
  transform-origin: right center;
  transform: translateX(8px) scale(.98);
  opacity: 0;
  visibility: hidden;
  transition: transform 220ms cubic-bezier(.2,.9,.2,1), opacity 180ms ease;
}
#menuPanel.show { transform: translateX(0) scale(1); opacity: 1; visibility: visible; }
.menu-panel-btn {
  display: flex; align-items: center; gap: 10px; width: 100%; text-align: left; padding: 8px 10px; border-radius: 8px; border: none; background: transparent; color: #333; cursor: pointer; font-weight: 600;
}
.menu-panel-btn i { color: #6f4e37; font-size: 1.05rem; }
.menu-panel-btn:hover { background: #f3e8df; color: #6b4226; }
#menuPanel { z-index: 1050; }
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
  </style>

  <!-- === RESPONSIVE IMPROVEMENTS ===
       These additions make the layout behave consistently on mobile.
       - Stat cards wrap on small screens (so they don't overflow/overlap).
       - Inline order card becomes a full-screen sheet on narrow viewports.
       - Product grid becomes 2 columns (or 1 column on very small screens).
       - Header and paddings are reduced to avoid "exploding" layouts.
       - Menu panel converts to a full-width bottom sheet on mobile.
       - Inventory table remains scrollable horizontally if necessary.
  -->
  <style>
    /* General smaller spacing on small devices */
    @media (max-width: 991px) {
      .header { padding: 14px 18px; }
      .content { margin-top: 86px; padding: 16px 18px; }
      .floating-logo { font-size: 1.6rem; }
      .btn-quick { padding: 8px 18px; font-size: 0.95rem; }
    }

    /* Make stat cards wrap instead of forcing horizontal overflow */
    @media (max-width: 992px) {
      #dashboardStats {
        flex-wrap: wrap !important;
        overflow-x: visible !important;
      }
      .stat-card { min-width: unset; width: calc(50% - 0.5rem); margin-bottom: 0.75rem; }
      .stat-card .icon-wrapper { width: 56px; height:56px; }
      .stat-card .fs-4 { font-size: 1.4rem !important; }
    }

    /* On very small phones, stack stat cards full width */
    @media (max-width: 576px) {
      .stat-card { width: 100% !important; padding: 12px; min-height: 110px; }
      .stat-card .icon-wrapper { width:48px; height:48px; margin-right: 10px; }
      .stat-card .icon-wrapper i { font-size: 1.6rem; }
      .header .title p { font-size: 0.9rem; }
      .content { padding: 12px; margin-top: 80px; }
      .floating-logo { font-size: 1.3rem; }
    }

    /* Product grid responsiveness */
    @media (max-width: 991px) {
      /* Make product-items follow a 2-column layout */
      #productGrid { display: flex; flex-wrap: wrap; margin-left: -12px; margin-right: -12px; }
      #productGrid .product-item { flex: 0 0 50%; max-width: 50%; padding-left: 12px; padding-right: 12px; margin-bottom: 16px; box-sizing: border-box; }
      .product-card img { height: 150px; }
    }
    @media (max-width: 576px) {
      #productGrid .product-item { flex: 0 0 100%; max-width: 100%; }
      .product-card img { height: auto; max-height: 220px; }
      .product-card { border-radius: 12px; }
    }

    /* Inline order card becomes a mobile sheet */
    @media (max-width: 768px) {
      #inlineOrderCard {
        position: fixed !important;
        left: 0 !important;
        right: 0 !important;
        top: 56px !important;
        bottom: 0 !important;
        margin: 0 !important;
        border-radius: 0 !important;
        padding: 14px !important;
        overflow-y: auto !important;
        z-index: 2000;
      }
      #inlineOrderCard .order-modal-content { padding: 0; border-radius: 0; }
      #inlineOrderCard .col-lg-8, #inlineOrderCard .col-lg-4, #inlineOrderCard .col-lg-6 { width: 100%; display: block; }
      #inlineOrderCard .order-summary-table th, #inlineOrderCard .order-summary-table td { font-size: 0.88rem; }
      #order-items-container { max-height: 160px; }
    }

    /* Menu panel becomes full-width bottom anchored sheet for small screens */
    @media (max-width: 576px) {
      #menuPanel {
        position: fixed;
        left: 8px;
        right: 8px;
        top: 56px;
        min-width: unset;
        border-radius: 12px;
        max-height: calc(100vh - 72px);
        overflow-y: auto;
        transform: translateY(0) scale(1);
        opacity: 1;
        visibility: hidden;
        padding: 8px;
      }
      #menuPanel.show { visibility: visible; }
      .menu-panel-btn { padding: 12px; font-size: 1rem; }
    }

    /* Staff dropdown repositioning on small screens so it doesn't overflow */
    @media (max-width: 480px) {
      .user-dropdown-menu.staff-dropdown-menu {
        right: 8px !important;
        left: auto !important;
        width: calc(100% - 32px);
      }
    }

    /* Ensure the small buttons and inputs wrap nicely on tiny screens */
    @media (max-width: 420px) {
      .btn-quick { padding: 8px 12px; font-size: 0.9rem; }
      .category-filter select, #inventoryCategoryFilter { max-width: 100%; }
      .order-total-row { flex-direction: column; gap: 6px; align-items: flex-start; }
      .order-total-row .change-display { text-align: left; }
    }

    /* Advance Reservation stat cards responsiveness */
    @media (max-width: 991px) {
      #advance-reservation-section .row.mb-4 { display: flex; flex-wrap: wrap; }
      #advance-reservation-section .row.mb-4 > .col-md-3 { flex: 0 0 50%; max-width: 50%; margin-bottom: 1rem; }
    }
    @media (max-width: 576px) {
      #advance-reservation-section .row.mb-4 > .col-md-3 { flex: 0 0 100%; max-width: 100%; }
    }
    /* Minor accessibility: increase touch target for small interactive elements */
    @media (max-width: 576px) {
      .menu-panel-btn, .icon-btn, .profile-btn { padding: 12px; }
    }
  </style>

</head>
<body>

  <!-- Topbar-inserting liveclock, changes, 11-17-25 -->
  <div class="header">
  <div class="d-flex align-items-center w-100 justify-content-between">
    <div class="title">
      <p>WELCOME BACK, Staff</p>
      <p id="datetime" style="font-size:0.85rem;color:#fff;margin-top:4px;"></p>
    </div>
    <div class="d-flex align-items-center gap-3">
      <!-- Replaced the four buttons with a three-line (hamburger) icon.
           When clicked, the panel expands right-to-left and contains the same nav items.
           IDs for nav-dashboard/process-bulk/advance-reservation/inventory are preserved. -->
      <div class="menu-wrapper">
        <button id="menuBtn" aria-expanded="false" aria-controls="menuPanel" title="Menu">
          <i class="bi bi-list"></i>
        </button>
        <div id="menuPanel" role="menu" aria-hidden="true">
          <button class="menu-panel-btn" id="nav-dashboard" onclick="document.getElementById('menuPanel').classList.remove('show'); showContent('dashboard')">
            <i class="bi bi-speedometer2"></i> <span>Dashboard</span>
          </button>
          <button class="menu-panel-btn" id="nav-process-bulk" onclick="document.getElementById('menuPanel').classList.remove('show'); showContent('process-bulk')">
            <i class="bi bi-box"></i> <span>Process Bulk</span>
          </button>
          <button class="menu-panel-btn" id="nav-advance-reservation" onclick="document.getElementById('menuPanel').classList.remove('show'); showContent('advance-reservation')">
            <i class="bi bi-calendar-check"></i> <span>Advance Reservation</span>
          </button>
          <button class="menu-panel-btn" id="nav-inventory" onclick="document.getElementById('menuPanel').classList.remove('show'); showContent('inventory')">
            <i class="bi bi-archive"></i> <span>Products</span>
          </button>
        </div>
      </div>

      <div class="d-flex align-items-center gap-2">
        <div class="dropdown">
          <i class="bi bi-bell position-relative" style="font-size:1.5rem;cursor:pointer;margin-right: 0px;" id="notifBell" data-bs-toggle="dropdown" aria-expanded="false" title="Notifications">
            <span class="position-absolute top-0 start-100 translate-middle badge rounded-pill bg-danger" id="notifCount" style="display:none;">0</span>
          </i>
          <ul id="notifList" class="dropdown-menu dropdown-menu-end p-2" aria-labelledby="notifBell" style="min-width:250px; max-height:300px; overflow-y:auto;">
            <li class="dropdown-item text-muted">Loading notifications...</li>
          </ul>
        </div>
        <!-- STAFF PROFILE ICON & DROPDOWN -->
        <div class="user-profile-wrapper">
          <button class="icon-btn profile-btn" id="staffUserIcon" style="font-size:30px; background: none; border: none; box-shadow: none;">👤</button>
          <div class="user-dropdown-menu staff-dropdown-menu" id="staffUserDropdown" style="min-width: 270px; box-shadow: 0 4px 24px rgba(0,0,0,0.10); border-radius: 16px; background: #fff; padding: 0.5rem 0; display: none; position: absolute; right: 0; top: 48px; z-index: 999;">
            <div class="dropdown-header" style="font-weight:600; color:#6B4F3F; font-size:1.1rem; padding: 12px 24px 4px;">Staff</div>
            <hr style="margin: 0.5rem 0; border-color: #f3e8df;">
            <a href="#" class="dropdown-link d-flex align-items-center gap-2" onclick="openStaffProfileModal(); return false;" style="padding: 10px 24px; color: #4d2e00; font-weight:500; font-size:1rem; text-decoration:none;">
              <i class="bi bi-person-fill" style="color:#6f4e37; font-size:1.3rem;"></i> My Profile
            </a>
            <hr style="margin: 0.5rem 0; border-color: #f3e8df;">
            <a href="../../index.php" class="dropdown-link d-flex align-items-center gap-2 text-danger" style="padding: 10px 24px; font-weight:500; font-size:1rem; text-decoration:none;">
              <i class="bi bi-box-arrow-right" style="color:#e76f51; font-size:1.3rem;"></i> Logout
            </a>
          </div>
        </div>
      </div>
    </div>
  </div>
</div>
  



  <!-- Content -->
  <div class="content">

    <!-- Floating Logo inside dashboard -->
    <div class="floating-logo mb-4" style="font-size:2rem;">Guillermo's Cafe</div>

    <!-- Dashboard Section -->
    <div id="dashboard-section">

      <!-- Stat Cards Row -->
      <div class="row mb-4 g-3 justify-content-center" id="dashboardStats">
  <div class="col-lg-2 col-md-4 col-sm-6">
    <div class="card stat-card shadow-sm d-flex flex-row align-items-center p-3 h-100" style="min-width:280px; background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%); color: #4d2e00; border: none; border-radius: 16px;">
      <div class="icon-wrapper me-3" style="background: linear-gradient(135deg, #f4a261 0%, #e76f51 100%); border-radius: 14px; color: #fff;">
        <i class="bi bi-hourglass-split animate__animated animate__pulse"></i>
      </div>
      <div>
        <h6 class="mb-1 fw-bold">Total Pending</h6>
        <div class="fs-4 fw-bold" id="pendingCountCard">0</div>
      </div>
    </div>
  </div>
  <div class="col-lg-2 col-md-4 col-sm-6">
    <div class="card stat-card shadow-sm d-flex flex-row align-items-center p-3 h-100" style="min-width:280px; background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%); color: #4d2e00; border: none; border-radius: 16px;">
      <div class="icon-wrapper me-3" style="background: linear-gradient(135deg, #f4a261 0%, #e76f51 100%); border-radius: 14px; color: #fff;">
        <i class="bi bi-check2-circle animate__animated animate__pulse"></i>
      </div>
      <div>
        <h6 class="mb-1 fw-bold">Completed Today</h6>
        <div class="fs-4 fw-bold" id="completedCountCard">0</div>
      </div>
    </div>
  </div>
  <div class="col-lg-2 col-md-4 col-sm-6">
    <div class="card stat-card shadow-sm d-flex flex-row align-items-center p-3 h-100" style="min-width:280px; background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%); color: #4d2e00; border: none; border-radius: 16px;">
      <div class="icon-wrapper me-3" style="background: linear-gradient(135deg, #f4a261 0%, #e76f51 100%); border-radius: 14px; color: #fff;">
        <i class="bi bi-calendar-check animate__animated animate__pulse"></i>
      </div>
      <div>
        <h6 class="mb-1 fw-bold">Pending Reservation Orders</h6>
        <div class="fs-4 fw-bold" id="reserveCountCard">0</div>
      </div>
    </div>
  </div>
  <div class="col-lg-2 col-md-4 col-sm-6">
    <div class="card stat-card shadow-sm d-flex flex-row align-items-center p-3 h-100" style="min-width:280px; background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%); color: #4d2e00; border: none; border-radius: 16px;">
      <div class="icon-wrapper me-3" style="background: linear-gradient(135deg, #f4a261 0%, #e76f51 100%); border-radius: 14px; color: #fff;">
        <i class="bi bi-bag-check animate__animated animate__pulse"></i>
      </div>
      <div>
        <h6 class="mb-1 fw-bold">Online Orders</h6>
        <div class="fs-4 fw-bold" id="onlineCountCard">0</div>
      </div>
    </div>
  </div>
  <div class="col-lg-2 col-md-4 col-sm-6">
    <div class="card stat-card shadow-sm d-flex flex-row align-items-center p-3 h-100" style="min-width:280px; background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%); color: #4d2e00; border: none; border-radius: 16px;">
      <div class="icon-wrapper me-3" style="background: linear-gradient(135deg, #f4a261 0%, #e76f51 100%); border-radius: 14px; color: #fff;">
        <i class="bi bi-currency-exchange animate__animated animate__pulse"></i>
      </div>
      <div>
        <h6 class="mb-1 fw-bold">Total Revenue</h6>
        <div class="fs-4 fw-bold" id="revenueCard">₱0.00</div>
      </div>
    </div>
  </div>
</div>

      <!-- Pending Orders Section -->
      <div class="card shadow-sm mb-4" id="recentOrdersCard">
        <div class="card-header gradient-brown fw-bold fs-5">
          <i class="bi bi-hourglass-split me-2"></i>Pending Orders
          <small class="float-end" style="font-size:0.85rem;font-weight:normal;opacity:0.9;">
            <i class="bi bi-arrow-clockwise"></i> Auto-refresh every 30 seconds
          </small>
        </div>
        <div class="card-body p-0 table-responsive">
          <div class="table-responsive">
            <table class="table table-sm mb-0">
              <thead>
                <tr>
                  <th>Customer</th>
                  <th>Type</th>
                  <th>Status</th>
                  <th>Total</th>
                  <th>Date & Items</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="recentOrdersList">
                <tr>
                  <td colspan="6" class="text-center text-muted">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    Loading pending orders...
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Inline Order Card (Modal Style) -->
      <div id="inlineOrderCard" class="order-modal show">
        <div class="order-modal-content animate__animated animate__fadeInRight">
          <h5 class="mb-3">Walk-In / Takeout Orders</h5>
          <div class="row">
            <!-- LEFT – Product Grid + Filter -->
            <div class="col-lg-8">
              <?php // $products is provided by ProductController ?>
              <!-- Category Filter -->
              <div class="category-filter d-flex align-items-center mb-3">
                  <label class="me-2 fw-semibold">Category:</label>
                    <select id="categoryFilter" class="form-select category-filter">
                      <option value="all">All</option>
                      <option value="pasta">Pasta</option>
                      <option value="ricemeals">Rice Meals</option>
                      <option value="coffeebeverages">Coffee Beverages</option>
                      <option value="noncoffee">NonCoffee</option>
                      <option value="pizza">Pizza</option>
                      <option value="cakes">Cakes</option>
                      <option value="sandwichessalad">Sandwiches & Salad</option>
                      <option value="lemonseries">Lemon Series</option>
                      <option value="breads">Breads</option>
                      <option value="piecookiesbar">Pie, Cookies & Bar</option>
                      <option value="milktea">Milktea</option>
                      <option value="fruitsyogurt">Fruits & Yogurt</option>
                    </select>
              </div>
              <!-- Display products -->
                <div class="product-list-wrapper">
                  <div class="row g-3" id="productGrid">
                        <?php foreach ($products as $p): 
                          $qCat = strtolower(str_replace([' ', '&', '-'], '', $p['Category']));
                          $stockQty = isset($p['Stock_Quantity']) ? (int)$p['Stock_Quantity'] : 0;
                          $cardClasses = 'product-card' . ($stockQty <= 0 ? ' product-card-out' : '');
                        ?>
                          <div class="col-md-4 product-item" data-category="<?php echo $qCat; ?>" data-product-id="<?= (int)$p['Product_ID'] ?>">
                              <div class="<?= $cardClasses ?>"
                                data-product-id="<?php echo (int)$p['Product_ID']; ?>"
                                data-name="<?php echo htmlspecialchars($p['Product_Name']); ?>"
                                data-price="<?php echo (float)$p['Price']; ?>"
                                data-stock="<?= $stockQty ?>">
                                  <?php if (!empty($p['Image'])): 
                                    $finfo = new finfo(FILEINFO_MIME_TYPE);
                                    $mime = $finfo->buffer($p['Image']);
                                    $mime = $mime ?: 'image/jpeg';
                                    ?>
                                  <img src="data:<?= $mime ?>;base64,<?= base64_encode($p['Image']) ?>" 
                                          class="img-fluid" 
                                          alt="<?= htmlspecialchars($p['Product_Name']) ?>"
                                          style="height:180px; width:100%; object-fit:cover;">
                                  <?php else: ?>
                                      <img src="images/default.jpg" 
                                          class="img-fluid" 
                                          alt="No Image"
                                          style="height:180px; width:100%; object-fit:cover;">
                                  <?php endif; ?>
                                  <div class="p-2">
                                      <h6><?php echo htmlspecialchars($p['Product_Name']); ?></h6>
                                      <p class="price">₱<?php echo number_format($p['Price'], 2); ?></p>
                                      <?php if ($stockQty <= 0): ?>
                                        <span class="badge bg-dark px-3 py-2">Out of stock</span>
                                      <?php endif; ?>
                                  </div>
                              </div>
                          </div>
                      <?php endforeach; ?>
                  </div>
              </div>
            </div>
            <!-- RIGHT – Order Summary -->
            <div class="col-lg-4">
              <div class="card shadow-sm p-3">
                <h6>Order Summary</h6>
                <div id="order-items-container" class="border rounded p-3 mb-3">
                  <table class="table table-sm order-summary-table">
                    <thead>
                      <tr><th>Item</th><th>Qty</th><th>Price</th><th></th></tr>
                    </thead>
                    <tbody id="order-items-list"></tbody>
                  </table>
                </div>
                <div class="mb-3">
                  <label>Customer Name</label>
                  <input type="text" class="form-control" id="customerName" placeholder="Enter name">
                </div>
                <div class="mb-3">
                  <label>Order Type</label>
                  <select class="form-select" id="orderType">
                    <option value="" selected disabled>Select order type</option>
                    <option>Dine In</option>
                    <option>Take Out</option>
                  </select>
                </div>
                <div class="mb-3">
                  <label>Payment Type</label>
                  <select class="form-select" id="paymentType" onchange="togglePaymentFields()">
                    <option value="" selected disabled>Select payment type</option>
                    <option>Cash</option>
                    <option value="GCash" disabled>GCash (Unavailable)</option>
                  </select>
                </div>
                <div id="cashCalculator" style="display:none;">
                  <div class="mb-3">
                    <label>Cash Amount</label>
                    <input type="number" class="form-control" id="cashAmount" placeholder="Enter cash amount" oninput="computeChange()">
                  </div>
                </div>
                <div class="order-total-row">
                  <div class="total-amount">Total Amount: <span id="totalAmount">₱0.00</span></div>
                  <div class="change-display">Change: <span id="changeDisplay">₱0.00</span></div>
                </div>
                <div class="d-flex gap-2">
                  <button class="btn btn-secondary flex-fill" onclick="hideInlineOrder()">Clear</button>
                  <button class="btn btn-quick flex-fill" onclick="submitOrder()">Process Order</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>

    <!-- Process Bulk Section -->
    <div id="process-bulk-section" style="display:none;">
      <h4 class="mb-4">Process Bulk Orders</h4>
      
      <!-- In Process - Bulk Orders Section -->
      <div class="card shadow-sm mb-4" id="bulkOrdersCard">
        <div class="card-header gradient-brown fw-bold fs-5">
          <i class="bi bi-basket3-fill me-2"></i>In Process - Bulk Orders
          <small class="float-end" style="font-size:0.85rem;font-weight:normal;opacity:0.9;">
            <i class="bi bi-info-circle"></i> Orders with 5+ products
          </small>
        </div>
        <div class="card-body p-0 table-responsive">
          <div class="table-responsive">
            <table class="table table-sm mb-0">
              <thead>
                <tr>
                  <th>Customer</th>
                  <th>Type</th>
                  <th>Products Count</th>
                  <th>Total</th>
                  <th>Date & Time</th>
                  <th>Status</th>
                  <th>Action</th>
                </tr>
              </thead>
              <tbody id="bulkOrdersList">
                <tr>
                  <td colspan="7" class="text-center text-muted">
                    <div class="spinner-border spinner-border-sm me-2" role="status"></div>
                    Loading bulk orders...
                  </td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>

    <!-- Advance Reservation Section -->
    <div id="advance-reservation-section" style="display:none;">
      <h4 class="mb-4"></h4>

      <div class="card card-custom p-4 text-start mb-4">
        <h6 class="fw-semibold mb-3">Reservation Status Overview:</h6>
        <div class="row g-3">
          <div class="col-md-3">
            <div class="card stat-card h-100 justify-content-center text-center p-3" style="background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%);">
              <i class="bi bi-journal-bookmark-fill fs-1 animate__animated animate__pulse animate__infinite"></i>
              <h6 class="mt-2 mb-0">Total Reservations</h6>
              <h4 class="fw-bold" id="totalReservations">0</h4>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card stat-card h-100 justify-content-center text-center p-3" style="background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%);">
              <i class="bi bi-hourglass-top fs-1 animate__animated animate__pulse animate__infinite"></i>
              <h6 class="mt-2 mb-0">Pending</h6>
              <h4 class="fw-bold" id="pendingCount">0</h4>
              <small class="text-muted">₱<span id="overviewPendingValue">0.00</span></small>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card stat-card h-100 justify-content-center text-center p-3" style="background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%);">
              <i class="bi bi-check-circle-fill fs-1 animate__animated animate__pulse animate__infinite"></i>
              <h6 class="mt-2 mb-0">Completed</h6>
              <h4 class="fw-bold" id="completedCount">0</h4>
              <small class="text-muted">₱<span id="overviewCompletedValue">0.00</span></small>
            </div>
          </div>
          <div class="col-md-3">
            <div class="card stat-card h-100 justify-content-center text-center p-3" style="background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%);">
              <i class="bi bi-x-circle-fill fs-1 animate__animated animate__pulse animate__infinite"></i>
              <h6 class="mt-2 mb-0">Cancelled</h6>
              <h4 class="fw-bold" id="cancelledCount">0</h4>
              <small class="text-muted">₱<span id="overviewCancelledValue">0.00</span></small>
            </div>
          </div>
        </div>
      </div>

      <div class="d-flex align-items-center mb-3">
        <div class="input-group" style="max-width:400px;">
          <span class="input-group-text bg-light border-end-0">Search</span>
          <input type="text" id="searchInput" class="form-control border-start-0" placeholder="Quick Search">
        </div>
        <button class="btn btn-quick ms-3" id="searchBtn">Find Customer Reservations</button>
      </div>
      <div class="table-responsive">
        <!-- Removed visible customer name column and cleared reservation history rows per instruction -->
        <table id="reservationTable" class="table align-middle text-center" style="background-color:#f5e9dd;">
          <thead class="table-light">
            <tr>
              <th>Reservation ID</th>
              <th>Customer Name</th>
              <th>Product</th>
              <th>Price</th>
              <th>Date & Time</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="reservationTableBody">
            <!-- Reservation data will be loaded via AJAX -->
          </tbody>
        </table>
      </div>
    </div>

    <!-- Inventory Section -->
    <div id="inventory-section" style="display:none;">
      <div class="d-flex justify-content-between align-items-center mb-4">
        <div>
          <h4 class="mb-1" style="color:#4d2e00;">📦 Inventory Management</h4>
          <p class="text-muted mb-0" style="font-size:0.9rem;">View and monitor product stock levels</p>
        </div>
        <div class="d-flex gap-2 align-items-center">
          <i class="bi bi-box-seam fs-4" style="color:#b57b46;"></i>
        </div>
      </div>

      <!-- Stock Summary Cards -->
      <div class="row g-3 mb-4">
        <div class="col-md-3">
          <div class="card h-100 text-center p-3" style="background: linear-gradient(135deg, #d4edda 0%, #c3e6cb 100%); border: none; box-shadow: 0 2px 8px rgba(40,167,69,0.15);">
            <i class="bi bi-check-circle-fill fs-2 text-success mb-2"></i>
            <h6 class="mb-0 text-muted" style="font-size:0.85rem;">Safe Stock</h6>
            <h3 class="fw-bold mb-0" style="color:#28a745;" id="safeStockCount">0</h3>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card h-100 text-center p-3" style="background: linear-gradient(135deg, #fff3cd 0%, #ffe69c 100%); border: none; box-shadow: 0 2px 8px rgba(255,193,7,0.15);">
            <i class="bi bi-exclamation-triangle-fill fs-2 text-warning mb-2"></i>
            <h6 class="mb-0 text-muted" style="font-size:0.85rem;">Low Stock</h6>
            <h3 class="fw-bold mb-0" style="color:#ffc107;" id="lowStockCount">0</h3>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card h-100 text-center p-3" style="background: linear-gradient(135deg, #f8d7da 0%, #f5c6cb 100%); border: none; box-shadow: 0 2px 8px rgba(220,53,69,0.15);">
            <i class="bi bi-x-circle-fill fs-2 text-danger mb-2"></i>
            <h6 class="mb-0 text-muted" style="font-size:0.85rem;">Critical Stock</h6>
            <h3 class="fw-bold mb-0" style="color:#dc3545;" id="criticalStockCount">0</h3>
          </div>
        </div>
        <div class="col-md-3">
          <div class="card h-100 text-center p-3" style="background: linear-gradient(135deg, #fbeee6 0%, #f0dcc8 100%); border: none; box-shadow: 0 2px 8px rgba(181,123,70,0.15);">
            <i class="bi bi-box-fill fs-2 mb-2" style="color:#b57b46;"></i>
            <h6 class="mb-0 text-muted" style="font-size:0.85rem;">Total Products</h6>
            <h3 class="fw-bold mb-0" style="color:#4d2e00;" id="totalProductsCount">0</h3>
          </div>
        </div>
      </div>

      <!-- Category Filter & Search -->
      <div class="card card-custom p-3 mb-3">
        <div class="row g-3 align-items-center">
          <div class="col-md-4">
            <label class="form-label mb-1 fw-semibold" style="font-size:0.9rem;">
              <i class="bi bi-funnel-fill me-1" style="color:#b57b46;"></i>Filter by Category
            </label>
            <select id="inventoryCategoryFilter" class="form-select" style="border: 2px solid #e0d5c7; background-color:#fdfcfb;">
              <option value="all">🍽️ All Categories</option>
              <option value="pasta">🍝 Pasta</option>
              <option value="ricemeals">🍚 Rice Meals</option>
              <option value="coffeebeverages">☕ Coffee Beverages</option>
              <option value="noncoffee">🥤 NonCoffee</option>
              <option value="pizza">🍕 Pizza</option>
              <option value="cakes">🎂 Cakes</option>
              <option value="sandwichessalad">🥪 Sandwiches & Salad</option>
              <option value="lemonseries">🍋 Lemon Series</option>
              <option value="breads">🍞 Breads</option>
              <option value="piecookiesbar">🥧 Pie, Cookies & Bar</option>
              <option value="milktea">🧋 Milktea</option>
              <option value="fruitsyogurt">🍓 Fruits & Yogurt</option>
            </select>
          </div>
          <div class="col-md-4">
            <label class="form-label mb-1 fw-semibold" style="font-size:0.9rem;">
              <i class="bi bi-search me-1" style="color:#b57b46;"></i>Search Products
            </label>
            <input type="text" id="inventorySearchInput" class="form-control" placeholder="Search by product name..." style="border: 2px solid #e0d5c7; background-color:#fdfcfb;">
          </div>
          <div class="col-md-4">
            <label class="form-label mb-1 fw-semibold" style="font-size:0.9rem;">
              <i class="bi bi-flag-fill me-1" style="color:#b57b46;"></i>Stock Status
            </label>
            <select id="inventoryStockFilter" class="form-select" style="border: 2px solid #e0d5c7; background-color:#fdfcfb;">
              <option value="all">All Statuses</option>
              <option value="Safe">✅ Safe</option>
              <option value="Low">⚠️ Low</option>
              <option value="Critical">🚨 Critical</option>
              <option value="Out of Stock">❌ Out of Stock</option>
            </select>
          </div>
        </div>
      </div>

      <!-- Inventory Grid -->
      <div id="inventoryGrid" class="row g-3">
        <?php foreach ($products as $p): 
             // Match Stock Color to Low Stock Alert logic
            if ($p['Low_Stock_Alert'] === 'Critical') {
                $badge = 'bg-danger';
                $stockClass = 'text-danger';
                $icon = '🚨';
            } elseif ($p['Low_Stock_Alert'] === 'Low') {
                $badge = 'bg-warning';
                $stockClass = 'text-warning';
                $icon = '⚠️';
            } elseif ($p['Low_Stock_Alert'] === 'Out of Stock') {
                $badge = 'bg-secondary';
                $stockClass = 'text-secondary';
                $icon = '❌';
            } else {
                $badge = 'bg-success';
                $stockClass = 'text-success';
                $icon = '✅';
            }

            $dataCat = strtolower(str_replace([' ', '&', '-'], '', $p['Category']));
          ?>
          <div class="col-md-6 col-lg-4 col-xl-3 inventory-item" data-category="<?= $dataCat ?>" data-product-name="<?= strtolower($p['Product_Name']) ?>" data-stock-status="<?= $p['Low_Stock_Alert'] ?>" data-product-id="<?= (int)$p['Product_ID'] ?>">
            <div class="card h-100" style="border: 2px solid #e0d5c7; box-shadow: 0 2px 8px rgba(107,79,63,0.1); transition: all 0.3s;">
              <div class="position-relative">
                <?php if (!empty($p['Image'])): 
                  $finfo = new finfo(FILEINFO_MIME_TYPE); 
                  $mime = $finfo->buffer($p['Image']) ?: 'image/jpeg'; ?>
                  <img src="data:<?= $mime ?>;base64,<?= base64_encode($p['Image']) ?>" 
                       class="card-img-top" 
                       style="height:180px; object-fit:cover;" 
                       alt="<?= htmlspecialchars($p['Product_Name']) ?>">
                <?php else: ?>
                  <div class="card-img-top d-flex align-items-center justify-content-center" 
                       style="height:180px; background: linear-gradient(135deg, #f0e6d6 0%, #e8dcc4 100%);">
                    <i class="bi bi-image fs-1" style="color:#b57b46;"></i>
                  </div>
                <?php endif; ?>
                <span class="badge <?= $badge ?> position-absolute top-0 end-0 m-2"><?= $icon ?> <?= $p['Low_Stock_Alert'] ?: 'Safe' ?></span>
              </div>
              <div class="card-body p-3">
                <div class="d-flex justify-content-between align-items-start mb-2">
                  <span class="badge" style="background-color:#b57b46; font-size:0.75rem;">P<?= str_pad($p['Product_ID'], 3, '0', STR_PAD_LEFT) ?></span>
                  <span class="badge bg-secondary" style="font-size:0.75rem;"><?= $p['Category'] ?></span>
                </div>
                <h6 class="card-title mb-2 fw-bold" style="color:#4d2e00; font-size:0.95rem; min-height:40px;"><?= htmlspecialchars($p['Product_Name']) ?></h6>
                <div class="d-flex justify-content-between align-items-center">
                  <div>
                    <small class="text-muted d-block" style="font-size:0.75rem;">Price</small>
                    <span class="fw-bold" style="color:#b57b46; font-size:1.1rem;">₱<?= number_format($p['Price'], 2) ?></span>
                  </div>
                  <div class="text-end">
                    <small class="text-muted d-block" style="font-size:0.75rem;">Stock</small>
                    <span class="fw-bold <?= $stockClass ?>" style="font-size:1.1rem;"><?= $p['Stock_Quantity'] ?></span>
                  </div>
                </div>
              </div>
            </div>
          </div>
        <?php endforeach; ?>
      </div>

      <!-- Empty State -->
      <div id="emptyInventory" class="text-center p-5" style="display:none;">
        <i class="bi bi-box-seam" style="font-size:4rem; color:#b57b46; opacity:0.5;"></i>
        <h5 class="mt-3 text-muted">No products found</h5>
        <p class="text-muted">Try adjusting your filters or search criteria</p>
      </div>
    </div>

  <!-- STAFF PROFILE OVERLAY (like customer) -->
  <div id="staff-profile-overlay" class="overlay" style="display:none;z-index:99999;">
    <div style="position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.35);z-index:99999;display:flex;align-items:center;justify-content:center;">
      <div class="card shadow-lg" style="max-width:450px;width:100%;padding:32px 36px 40px;">
        <div class="d-flex justify-content-between align-items-center mb-3">
          <h1 style="font-size:1.6rem;color:#4d2e00;margin:0;font-weight:600;">
            👤 My Profile
          </h1>
          <button class="close-btn" id="close-staff-profile" style="background:none;border:none;font-size:32px;color:#888;cursor:pointer;">×</button>
        </div>
        <div class="text-center mb-4">
          <div style="width:70px;height:70px;background:linear-gradient(135deg,#f0e6d6,#e8dcc4);border-radius:50%;display:flex;align-items:center;justify-content:center;margin:0 auto 12px;box-shadow:0 4px 12px rgba(107,79,63,0.15);">
            👤
          </div>
          <p style="color:#666;font-size:0.95rem;margin:0;">Update your personal information</p>
        </div>
        <div id="staff-profile-info">
          <div class="form-group mb-3">
            <label class="form-label">👤 Full Name</label>
            <input type="text" class="form-control" value="<?= htmlspecialchars($staffFullname) ?>" readonly style="background-color:#f8f9fa;cursor:not-allowed;">
          </div>
          <div class="form-group mb-3">
            <label class="form-label"><i class='bi bi-tag-fill' style='color:#b57b46;'></i> Username</label>
            <input type="text" class="form-control" value="<?= htmlspecialchars($staffUsername) ?>" readonly style="background-color:#f8f9fa;cursor:not-allowed;">
          </div>
          <div class="form-group mb-3">
            <label class="form-label"><i class='bi bi-envelope-fill' style='color:#a0845c;'></i> Email Address</label>
            <input type="email" class="form-control" value="<?= htmlspecialchars($staffEmail) ?>" readonly style="background-color:#f8f9fa;cursor:not-allowed;">
          </div>
          <div class="form-group mb-3">
            <label class="form-label"><i class='bi bi-telephone-fill' style='color:#c1976b;'></i> Phone Number</label>
            <input type="text" class="form-control" value="<?= htmlspecialchars($staffPhone) ?>" readonly style="background-color:#f8f9fa;cursor:not-allowed;">
          </div>
          <div class="alert alert-info mt-3" style="font-size:0.9rem;">
            <i class="bi bi-info-circle"></i> Your profile information is managed by the administrator and cannot be edited here.
          </div>
        </div>
      </div>
    </div>
  </div>
   
  <!-- Bulk Order Details Modal -->
  <div class="modal fade" id="bulkOrderModal" tabindex="-1" aria-labelledby="bulkOrderModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-lg modal-dialog-centered modal-dialog-scrollable">
      <div class="modal-content">
        <div class="modal-header" style="background: linear-gradient(135deg, #fbeee6 0%, #d7b79a 100%);">
          <h5 class="modal-title fw-bold" id="bulkOrderModalLabel">
            <i class="bi bi-basket3-fill me-2"></i>Bulk Order Details
          </h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <div class="row mb-3">
            <div class="col-md-6">
              <strong><i class="bi bi-person-fill text-primary"></i> Customer:</strong>
              <p class="mb-1" id="bulkModalCustomer"></p>
            </div>
            <div class="col-md-6">
              <strong><i class="bi bi-envelope-fill text-info"></i> Email:</strong>
              <p class="mb-1" id="bulkModalEmail"></p>
            </div>
          </div>
          <div class="row mb-3">
            <div class="col-md-4">
              <strong><i class="bi bi-calendar-event text-success"></i> Date:</strong>
              <p class="mb-1" id="bulkModalDate"></p>
            </div>
            <div class="col-md-4">
              <strong><i class="bi bi-credit-card text-warning"></i> Payment:</strong>
              <p class="mb-1" id="bulkModalPayment"></p>
            </div>
            <div class="col-md-4">
              <strong><i class="bi bi-flag-fill text-danger"></i> Status:</strong>
              <p class="mb-1" id="bulkModalStatus"></p>
            </div>
          </div>
          <hr>
          <h6 class="fw-bold mb-3"><i class="bi bi-cart-fill me-2"></i>Ordered Products:</h6>
          <div class="table-responsive">
            <table class="table table-hover">
              <thead class="table-light">
                <tr>
                  <th>#</th>
                  <th>Product Name</th>
                  <th>Price</th>
                  <th>Quantity</th>
                  <th>Subtotal</th>
                </tr>
              </thead>
              <tbody id="bulkModalItems">
              </tbody>
            </table>
          </div>
          <div class="text-end mt-3">
            <h5><strong>Total Amount: <span class="text-success" id="bulkModalTotal"></span></strong></h5>
          </div>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Close</button>
          <button type="button" class="btn btn-success" id="bulkModalCompleteBtn">
            <i class="bi bi-check2-circle"></i> Complete Order
          </button>
        </div>
      </div>
    </div>
  </div>

  <!-- Reservation Modal (popup) -->
  <div class="modal fade" id="reservationModal" tabindex="-1" aria-labelledby="reservationModalLabel" aria-hidden="true">
    <div class="modal-dialog modal-dialog-centered">
      <div class="modal-content">
        <div class="modal-header">
          <h5 class="modal-title" id="reservationModalLabel">Process Reservation</h5>
          <button type="button" class="btn-close" data-bs-dismiss="modal" aria-label="Close"></button>
        </div>
        <div class="modal-body">
          <form id="reservationForm">
            <div class="mb-3">
              <label for="modalResCustomerName" class="form-label">Customer Name</label>
              <input type="text" id="modalResCustomerName" class="form-control" placeholder="Enter customer name">
            </div>
            <div class="mb-3">
              <label for="modalResDateTime" class="form-label">Date & Time</label>
              <input type="datetime-local" id="modalResDateTime" class="form-control">
            </div>
            <div id="reservationFormAlert" class="text-danger" style="display:none;"></div>
          </form>
        </div>
        <div class="modal-footer">
          <button type="button" class="btn btn-secondary" data-bs-dismiss="modal">Cancel</button>
          <button type="button" class="btn btn-quick" id="submitReservationModalBtn">Process Reservation</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Bootstrap JS -->
  <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/animate.css/4.1.1/animate.min.css"/>
  <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.3/dist/js/bootstrap.bundle.min.js"></script>

  <script>

    

    // STAFF USER ICON DROPDOWN (show only on click, hide on outside click)
    document.addEventListener("DOMContentLoaded", function () {
      const userIcon = document.getElementById("staffUserIcon");
      const dropdown = document.getElementById("staffUserDropdown");
      userIcon.addEventListener("click", function(e) {
        e.stopPropagation();
        if (dropdown.style.display === "block") {
          dropdown.style.display = "none";
        } else {
          dropdown.style.display = "block";
        }
      });
      document.addEventListener("click", function(e) {
        if (!dropdown.contains(e.target) && e.target !== userIcon) {
          dropdown.style.display = "none";
        }
      });
      dropdown.addEventListener("click", function(e) {
        e.stopPropagation();
      });
    });

    // STAFF PROFILE MODAL
    function openStaffProfileModal() {
      document.getElementById('staff-profile-overlay').style.display = 'flex';
    }
    document.getElementById('close-staff-profile').onclick = () => {
      document.getElementById('staff-profile-overlay').style.display = 'none';
    };

    // Staff profile is read-only, no form submission needed
    // ---------- Section Navigation ----------
    function showContent(section) {
      const sections = ['dashboard', 'process-bulk', 'advance-reservation', 'inventory'];
      sections.forEach(s => {
        const el = document.getElementById(s + '-section');
        if (el) el.style.display = 'none';
      });
      document.querySelectorAll('[id$="-section"]').forEach(s => s.style.display = 'none');
      document.querySelectorAll('.sidebar .nav-link').forEach(l => l.classList.remove('active'));
      const target = document.getElementById(section + '-section');
      if (target) target.style.display = 'block';
      try {
        // Prefer an explicit nav button (nav-<section>) if available, else fall back to event.currentTarget
        const navBtn = document.getElementById('nav-' + section);
        if (navBtn && navBtn.classList) {
          navBtn.classList.add('active');
        } else if (typeof event !== 'undefined' && event.currentTarget && event.currentTarget.classList) {
          event.currentTarget.classList.add('active');
        }
      } catch (e) {}
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
      document.getElementById('datetime').textContent = now.toLocaleString('en-PH', options);
    }
    setInterval(updateDateTime, 1000);
    updateDateTime();

    // ---------- Profile ----------
    // saveProfile now sends form data to server to save changes (action=save_profile)
    async function saveProfile() {
      const fullname = document.getElementById('profileFullname').value.trim();
      const username = document.getElementById('profileUsername').value.trim();
      const email = document.getElementById('profileEmail').value.trim();
      const phone = document.getElementById('profilePhone').value.trim();

      const form = new FormData();
      form.append('action', 'save_profile');
      form.append('fullname', fullname);
      form.append('username', username);
      form.append('email', email);
      form.append('phone', phone);

      try {
        const resp = await fetch(window.location.pathname, {
          method: 'POST',
          body: form,
          credentials: 'same-origin'
        });
        // expect JSON response from server
        const data = await resp.json().catch(() => ({ success: false, message: 'Invalid server response' }));
        if (data.success) {
          alert(data.message || 'Profile saved successfully.');
          // close modal
          const modalEl = document.getElementById('profileModal');
          try {
            const bsModal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
            bsModal.hide();
          } catch (e) {}
          // optionally update session values displayed elsewhere if needed
        } else {
          alert(data.message || 'Failed to save profile.');
        }
      } catch (err) {
        console.error(err);
        alert('An error occurred while saving profile.');
      }
    }

    function logout() { if (confirm('Logout?')) window.location.href = 'login.php'; }

    // Keep the walk-in order panel visible; this routine now just resets the form state.
    function hideInlineOrder() {
      const card = document.getElementById('inlineOrderCard');
      if (!card) return;
      resetOrderForm();
      card.classList.add('show');
      card.style.display = 'block';
    }

    // ---------- Category Filter (Quick Add) ----------
    const filterSelect = document.getElementById('categoryFilter');
    const productItems = document.querySelectorAll('.product-item');
    if (filterSelect) {
      filterSelect.addEventListener('change', function () {
        const selectedRaw = this.value || 'all';
        const selected = selectedRaw.toLowerCase().replace(/[^a-z]/g,'');
        productItems.forEach(item => {
          const catRaw = item.dataset.category || '';
          const cat = catRaw.toLowerCase().replace(/[^a-z]/g,'');
          if (selected === 'all' || cat === selected) {
            item.style.display = '';
          } else {
            item.style.display = 'none';
          }
        });
      });
    }

    document.getElementById("categoryFilter")?.addEventListener("change", function () {
      const selectedRaw = this.value || 'all';
      const selected = selectedRaw.toLowerCase().replace(/[^a-z]/g,'');
      document.querySelectorAll(".product-item").forEach(item => {
        const cat = (item.dataset.category || '').toLowerCase().replace(/[^a-z]/g,'');
        item.style.display =
          selected === "all" || cat === selected
            ? "block"
            : "none";
      });
    });

    // ---------- Inventory Filters & Stock Summary ----------
    function updateInventoryDisplay() {
      const categoryVal = document.getElementById('inventoryCategoryFilter')?.value || 'all';
      const categoryValNormalized = (categoryVal || 'all').toLowerCase().replace(/[^a-z]/g,'');
      const searchVal = document.getElementById('inventorySearchInput')?.value.toLowerCase() || '';
      const stockVal = document.getElementById('inventoryStockFilter')?.value || 'all';
      
      const items = document.querySelectorAll('.inventory-item');
      const empty = document.getElementById('emptyInventory');
      let visible = 0;
      
      let safeCount = 0, lowCount = 0, criticalCount = 0, totalCount = 0;
      
      items.forEach(item => {
        const cat = (item.dataset.category || '').toLowerCase();
        const catNormalized = cat.replace(/[^a-z]/g,'');
        const productName = item.dataset.productName;
        const stockStatus = item.dataset.stockStatus;
        
        const matchCategory = categoryValNormalized === 'all' || catNormalized === categoryValNormalized;
        const matchSearch = searchVal === '' || productName.includes(searchVal);
        const matchStock = stockVal === 'all' || stockStatus === stockVal;
        
        if (matchCategory && matchSearch && matchStock) {
          item.style.display = '';
          visible++;
          
          // Count stock levels for summary
          if (stockStatus === 'Safe') safeCount++;
          else if (stockStatus === 'Low') lowCount++;
          else if (stockStatus === 'Critical' || stockStatus === 'Out of Stock') criticalCount++;
          totalCount++;
        } else {
          item.style.display = 'none';
        }
      });
      
      // Update summary cards
      document.getElementById('safeStockCount').textContent = safeCount;
      document.getElementById('lowStockCount').textContent = lowCount;
      document.getElementById('criticalStockCount').textContent = criticalCount;
      document.getElementById('totalProductsCount').textContent = totalCount;
      
      empty.style.display = visible === 0 ? 'block' : 'none';
    }
    
    // Initialize inventory counts on page load
    if (document.getElementById('inventory-section')) {
      updateInventoryDisplay();
    }
    
    // Category filter
    document.getElementById('inventoryCategoryFilter')?.addEventListener('change', updateInventoryDisplay);
    
    // Search filter
    document.getElementById('inventorySearchInput')?.addEventListener('input', updateInventoryDisplay);
    
    // Stock status filter
    document.getElementById('inventoryStockFilter')?.addEventListener('change', updateInventoryDisplay);
    
    // Add hover effect to inventory cards
    document.querySelectorAll('.inventory-item .card').forEach(card => {
      card.addEventListener('mouseenter', function() {
        this.style.transform = 'translateY(-5px)';
        this.style.boxShadow = '0 4px 16px rgba(107,79,63,0.2)';
      });
      card.addEventListener('mouseleave', function() {
        this.style.transform = 'translateY(0)';
        this.style.boxShadow = '0 2px 8px rgba(107,79,63,0.1)';
      });
    });

    // ---------- Order Logic ----------
    // FIX: ensure remove button truly removes from the underlying data (orderItems)
    // and not only visually; prevent event propagation from remove clicks so they
    // won't accidentally trigger the outside-click handler that hides the modal.

    let orderItems = [];

    // Use delegation for product clicks to ensure newly added/modified DOM still works.
    const productGrid = document.getElementById('productGrid');
    if (productGrid) {
      productGrid.addEventListener('click', function (e) {
        const card = e.target.closest('.product-card');
        if (!card) return;
        e.stopPropagation();
        const productId = parseInt(card.dataset.productId, 10);
        const name = card.dataset.name;
        const price = parseFloat(card.dataset.price);
        const stock = parseInt(card.dataset.stock, 10);
        if (!Number.isFinite(stock) || stock <= 0) {
          alert('Sorry, this product is currently out of stock.');
          return;
        }
        if (!productId || !name || isNaN(price)) return;
        const existing = orderItems.find(i => i.productId === productId);
        if (existing) existing.qty += 1;
        else orderItems.push({ productId, name, price, qty: 1 });
        updateOrderSummary();
      });
    } else {
      // fallback to binding to each product-card if grid not found
      document.querySelectorAll('.product-card').forEach(card => {
        card.addEventListener('click', function (e) {
          e.preventDefault();
          e.stopPropagation();
          const productId = parseInt(this.dataset.productId, 10);
          const name = this.dataset.name;
          const price = parseFloat(this.dataset.price);
          const stock = parseInt(this.dataset.stock, 10);
          if (!Number.isFinite(stock) || stock <= 0) {
            alert('Sorry, this product is currently out of stock.');
            return;
          }
          if (!productId || !name || isNaN(price)) return;
          const existing = orderItems.find(i => i.productId === productId);
          if (existing) existing.qty += 1;
          else orderItems.push({ productId, name, price, qty: 1 });
          updateOrderSummary();
        });
      });
    }

    function updateOrderSummary() {
      const tbody = document.getElementById('order-items-list');
      if (!tbody) return;
      tbody.innerHTML = '';
      let total = 0;
      orderItems.forEach((item, idx) => {
        const row = document.createElement('tr');

        // Name
        const tdName = document.createElement('td');
        tdName.textContent = item.name;
        row.appendChild(tdName);

        // Qty input
        const tdQty = document.createElement('td');
        const qtyInput = document.createElement('input');
        qtyInput.type = 'number';
        qtyInput.className = 'form-control form-control-sm';
        qtyInput.style.width = '60px';
        qtyInput.min = 1;
        qtyInput.value = item.qty;
        qtyInput.dataset.idx = idx;
        qtyInput.addEventListener('change', function (ev) {
          ev.stopPropagation();
          const i = parseInt(this.dataset.idx, 10);
          const v = parseInt(this.value, 10) || 1;
          if (orderItems[i]) {
            orderItems[i].qty = Math.max(1, v);
            updateOrderSummary();
          }
        });
        // prevent propagation from clicks inside input
        qtyInput.addEventListener('click', function(ev){ ev.stopPropagation(); });
        tdQty.appendChild(qtyInput);
        row.appendChild(tdQty);

        // Price
        const tdPrice = document.createElement('td');
        tdPrice.textContent = `₱${(item.price * item.qty).toFixed(2)}`;
        row.appendChild(tdPrice);

        // Remove button
        const tdAction = document.createElement('td');
        const removeBtn = document.createElement('button');
        removeBtn.type = 'button';
        removeBtn.className = 'btn btn-sm btn-danger';
        removeBtn.textContent = 'X';
        removeBtn.dataset.idx = idx;
        // IMPORTANT: stopPropagation so click doesn't bubble to document handler that hides modal
        removeBtn.addEventListener('click', function (ev) {
          ev.stopPropagation();
          const i = parseInt(this.dataset.idx, 10);
          removeItem(i);
        });
        tdAction.appendChild(removeBtn);
        row.appendChild(tdAction);

        tbody.appendChild(row);
        total += item.price * item.qty;
      });
      const totalEl = document.getElementById('totalAmount');
      if (totalEl) totalEl.textContent = `₱${total.toFixed(2)}`;

      // Update change if cash field present
      computeChange();
    }

    // Keep updateQty for any inline calls (though inputs already handle their own)
    function updateQty(idx, val) {
      const qty = parseInt(val) || 1;
      if (orderItems[idx]) {
        orderItems[idx].qty = Math.max(1, qty);
        updateOrderSummary();
      }
    }

    function removeItem(idx) {
      if (typeof idx !== 'number' || idx < 0 || idx >= orderItems.length) return;
      // Remove from underlying array and re-render
      orderItems.splice(idx, 1);
      updateOrderSummary();
    }

    function resetOrderForm() {
      // Reset order items
      orderItems = [];
      updateOrderSummary();

      // Reset customer info
      const cn = document.getElementById('customerName');
      if (cn) cn.value = '';
      const ot = document.getElementById('orderType');
      if (ot) ot.selectedIndex = 0;

      // Reset payment type
      const paymentSelect = document.getElementById('paymentType');
      if (paymentSelect) paymentSelect.selectedIndex = 0;

      // Hide cash calculator & clear cash input
      const calc = document.getElementById('cashCalculator');
      if (calc) calc.style.display = 'none';
      const cash = document.getElementById('cashAmount');
      if (cash) cash.value = '';

      // Reset change display
      const changeDisplay = document.getElementById('changeDisplay');
      if (changeDisplay) changeDisplay.innerText = '₱0.00';

      const totalEl = document.getElementById('totalAmount');
      if (totalEl) totalEl.textContent = '₱0.00';

      togglePaymentFields();
    }

    // --- Dashboard Order Data ---
    let dashboardOrders = [];

    // Fetch dashboard stats from database
    function loadDashboardStats() {
      fetch('?action=get_dashboard_stats', {
        method: 'GET',
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success' && res.stats) {
          // Update stat cards with database values
          document.getElementById('pendingCountCard').textContent = res.stats.pending;
          document.getElementById('completedCountCard').textContent = res.stats.completedToday;
          document.getElementById('reserveCountCard').textContent = res.stats.pendingReservations;
          document.getElementById('onlineCountCard').textContent = res.stats.online;
          document.getElementById('revenueCard').textContent = '₱' + parseFloat(res.stats.revenue).toFixed(2);
        }
      })
      .catch(err => {
        console.error('Error loading dashboard stats:', err);
      });
    }

    // Make the Reserve / Pending Reservation Orders card clickable to show reservations
    (function attachReserveCardClick() {
      try {
        const reserveCountEl = document.getElementById('reserveCountCard');
        if (!reserveCountEl) return;
        const cardEl = reserveCountEl.closest('.stat-card');
        if (!cardEl) return;
        cardEl.style.cursor = 'pointer';
        cardEl.addEventListener('click', function (e) {
          e.preventDefault();
          // Show advance reservation section
          showContent('advance-reservation');
          // Load only Pending reservations
          loadReservationsFromDB('Pending');
          // Also ensure the status overview is updated
          loadReservationStatusOverview();
        });
      } catch (err) {
        // Silent fail in case the DOM structure differs
        console.error('Failed to attach click to reserve card:', err);
      }
    })();

    // Fetch pending orders from database when dashboard loads
    function loadPendingOrders() {
      const pendingUrl = '?action=get_pending_orders&_=' + Date.now();
      fetch(pendingUrl, {
        method: 'GET',
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success' && res.orders) {
          // Convert database orders to dashboard format
          dashboardOrders = res.orders.map(o => {
            const orderSource = o.order_source || (o.User_ID ? 'Online' : 'Walk-In');
            const serviceType = o.service_type || (orderSource === 'Walk-In' ? 'Walk-In' : 'Online');

            return {
              orderId: o.OrderID,
              customer: o.customer_name || (orderSource === 'Walk-In' ? 'Walk-in Customer' : 'Guest'),
              customerEmail: o.customer_email || '',
              orderSource,
              serviceType,
              paymentType: o.Mode_Payment,
              items: (o.items || []).map(item => ({
                name: item.Product_Name,
                price: parseFloat(item.Price),
                qty: parseInt(item.Quantity, 10)
              })),
              total: parseFloat(o.Total_Amount),
              status: o.Status,
              date: new Date(o.Order_Date).toLocaleString('en-PH', {
                year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', timeZone: 'Asia/Manila'
              })
            };
          });
          updateRecentOrders();
          // Load stats from database instead of calculating locally
          loadDashboardStats();
        }
      })
      .catch(err => {
        console.error('Error loading pending orders:', err);
      });
    }

    // Fetch bulk orders (5+ products) from database
    function loadBulkOrders() {
      const pendingUrl = '?action=get_pending_orders&_=' + Date.now();
      fetch(pendingUrl, {
        method: 'GET',
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success' && res.orders) {
          // Filter orders with 5 or more total products (sum of quantities)
          const bulkOrders = res.orders.filter(o => {
            const totalProducts = o.items.reduce((sum, item) => sum + parseInt(item.Quantity, 10), 0);
            return totalProducts >= 5;
          });
          
          updateBulkOrdersTable(bulkOrders);
        }
      })
      .catch(err => {
        console.error('Error loading bulk orders:', err);
      });
    }

    // Update bulk orders table
    function updateBulkOrdersTable(orders) {
      const tbody = document.getElementById('bulkOrdersList');
      if (!tbody) return;
      tbody.innerHTML = '';
      
      if (orders.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="7" class="text-center text-muted">No bulk orders currently in process</td>';
        tbody.appendChild(tr);
        return;
      }

      orders.forEach(o => {
        const totalProducts = o.items.reduce((sum, item) => sum + parseInt(item.Quantity, 10), 0);
        const itemsList = o.items.map(item => `${item.Product_Name} x${item.Quantity}`).join(', ');
        const orderSource = o.order_source || (o.User_ID ? 'Online' : 'Walk-In');
        const orderSourceBadgeClass = orderSource === 'Walk-In' ? 'badge bg-secondary' : 'badge bg-info';
        const serviceTypeLabel = o.service_type ? `<small class="text-muted d-block">${o.service_type}</small>` : '';
        const statusBadgeClass = o.Status === 'Confirmed' ? 'badge bg-primary' : 'badge bg-warning text-dark';
        const confirmBtn = o.Status === 'Pending'
          ? `<button class='btn btn-sm btn-primary me-1' onclick='confirmBulkOrder(${o.OrderID}, this)' title='Confirm this bulk order'>
              <i class='bi bi-check2-square'></i> Confirm
            </button>`
          : '';
        const completeDisabledAttr = o.Status === 'Confirmed' ? '' : 'disabled';
        const completeTitle = o.Status === 'Confirmed'
          ? 'Mark as complete and notify customer'
          : 'Confirm this order before completing';

        const tr = document.createElement('tr');
        tr.innerHTML = `
          <td>
            <strong>${o.customer_name || 'Guest'}</strong>
            ${o.customer_email ? `<br><small class="text-muted">${o.customer_email}</small>` : ''}
          </td>
          <td>
            <span class="${orderSourceBadgeClass}">${orderSource}</span>
            ${serviceTypeLabel}
          </td>
          <td>
            <span class="badge bg-warning text-dark" style="font-size:0.9rem;">
              <i class="bi bi-basket3-fill"></i> ${totalProducts} items
            </span>
          </td>
          <td><strong>₱${parseFloat(o.Total_Amount).toFixed(2)}</strong></td>
          <td>
            ${new Date(o.Order_Date).toLocaleString('en-PH', { 
              year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', timeZone: 'Asia/Manila'
            })}
            <br><small class="text-muted" title="${itemsList}">${itemsList.length > 50 ? itemsList.substring(0, 50) + '...' : itemsList}</small>
          </td>
          <td><span class="${statusBadgeClass}">${o.Status}</span></td>
          <td>
            <button class='btn btn-sm btn-info me-1' onclick='viewBulkOrder(${JSON.stringify(o).replace(/'/g, "&#39;")})' title='View full order details'>
              <i class='bi bi-eye-fill'></i> View
            </button>
            ${confirmBtn}
            <button class='btn btn-sm btn-success' onclick='completeBulkOrder(${o.OrderID}, this)' ${completeDisabledAttr} title="${completeTitle}">
              <i class='bi bi-check2-circle'></i> Complete
            </button>
          </td>
        `;
        tbody.appendChild(tr);
      });
    }
    
    // View bulk order details in modal
    window.viewBulkOrder = function(orderData) {
      const order = typeof orderData === 'string' ? JSON.parse(orderData) : orderData;
      
      // Populate modal with order details
      document.getElementById('bulkModalCustomer').textContent = order.customer_name || 'Guest';
      document.getElementById('bulkModalEmail').textContent = order.customer_email || 'N/A';
      document.getElementById('bulkModalDate').textContent = new Date(order.Order_Date).toLocaleString('en-PH', { 
        year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', timeZone: 'Asia/Manila' 
      });
      document.getElementById('bulkModalPayment').textContent = order.Mode_Payment || 'N/A';
      const modalStatusClass = order.Status === 'Confirmed' ? 'badge bg-primary' : 'badge bg-warning text-dark';
      document.getElementById('bulkModalStatus').innerHTML = `<span class="${modalStatusClass}">${order.Status}</span>`;
      document.getElementById('bulkModalTotal').textContent = '₱' + parseFloat(order.Total_Amount).toFixed(2);
      
      // Populate items table
      const itemsBody = document.getElementById('bulkModalItems');
      itemsBody.innerHTML = '';
      
      if (order.items && order.items.length > 0) {
        order.items.forEach((item, index) => {
          const subtotal = parseFloat(item.Price) * parseInt(item.Quantity);
          const row = `
            <tr>
              <td>${index + 1}</td>
              <td><strong>${item.Product_Name}</strong></td>
              <td>₱${parseFloat(item.Price).toFixed(2)}</td>
              <td><span class="badge bg-primary">${item.Quantity}</span></td>
              <td><strong>₱${subtotal.toFixed(2)}</strong></td>
            </tr>
          `;
          itemsBody.innerHTML += row;
        });
      } else {
        itemsBody.innerHTML = '<tr><td colspan="5" class="text-center text-muted">No items found</td></tr>';
      }
      
      // Set up complete button with order ID
      const completeBtn = document.getElementById('bulkModalCompleteBtn');
      completeBtn.disabled = order.Status !== 'Confirmed';
      completeBtn.title = order.Status !== 'Confirmed'
        ? 'Confirm this order before completing'
        : 'Mark as complete and notify customer';
      completeBtn.onclick = function() {
        if (completeBtn.disabled) {
          alert('Confirm this order before completing.');
          return;
        }

        const modal = bootstrap.Modal.getInstance(document.getElementById('bulkOrderModal'));
        modal.hide();
        completeBulkOrder(order.OrderID, completeBtn);
      };
      
      // Show modal
      const modal = new bootstrap.Modal(document.getElementById('bulkOrderModal'));
      modal.show();
    }

    window.confirmBulkOrder = function(orderId, buttonEl) {
      if (!confirm('Confirm this bulk order for processing?')) {
        return;
      }

      const btn = buttonEl instanceof HTMLElement ? buttonEl : (typeof event !== 'undefined' ? event.target.closest('button') : null);
      const originalHtml = btn ? btn.innerHTML : '';

      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      }

      const formData = new FormData();
      formData.append('action', 'confirm_order');
      formData.append('order_id', orderId);

      fetch(window.location.pathname, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (btn) {
          btn.innerHTML = originalHtml;
        }

        if (res.status === 'success') {
          loadBulkOrders();
          loadPendingOrders();
          loadDashboardStats();
          const baseMessage = res.message || 'Bulk order confirmed successfully.';
          const fullMessage = res.email_sent ? `${baseMessage} Customer notified via email.` : baseMessage;
          alert(fullMessage);
        } else {
          alert('Error: ' + (res.message || 'Failed to confirm order'));
          if (btn) {
            btn.disabled = false;
          }
        }
      })
      .catch(err => {
        console.error(err);
        alert('Network error. Please try again.');
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
      });
    }

    // Complete bulk order
    window.completeBulkOrder = function(orderId, buttonEl) {
      if (!confirm('Mark this bulk order as complete? The customer will be notified.')) {
        return;
      }

      const btn = buttonEl instanceof HTMLElement ? buttonEl : (typeof event !== 'undefined' ? event.target.closest('button') : null);
      const originalHtml = btn ? btn.innerHTML : '';

      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span>';
      }

      const formData = new FormData();
      formData.append('action', 'complete_order');
      formData.append('order_id', orderId);

      fetch(window.location.pathname, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success') {
          loadBulkOrders();
          loadPendingOrders();
          loadDashboardStats();
          alert(res.email_sent ? 'Bulk order completed! Email notification sent.' : 'Bulk order completed!');
        } else {
          alert('Error: ' + (res.message || 'Failed to complete order'));
          if (btn) {
            if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; }
          }
        }
      })
      .catch(err => {
        console.error(err);
        alert('Network error. Please try again.');
        if (btn) {
          if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; }
        }
      });
    }

    // Load pending orders and stats on page load
    document.addEventListener('DOMContentLoaded', function() {
      loadPendingOrders();
      loadBulkOrders();
      togglePaymentFields();
      // Refresh every 30 seconds
      setInterval(function() {
        loadPendingOrders();
        loadBulkOrders();
      }, 30000);
    });

    function submitOrder() {
      const customerInput = document.getElementById('customerName');
      const orderTypeSelect = document.getElementById('orderType');
      const paymentSelect = document.getElementById('paymentType');
      const cashInput = document.getElementById('cashAmount');
      const processBtn = document.getElementById('processOrderBtn');

      const customer = customerInput ? customerInput.value.trim() : '';
      const orderType = orderTypeSelect?.value || '';
      const paymentType = paymentSelect?.value || '';

      if (!customer) {
        alert('Please enter customer name.');
        return;
      }
      if (!orderType) {
        alert('Please select order type.');
        return;
      }
      if (!paymentType) {
        alert('Please select payment type.');
        return;
      }
      if (orderItems.length === 0) {
        alert('Please add at least one item to the order.');
        return;
      }

      const total = orderItems.reduce((sum, item) => sum + (item.price * item.qty), 0);
      let cashTendered = null;

      if (paymentType === 'Cash') {
        const rawCash = cashInput ? cashInput.value : '';
        if (rawCash === '') {
          alert('Please enter the cash amount received.');
          return;
        }
        cashTendered = parseFloat(rawCash);
        if (Number.isNaN(cashTendered)) {
          alert('Cash amount must be a valid number.');
          return;
        }
        if (cashTendered < total) {
          alert('Cash amount cannot be less than the order total.');
          return;
        }
      } else {
        alert('GCash payments are currently disabled for walk-in orders.');
        return;
      }

      const payload = {
        customerName: customer,
        orderType,
        paymentType,
        items: orderItems.map(item => ({
          productId: item.productId,
          name: item.name,
          quantity: item.qty,
          price: item.price
        })),
        cashTendered
      };

      const originalBtnHtml = processBtn ? processBtn.innerHTML : '';
      if (processBtn) {
        processBtn.disabled = true;
        processBtn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Processing...';
      }

      const formData = new FormData();
      formData.append('action', 'create_walkin_order');
      formData.append('order', JSON.stringify(payload));

      fetch(window.location.pathname, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success') {
          loadPendingOrders();
          loadBulkOrders();
          loadDashboardStats();

          const message = res.message || 'Walk-in order submitted successfully.';
          alert(message);

          if (res.receipt_pdf) {
            openReceiptPdf(res.receipt_pdf, res.receipt_filename || 'walkin_receipt.pdf');
          }

          hideInlineOrder();
        } else {
          alert('Error: ' + (res.message || 'Failed to submit order.'));
        }
      })
      .catch(err => {
        console.error('Walk-in order error:', err);
        alert('Network error. Please try again.');
      })
      .finally(() => {
        if (processBtn) {
          processBtn.disabled = false;
          processBtn.innerHTML = originalBtnHtml;
        }
      });
    }

    function openReceiptPdf(base64Data, fileName) {
      if (!base64Data) return;

      try {
        const cleaned = base64Data.replace(/\s+/g, '');
        const byteCharacters = atob(cleaned);
        const byteNumbers = new Array(byteCharacters.length);
        for (let i = 0; i < byteCharacters.length; i++) {
          byteNumbers[i] = byteCharacters.charCodeAt(i);
        }
        const byteArray = new Uint8Array(byteNumbers);
        const blob = new Blob([byteArray], { type: 'application/pdf' });
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = fileName || 'receipt.pdf';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        setTimeout(() => URL.revokeObjectURL(url), 0);
      } catch (error) {
        console.error('Failed to open receipt PDF:', error);
        alert('Order recorded, but the receipt could not be opened automatically.');
      }
    }

    // Stats are now loaded from database via loadDashboardStats()

    function updateRecentOrders() {
      const tbody = document.getElementById('recentOrdersList');
      if (!tbody) return;
      tbody.innerHTML = '';
      
      // Filter to show pending and confirmed orders
      const openOrders = dashboardOrders.filter(o => o.status === 'Pending' || o.status === 'Confirmed');
      
      if (openOrders.length === 0) {
        const tr = document.createElement('tr');
        tr.innerHTML = '<td colspan="6" class="text-center text-muted">No pending or confirmed orders</td>';
        tbody.appendChild(tr);
        return;
      }

      openOrders.slice(0, 8).forEach((o) => {
        // Find the original index in dashboardOrders
        const originalIdx = dashboardOrders.indexOf(o);
        
        const tr = document.createElement('tr');
        const itemsList = o.items ? o.items.map(i => `${i.name} x${i.qty}`).join(', ') : 'N/A';
        const statusClass = o.status === 'Confirmed' ? 'badge bg-primary' : 'badge bg-warning text-dark';
        const source = o.orderSource || 'Online';
        const serviceType = o.serviceType && o.serviceType !== source ? o.serviceType : '';
        const orderTypeDisplay = serviceType ? `${source} · ${serviceType}` : source;
        const actionButtons = o.status === 'Pending'
          ? `<button class='btn btn-sm btn-primary me-1' onclick='confirmOrder(${originalIdx}, this)' title='Confirm this order'>
               <i class='bi bi-check2-square'></i> Confirm
             </button>
             <button class='btn btn-sm btn-success' disabled title='Confirm this order before completing'>
               <i class='bi bi-check2-circle'></i> Complete
             </button>`
          : `<button class='btn btn-sm btn-success' onclick='completeOrder(${originalIdx}, this)' title='Mark as complete and notify customer'>
               <i class='bi bi-check2-circle'></i> Complete
             </button>`;
        
        tr.innerHTML = `
          <td>
            <strong>${o.customer}</strong>
            ${o.customerEmail ? `<br><small class="text-muted">${o.customerEmail}</small>` : ''}
          </td>
          <td>${orderTypeDisplay}</td>
          <td><span class="${statusClass}">${o.status}</span></td>
          <td>₱${o.total.toFixed(2)}</td>
          <td>
            ${o.date}
            <br><small class="text-muted" title="${itemsList}">${itemsList.length > 40 ? itemsList.substring(0, 40) + '...' : itemsList}</small>
          </td>
          <td>
            ${actionButtons}
          </td>
        `;
        tbody.appendChild(tr);
      });
    }

    window.confirmOrder = function(idx, buttonEl) {
      const order = dashboardOrders[idx];
      if (!order) return;

      if (order.status === 'Confirmed') {
        alert('Order already confirmed.');
        return;
      }

      if (!confirm(`Confirm order for ${order.customer} (₱${order.total.toFixed(2)})?`)) {
        return;
      }

      const btn = buttonEl instanceof HTMLElement ? buttonEl : (typeof event !== 'undefined' ? event.target.closest('button') : null);
      const originalHtml = btn ? btn.innerHTML : '';

      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Confirming...';
      }

      if (order.orderId) {
        const formData = new FormData();
        formData.append('action', 'confirm_order');
        formData.append('order_id', order.orderId);

        fetch(window.location.pathname, {
          method: 'POST',
          body: formData,
          credentials: 'same-origin'
        })
        .then(r => r.json())
        .then(res => {
          if (res.status === 'success') {
            loadPendingOrders();
            loadBulkOrders();
            loadDashboardStats();
            const baseMessage = res.message || 'Order confirmed successfully!';
            const fullMessage = res.email_sent ? `${baseMessage} Customer notified via email.` : baseMessage;
            alert(fullMessage);
          } else {
            alert('Error: ' + (res.message || 'Failed to confirm order'));
            if (btn) {
              btn.disabled = false;
              btn.innerHTML = originalHtml;
            }
          }
        })
        .catch(err => {
          console.error(err);
          alert('Network error. Please try again.');
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
          }
        });
      } else {
        dashboardOrders[idx].status = 'Confirmed';
        updateRecentOrders();
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
        alert('Order confirmed successfully!');
      }
    }

    window.completeOrder = function(idx, buttonEl) {
      const order = dashboardOrders[idx];
      if (!order) return;

      if (order.status !== 'Confirmed') {
        alert('Confirm the order before marking it complete.');
        return;
      }

      if (!confirm(`Mark order for ${order.customer} (₱${order.total.toFixed(2)}) as complete?${order.customerEmail ? '\nAn email notification will be sent.' : ''}`)) {
        return;
      }

      // Show loading state
      const btn = buttonEl instanceof HTMLElement ? buttonEl : (typeof event !== 'undefined' ? event.target.closest('button') : null);
      const originalHtml = btn ? btn.innerHTML : '';

      if (btn) {
        btn.disabled = true;
        btn.innerHTML = '<span class="spinner-border spinner-border-sm" role="status"></span> Processing...';
      }

      // Send to server if order has an ID (from database)
      if (order.orderId) {
        const formData = new FormData();
        formData.append('action', 'complete_order');
        formData.append('order_id', order.orderId);

        fetch(window.location.pathname, {
          method: 'POST',
          body: formData,
          credentials: 'same-origin'
        })
        .then(r => r.json())
        .then(res => {
          if (res.status === 'success') {
            // Reload orders and stats from database
            loadPendingOrders();
            loadBulkOrders();
            loadDashboardStats();
            
            // Show success message
            const message = res.email_sent 
              ? 'Order completed successfully! Email notification sent to customer.' 
              : 'Order completed successfully!';
            alert(message);
          } else {
            alert('Error: ' + (res.message || 'Failed to complete order'));
            if (btn) {
              btn.disabled = false;
              btn.innerHTML = originalHtml;
            }
          }
        })
        .catch(err => {
          console.error(err);
          alert('Network error. Please try again.');
          if (btn) {
            btn.disabled = false;
            btn.innerHTML = originalHtml;
          }
        });
      } else {
        // Local order (not from database)
        dashboardOrders[idx].status = 'Completed';
        loadDashboardStats();
        updateRecentOrders();
        if (btn) {
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
        alert('Order completed successfully!');
      }
    }

    // ---------- Reservation Search ----------
    document.getElementById('searchBtn')?.addEventListener('click', function() {
      const input = document.getElementById('searchInput')?.value.toLowerCase() || '';
      const rows = document.querySelectorAll('#reservationTable tbody tr');
      rows.forEach(row => {
        const name = (row.dataset.customer || '').toLowerCase();
        row.style.display = name.includes(input) ? '' : 'none';
      });
    });

    // View Details (use data-customer for name - name not shown in table)
    document.querySelectorAll('.view-btn').forEach(button => {
      button.addEventListener('click', function() {
        const row = this.closest('tr');
        const id = row.cells[0].textContent;
        const date = row.cells[1].textContent;
        const status = row.cells[2].textContent;
        const name = row.dataset.customer || '';
        alert(`Reservation Details:\n\nID: ${id}\nCustomer: ${name}\nDate & Time: ${date}\nStatus: ${status}`);
      });
    });

    // Confirm and Cancel (works independent of column position)
    document.querySelectorAll('.confirm-btn').forEach(button => {
      button.addEventListener('click', function() {
        const row = this.closest('tr');
        const statusCell = row.querySelector('.status');
        statusCell.textContent = 'Confirmed';
        statusCell.className = 'status text-success';
        computeReservationStats();
        alert('Reservation confirmed successfully!');
      });
    });

    document.querySelectorAll('.cancel-btn').forEach(button => {
      button.addEventListener('click', function() {
        const row = this.closest('tr');
        const statusCell = row.querySelector('.status');
        statusCell.textContent = 'Cancelled';
        statusCell.className = 'status text-danger';
        computeReservationStats();
        alert('Reservation cancelled successfully!');
      });
    });

    // Helper: get next reservation id based on existing table rows
    function getNextReservationId() {
      const rows = document.querySelectorAll('#reservationTable tbody tr');
      let max = 0;
      rows.forEach(r => {
        const txt = (r.cells[0] && r.cells[0].textContent) ? r.cells[0].textContent.trim() : '';
        const num = parseInt(txt.replace(/\D/g, ''), 10) || 0;
        if (num > max) max = num;
      });
      return 'R' + String(max + 1).padStart(3, '0');
    }

    function formatReservationDateFromInput(val) {
      // val is "YYYY-MM-DDTHH:MM" (datetime-local), produce "Nov 14, 2025 - 2:00 PM"
      if (!val) return '';
      const dt = new Date(val);
      if (isNaN(dt)) return val;
      const opts = { year:'numeric', month:'short', day:'numeric', hour:'numeric', minute:'2-digit', timeZone: 'Asia/Manila' };
      const s = dt.toLocaleString('en-PH', opts);
      return s.replace(',', ' -');
    }

    function escapeHtml(str) {
      return String(str)
        .replace(/&/g, '&amp;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;');
    }

    // Compute reservation stats and update the top cards
    function computeReservationStats() {
      const rows = document.querySelectorAll('#reservationTable tbody tr');
      let total = 0, pending = 0, cancelled = 0, completed = 0;
      rows.forEach(r => {
        total++;
        const status = (r.querySelector('.status') && r.querySelector('.status').textContent || '').trim();
        if (status === 'Pending') pending++;
        else if (status === 'Cancelled') cancelled++;
        else if (status === 'Confirmed' || status === 'Completed') completed++;
      });
      document.getElementById('totalReservations').textContent = total;
      document.getElementById('pendingCount').textContent = pending;
      document.getElementById('cancelledCount').textContent = cancelled;
      // Also update completed count card if desired
      document.getElementById('completedCount').textContent = completed;
    }

    // Reservation modal submit behavior: validate, append to table, attach handlers
    document.getElementById('submitReservationModalBtn')?.addEventListener('click', function() {
      const nameEl = document.getElementById('modalResCustomerName');
      const dtEl = document.getElementById('modalResDateTime');
      const alertEl = document.getElementById('reservationFormAlert');

      const name = nameEl ? nameEl.value.trim() : '';
      const dtVal = dtEl ? dtEl.value : '';

      if (!name) {
        if (alertEl) { alertEl.textContent = 'Please enter customer name.'; alertEl.style.display = 'block'; }
        return;
      }
      if (!dtVal) {
        if (alertEl) { alertEl.textContent = 'Please select date and time.'; alertEl.style.display = 'block'; }
        return;
      }
      if (alertEl) { alertEl.style.display = 'none'; }

      const id = getNextReservationId();
      const displayDate = formatReservationDateFromInput(dtVal) || dtVal;

      const tbody = document.querySelector('#reservationTable tbody');
      if (!tbody) return;

      const tr = document.createElement('tr');
      tr.dataset.customer = name;
      tr.innerHTML = `
        <td>${id}</td>
        <td>${escapeHtml(displayDate)}</td>
        <td class="status">Pending</td>
        <td><button class="btn btn-sm btn-quick view-btn">View Details</button></td>
        <td>
          <button class="btn btn-sm btn-success me-2 confirm-btn">Confirm</button>
          <button class="btn btn-sm btn-danger cancel-btn">Cancel</button>
        </td>
      `;
      tbody.prepend(tr);

      // Attach handlers for the new row buttons (use dataset.customer for name)
      const viewBtn = tr.querySelector('.view-btn');
      const confirmBtn = tr.querySelector('.confirm-btn');
      const cancelBtn = tr.querySelector('.cancel-btn');

      viewBtn?.addEventListener('click', function() {
        const row = this.closest('tr');
        const id = row.cells[0].textContent;
        const date = row.cells[1].textContent;
        const status = row.cells[2].textContent;
        const name = row.dataset.customer || '';
        alert(`Reservation Details:\n\nID: ${id}\nCustomer: ${name}\nDate & Time: ${date}\nStatus: ${status}`);
      });

      confirmBtn?.addEventListener('click', function() {
        const row = this.closest('tr');
        const statusCell = row.querySelector('.status');
        statusCell.textContent = 'Confirmed';
        statusCell.className = 'status text-success';
        computeReservationStats();
        alert('Reservation confirmed successfully!');
      });

      cancelBtn?.addEventListener('click', function() {
        const row = this.closest('tr');
        const statusCell = row.querySelector('.status');
        statusCell.textContent = 'Cancelled';
        statusCell.className = 'status text-danger';
        computeReservationStats();
        alert('Reservation cancelled successfully!');
      });

      // Clear modal inputs and hide modal
      if (nameEl) nameEl.value = '';
      if (dtEl) dtEl.value = '';

      // hide bootstrap modal programmatically
      try {
        const modalEl = document.getElementById('reservationModal');
        const bsModal = bootstrap.Modal.getInstance(modalEl) || new bootstrap.Modal(modalEl);
        bsModal.hide();
      } catch (e) {}

      // Update the linked cards now that a reservation was added
      computeReservationStats();

      // Focus back to open button for quick repeat entries
      document.getElementById('openReservationModalBtn')?.focus();
    });

    // Event delegation for reservation table: handle dynamic confirm/cancel/view clicks and keep stats in sync
    (function() {
      const tbody = document.querySelector('#reservationTable tbody');
      if (!tbody) return;
      tbody.addEventListener('click', function(e) {
        const confirmBtn = e.target.closest('.confirm-btn');
        const cancelBtn = e.target.closest('.cancel-btn');
        const viewBtn = e.target.closest('.view-btn');

        if (viewBtn) {
          const row = viewBtn.closest('tr');
          const id = row.cells[0].textContent;
          const date = row.cells[1].textContent;
          const status = row.cells[2].textContent;
          const name = row.dataset.customer || '';
          alert(`Reservation Details:\n\nID: ${id}\nCustomer: ${name}\nDate & Time: ${date}\nStatus: ${status}`);
          return;
        }

        if (confirmBtn) {
          const row = confirmBtn.closest('tr');
          const statusCell = row.querySelector('.status');
          statusCell.textContent = 'Confirmed';
          statusCell.className = 'status text-success';
          computeReservationStats();
          alert('Reservation confirmed successfully!');
          return;
        }

        if (cancelBtn) {
          const row = cancelBtn.closest('tr');
          const statusCell = row.querySelector('.status');
          statusCell.textContent = 'Cancelled';
          statusCell.className = 'status text-danger';
          computeReservationStats();
          alert('Reservation cancelled successfully!');
          return;
        }
      });
    })();

    function togglePaymentFields() {
    const select = document.getElementById('paymentType');
    const type = select ? select.value : '';
    const calc = document.getElementById('cashCalculator');
    const cashInput = document.getElementById('cashAmount');
    const changeEl = document.getElementById('changeDisplay');

    if (calc) {
      calc.style.display = type === 'Cash' ? 'block' : 'none';
    }

    if (type !== 'Cash') {
      if (cashInput) cashInput.value = '';
      if (changeEl) changeEl.innerText = '₱0.00';
    } else {
      computeChange();
    }
  }

    function computeChange() {
      let total = parseFloat(document.getElementById("totalAmount").innerText.replace("₱","")) || 0;
      let cash = parseFloat(document.getElementById("cashAmount").value) || 0;
      let change = cash - total;
      const changeEl = document.getElementById("changeDisplay");
      if (changeEl) changeEl.innerText = "₱" + change.toFixed(2);
    }

    // Add fade/slide animation on dropdown toggle
  const bell = document.getElementById('notifBell');
  bell?.addEventListener('click', function(e) {
      e.stopPropagation();
      const dropdown = bell.closest('.dropdown');
      if (dropdown) dropdown.classList.toggle('show'); // toggle show class for animation
  });
  // Poll for inventory alerts every 60 seconds
  function loadStockAlerts() {
    fetch('?action=get_stock_alerts', { method: 'GET', credentials: 'same-origin' })
      .then(r => r.text())
      .then(t => {
        try {
          return JSON.parse(t);
        } catch (err) {
          console.error('Invalid JSON received for stock alerts:\n', t);
          throw err;
        }
      })
      .then(res => {
        const list = document.getElementById('notifList');
        const countEl = document.getElementById('notifCount');
        if (!list || !countEl) return;
        if (res.status !== 'success' || !Array.isArray(res.alerts)) {
          const message = res && res.message ? res.message : 'Failed to load notifications';
          list.innerHTML = '<li class="dropdown-item text-muted">' + escapeHtml(message) + '</li>';
          countEl.style.display = 'none';
          return;
        }

        const alerts = res.alerts;
        if (alerts.length === 0) {
          list.innerHTML = '<li class="dropdown-item text-muted">No stock alerts</li>';
          countEl.style.display = 'none';
          return;
        }

        countEl.textContent = alerts.length;
        countEl.style.display = 'inline-block';

        list.innerHTML = '';
        console.debug('Stock alerts received:', alerts);
        alerts.forEach(a => {
          const li = document.createElement('li');
          li.className = 'dropdown-item';
          const severity = a.Low_Stock_Alert || 'Low';
          let severityClass = 'text-warning';
          if (severity === 'Critical') severityClass = 'text-danger';
          if (severity === 'Out of Stock') severityClass = 'text-secondary';

          li.innerHTML = `
            <div class="d-flex flex-column">
              <strong>${escapeHtml(a.Product_Name)}</strong>
              <small class="text-muted">Category: <span class="fw-semibold">${escapeHtml(a.Category || '')}</span></small>
              <small class="fw-bold ${severityClass}">${escapeHtml(severity)}: Only ${escapeHtml(String(a.Stock_Quantity))} left!</small>
            </div>
          `;

          li.addEventListener('click', function() {
            // Navigate to inventory and highlight product if available
            showContent('inventory');
            setTimeout(() => {
              const pid = a.Product_ID ? parseInt(a.Product_ID, 10) : null;
              if (!isNaN(pid)) {
                const el = document.querySelector(`[data-product-id=\"${pid}\"]`);
                if (el) {
                  // Highlight briefly
                  el.scrollIntoView({ behavior: 'smooth', block: 'center' });
                  el.classList.add('animate__animated', 'animate__pulse');
                  setTimeout(() => el.classList.remove('animate__animated', 'animate__pulse'), 1500);
                }
              }
            }, 200);
            // Close the dropdown
            try { new bootstrap.Dropdown(document.getElementById('notifBell')).hide(); } catch (e) {}
          });
          list.appendChild(li);
        });
      })
      .catch(err => {
        console.error('Error loading stock alerts:', err);
        const list = document.getElementById('notifList');
        const countEl = document.getElementById('notifCount');
        if (list) list.innerHTML = '<li class="dropdown-item text-muted">Failed to load notifications</li>';
        if (countEl) countEl.style.display = 'none';
      });
  }

  // Initial load and polling
  loadStockAlerts();
  setInterval(loadStockAlerts, 60000);

  // Optional: close dropdown if clicked outside
  document.addEventListener('click', function(e) {
      const dropdown = bell?.closest('.dropdown');
      if (dropdown && !dropdown.contains(e.target)) {
          dropdown.classList.remove('show');
      }
  });

  document.addEventListener('DOMContentLoaded', function () {
  const bell = document.getElementById('notifBell');
  if (!bell) return; // safety

  // detect badge either by id or by searching inside the bell
  const badge = document.getElementById('notifCount') || bell.querySelector('.badge');

  // If there's notification badge, add shake class
  if (badge) {
    bell.classList.add('bell-shake');
  }

  // Improve UX: stop wiggle when dropdown is opened, resume when closed
  const dropdown = bell.closest('.dropdown');
  if (!dropdown) return;

  // Use Bootstrap's dropdown events if available
  try {
    // bs5 uses 'show.bs.dropdown' and 'hidden.bs.dropdown'
    dropdown.addEventListener('show.bs.dropdown', () => {
      bell.classList.remove('bell-shake');
    });
    dropdown.addEventListener('hidden.bs.dropdown', () => {
      if (badge) bell.classList.add('bell-shake');
    });
  } catch (e) {
    // Fallback if bootstrap events unavailable — toggle on click
    dropdown.addEventListener('click', (ev) => {
      // if we clicked inside the bell/dropdown, toggle wiggle state
      setTimeout(() => {
        if (dropdown.classList.contains('show')) {
          bell.classList.remove('bell-shake');
        } else {
          if (badge) bell.classList.add('bell-shake');
        }
      }, 50);
    });
  }

  // Initialize reservation statistic cards from current table (empty => zeros)
  computeReservationStats();
  
  // Load all reservations from database by default
  loadReservationsFromDB();
  
  // Load reservation status overview
  loadReservationStatusOverview();
});

    // Load reservations from database
    function loadReservationsFromDB(status = null) {
      let url = '?action=get_reservations';
      if (status) {
        url += '&status=' + encodeURIComponent(status);
      }
      // Append cache-busting timestamp to ensure fresh data
      url += (url.indexOf('?') === -1 ? '?_=' : '&_=') + Date.now();
      fetch(url, {
        method: 'GET',
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success' && res.reservations) {
          // Show only 'Pending' and 'Confirmed' in the staff reservations table
          const filtered = res.reservations.filter(item => {
            const s = (item.Payment_Status || '').trim();
            return s === 'Pending' || s === 'Confirmed';
          });
          renderReservationsTable(filtered);
          computeReservationStats();
        }
      })
      .catch(err => {
        console.error('Error loading reservations:', err);
      });
    }

    // Load reservation status overview
    function loadReservationStatusOverview() {
      fetch('?action=get_reservation_status_overview', {
        method: 'GET',
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success' && res.data) {
          const data = res.data;
          
          // Update cards
          document.getElementById('totalReservations').textContent = data.total_count;
          document.getElementById('pendingCount').textContent = data.Pending.count;
          document.getElementById('completedCount').textContent = data.Completed.count;
          document.getElementById('cancelledCount').textContent = data.Cancelled.count;
          
          // Update values below cards
          document.getElementById('overviewPendingValue').textContent = parseFloat(data.Pending.total_value).toFixed(2);
          document.getElementById('overviewCompletedValue').textContent = parseFloat(data.Completed.total_value).toFixed(2);
          document.getElementById('overviewCancelledValue').textContent = parseFloat(data.Cancelled.total_value).toFixed(2);
        }
      })
      .catch(err => {
        console.error('Error loading reservation status overview:', err);
      });
    }

    // Render reservations in the table
    function renderReservationsTable(reservations) {
      const tbody = document.getElementById('reservationTableBody');
      if (!tbody) return;
      
      tbody.innerHTML = '';
      
      if (reservations.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">No reservations found</td></tr>';
        return;
      }

      reservations.forEach(res => {
        const tr = document.createElement('tr');
        tr.dataset.customer = res.customer_name || 'Guest';
        tr.dataset.reservationId = res.Reservation_ID;
        
        const date = new Date(res.Reservation_Date);
        const formattedDate = date.toLocaleString('en-PH', { 
          year:'numeric', month:'short', day:'numeric', hour:'2-digit', minute:'2-digit', timeZone: 'Asia/Manila' 
        });
        
        let statusClass = 'bg-warning';
        let statusText = res.Payment_Status;
        if (res.Payment_Status === 'Confirmed') statusClass = 'bg-info';
        else if (res.Payment_Status === 'Completed') statusClass = 'bg-success';
        else if (res.Payment_Status === 'Cancelled') statusClass = 'bg-danger';
        
        // Determine which buttons to show based on status
        let actionButtons = '';
        if (res.Payment_Status === 'Pending') {
          actionButtons = `
            <button class="btn btn-sm btn-success me-1 confirm-btn" onclick="confirmReservation(${res.Reservation_ID}, this)">
              <i class="bi bi-check-circle"></i> Confirm
            </button>
            <button class="btn btn-sm btn-danger cancel-btn" onclick="cancelReservation(${res.Reservation_ID}, this)">
              <i class="bi bi-x-circle"></i> Cancel
            </button>
          `;
        } else if (res.Payment_Status === 'Confirmed') {
          actionButtons = `
            <button class="btn btn-sm btn-primary complete-btn" onclick="completeReservation(${res.Reservation_ID}, this)">
              <i class="bi bi-check2-circle"></i> Complete
            </button>
          `;
        } else {
          actionButtons = '<span class="text-muted">No actions available</span>';
        }
        
        tr.innerHTML = `
          <td>${res.Reservation_ID}</td>
          <td>${escapeHtml(res.customer_name || 'Guest')}</td>
          <td>${escapeHtml(res.Product_Name || 'N/A')}</td>
          <td>₱${parseFloat(res.Price || 0).toFixed(2)}</td>
          <td>${formattedDate}</td>
          <td><span class="badge ${statusClass} status">${statusText}</span></td>
          <td>${actionButtons}</td>
        `;
        
        tbody.appendChild(tr);
      });
    }

    // Confirm reservation
    window.confirmReservation = function(reservationId, btnEl) {
      if (!confirm('Confirm this reservation?')) return;
      
      const btn = btnEl instanceof HTMLElement ? btnEl : (event && event.target ? event.target.closest('button') : null);
      const originalHtml = btn ? btn.innerHTML : '';
      if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>'; }
      
      const formData = new FormData();
      formData.append('action', 'confirm_reservation');
      formData.append('reservation_id', reservationId);
      
      fetch(window.location.pathname, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success') {
          alert('Reservation confirmed successfully!');
          loadReservationsFromDB();
          loadReservationStatusOverview();
        } else {
          alert('Error: ' + (res.message || 'Failed to confirm reservation'));
          if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; }
        }
      })
      .catch(err => {
        console.error(err);
        alert('Network error. Please try again.');
        if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; }
      });
    }

    // Complete reservation
    window.completeReservation = function(reservationId, btnEl) {
      if (!confirm('Mark this reservation as complete? This will add the amount to revenue and create a completed order.')) return;
      
      const btn = btnEl instanceof HTMLElement ? btnEl : (event && event.target ? event.target.closest('button') : null);
      const originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
      
      const formData = new FormData();
      formData.append('action', 'complete_reservation');
      formData.append('reservation_id', reservationId);
      
      fetch(window.location.pathname, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })
      .then(r => {
        if (!r.ok) {
          throw new Error('HTTP ' + r.status + ' ' + r.statusText);
        }
        return r.text();
      })
      .then(text => {
        try {
          const res = JSON.parse(text);
          if (res.status === 'success') {
            alert('Reservation completed successfully! Revenue added: ₱' + parseFloat(res.revenue || 0).toFixed(2));
            loadReservationsFromDB();
            // Reload dashboard stats to reflect new revenue
            loadDashboardStats();
            loadReservationStatusOverview();
          } else {
            alert('Error: ' + (res.message || 'Failed to complete reservation'));
            btn.disabled = false;
            btn.innerHTML = originalHtml;
          }
        } catch (e) {
          console.error('Invalid JSON response:', text);
          alert('Server returned invalid response. Check console for details.');
          btn.disabled = false;
          btn.innerHTML = originalHtml;
        }
      })
      .catch(err => {
        console.error('Complete reservation error:', err);
        alert('Network error: ' + err.message + '. Please try again.');
        if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; }
      });
    }

    // Cancel reservation (existing function, now works with database)
    window.cancelReservation = function(reservationId, btnEl) {
      if (!confirm('Cancel this reservation?')) return;
      
      const btn = btnEl instanceof HTMLElement ? btnEl : (event && event.target ? event.target.closest('button') : null);
      const originalHtml = btn.innerHTML;
      btn.disabled = true;
      btn.innerHTML = '<span class="spinner-border spinner-border-sm"></span>';
      
      const formData = new FormData();
      formData.append('action', 'cancel_reservation');
      formData.append('reservation_id', reservationId);
      
      fetch(window.location.pathname, {
        method: 'POST',
        body: formData,
        credentials: 'same-origin'
      })
      .then(r => r.json())
      .then(res => {
        if (res.status === 'success') {
          alert('Reservation cancelled successfully!');
          // If the server provided the updated reservation, update the row immediately
          try {
            if (res.reservation && res.reservation.Reservation_ID) {
              const rid = String(res.reservation.Reservation_ID);
              const rows = document.querySelectorAll('#reservationTableBody tr');
              for (const r of rows) {
                if ((r.dataset.reservationId || r.cells[0]?.textContent || '').trim() === rid) {
                  // Update status cell
                  const statusCell = r.querySelector('.status');
                  if (statusCell) {
                    statusCell.textContent = res.reservation.Payment_Status || 'Cancelled';
                    // Update badge bg class
                    statusCell.className = 'badge bg-danger status';
                  }
                  // Remove action buttons for a cancelled reservation
                  const actionsCell = r.cells[6];
                  if (actionsCell) {
                    actionsCell.innerHTML = '<span class="text-muted">No actions available</span>';
                  }
                  break;
                }
              }
            }
          } catch (e) { console.error('Failed to update reservation row in DOM:', e); }
          // Still reload from DB to ensure counts and other rows are fresh
          loadReservationsFromDB();
          loadReservationStatusOverview();
        } else {
          // If server provided current reservation status, show clear message
          const currentStatus = res.reservation && res.reservation.Payment_Status ? res.reservation.Payment_Status : null;
          if (currentStatus) {
            alert('Failed to cancel reservation. Current status: ' + currentStatus);
          } else {
            alert('Error: ' + (res.message || 'Failed to cancel reservation'));
          }
          if (btn) { btn.disabled = false; btn.innerHTML = originalHtml; }
        }
      })
      .catch(err => {
        console.error(err);
        alert('Network error. Please try again.');
        btn.disabled = false;
        btn.innerHTML = originalHtml;
      });
    }

    // --- Elegant Stat Card Styles ---
    // Add gradient brown style and hover animation (this duplicates .stat-card rules above minimally)
    const style = document.createElement('style');
    style.innerHTML = `
      .stat-card:hover {
        box-shadow: 0 12px 32px rgba(111,78,55,0.18);
        transform: translateY(-6px) scale(1.02);
        background: linear-gradient(135deg, #c1976b 0%, #d7b79a 100%);
      }
      .gradient-brown {
        background: linear-gradient(135deg, #d7b79a 0%, #c1976b 100%) !important;
        color: #4d2e00 !important;
      }
    `;
    document.head.appendChild(style);

    // === Menu button behavior (minimal JS, keeps rest unchanged) ===
    (function(){
      const btn = document.getElementById('menuBtn');
      const panel = document.getElementById('menuPanel');

      if (!btn || !panel) return;
      btn.addEventListener('click', function(e){
        e.stopPropagation();
        panel.classList.toggle('show');
        const expanded = panel.classList.contains('show');
        btn.setAttribute('aria-expanded', expanded ? 'true' : 'false');
      });

      // close panel when clicking anywhere else
      document.addEventListener('click', function(e){
        if (!panel.contains(e.target) && e.target !== btn) {
          panel.classList.remove('show');
          btn.setAttribute('aria-expanded', 'false');
        }
      });

      // close using Escape
      document.addEventListener('keydown', function(e){
        if (e.key === 'Escape') {
          panel.classList.remove('show');
          btn.setAttribute('aria-expanded', 'false');
        }
      });
    })();
  </script>
</body>
</html>
