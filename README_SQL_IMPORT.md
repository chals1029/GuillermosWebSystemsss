# SQL Import Setup Guide

This guide explains where to place the project folder and how to import the database SQL file.

## 1. Place Project Folder in Correct Web Root

Choose based on your local server:

### If you are using XAMPP

Move the project folder to:

`C:\xampp\htdocs\GuillermosWebSystemss`

### If you are using Laragon

Move the project folder to:

`C:\laragon\www\GuillermosWebSystemss`

## 2. Start Services

1. Start Apache and MySQL.
2. Open phpMyAdmin.

## 3. Create Database

Create a database named:

`u435394025_guillermos_db`

## 4. Import SQL File

1. In phpMyAdmin, click the database `u435394025_guillermos_db`.
2. Click Import.
3. Select this file from the project root:

`u435394025_guillermos (2).sql`

4. Click Go.

## 5. Configure Environment

1. Copy `.env.example` to `.env`.
2. Update database values in `.env` if needed:
   - `DB_HOST`
   - `DB_PORT`
   - `DB_DATABASE`
   - `DB_USERNAME`
   - `DB_PASSWORD`

## 6. Run the App

Open in browser:

- XAMPP: `http://localhost/GuillermosWebSystemss/Views/landing/index.php`
- Laragon: `http://localhost/GuillermosWebSystemss/Views/landing/index.php`
