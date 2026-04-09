# Guillermos Web Systems

## Setup Tutorial

1. Clone the repository.
2. Open the project folder.
3. Install PHP dependencies first:

```bash
composer install
```

4. Create your local environment file from the template:

```bash
copy .env.example .env
```

5. Configure your local values in `.env`.
6. Make sure your database exists and matches your local configuration.
7. Start your local server (Laragon/Apache) and open the app in your browser.

## Environment Code

Do not commit your `.env` file.

DM me for the actual `.env` values (API keys, OAuth credentials, and other private settings).

## Notes

- `.env` is ignored by git.
- `.env.example` is safe to commit and should only contain placeholders.

## Backend Password Testing

Use this PowerShell command to test backend password rules:

```powershell
Invoke-WebRequest "http://localhost/guillermoswebsystemss/TestingBackend/test.php?password=Test123!" | Select-Object -ExpandProperty Content
```

This returns JSON showing each password rule check and whether the password is strong.

## SQL Import Guide

This guide explains where to place the project folder and how to import the database SQL file.

### 1. Place Project Folder in Correct Web Root

Choose based on your local server:

#### If you are using XAMPP

Move the project folder to:

`C:\xampp\htdocs\GuillermosWebSystemss`

#### If you are using Laragon

Move the project folder to:

`C:\laragon\www\GuillermosWebSystemss`

### 2. Start Services

1. Start Apache and MySQL.
2. Open phpMyAdmin.

### 3. Create Database

Create a database named:

`u435394025_guillermos_db`

### 4. Import SQL File

1. In phpMyAdmin, click the database `u435394025_guillermos_db`.
2. Click Import.
3. Select this file from the project root:

`u435394025_guillermos (2).sql`

4. Click Go.

### 5. Configure Environment

1. Copy `.env.example` to `.env`.
2. Update database values in `.env` if needed:
	- `DB_HOST`
	- `DB_PORT`
	- `DB_DATABASE`
	- `DB_USERNAME`
	- `DB_PASSWORD`

### 6. Run the App

Open in browser:

- For both XAMPP and Laragon: `http://localhost/guillermoswebsystemss/Views/landing/index.php`
