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

For complete SQL import and local folder placement instructions (XAMPP and Laragon), see:

- `README_SQL_IMPORT.md`
