import { test, expect } from '@playwright/test';

test.describe('Password Change Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should change password successfully with valid credentials', async ({ page }) => {
    const consolePromise = page.waitForEvent('console', msg => msg.text() === '[PassCore:Success]');
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 200);

    await page.fill('input[name="username"]', 'someuser@test.com');
    await page.fill('input[name="currentPassword"]', 'OldPassword123!');
    await page.fill('input[name="newPassword"]', 'SecurePassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'SecurePassword123!');

    await page.click('button:has-text("Change Password")');

    await Promise.all([consolePromise, responsePromise]);
    await expect(page.locator('text=You have changed your password successfully')).toBeVisible();
  });

  test('should show error for invalid current password', async ({ page }) => {
    const consolePromise = page.waitForEvent('console', msg => msg.text() === '[PassCore:Error:InvalidCredentials]');
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.fill('input[name="username"]', 'invalidCredentials@test.com');
    await page.fill('input[name="currentPassword"]', 'wrong');
    await page.fill('input[name="newPassword"]', 'SecurePassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'SecurePassword123!');

    await page.click('button:has-text("Change Password")');

    await Promise.all([consolePromise, responsePromise]);
    await expect(page.locator('text=You need to provide the correct current password')).toBeVisible();
  });

  test('should show error for user not found', async ({ page }) => {
    const consolePromise = page.waitForEvent('console', msg => msg.text() === '[PassCore:Error:UserNotFound]');
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.fill('input[name="username"]', 'userNotFound@test.com');
    await page.fill('input[name="currentPassword"]', 'OldPassword123!');
    await page.fill('input[name="newPassword"]', 'SecurePassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'SecurePassword123!');

    await page.click('button:has-text("Change Password")');

    await Promise.all([consolePromise, responsePromise]);
    await expect(page.locator('text=We could not find your user account')).toBeVisible();
  });

  test('should show error for change not permitted (group policy)', async ({ page }) => {
    const consolePromise = page.waitForEvent('console', msg => msg.text() === '[PassCore:Error:ChangeNotPermitted]');
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.fill('input[name="username"]', 'changeNotPermitted@test.com');
    await page.fill('input[name="currentPassword"]', 'OldPassword123!');
    await page.fill('input[name="newPassword"]', 'SecurePassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'SecurePassword123!');

    await page.click('button:has-text("Change Password")');

    await Promise.all([consolePromise, responsePromise]);
    await expect(page.locator('text=You are not allowed to change your password')).toBeVisible();
  });

  test('should show error for password policy violation', async ({ page }) => {
    const consolePromise = page.waitForEvent('console', msg => msg.text() === '[PassCore:Error:ComplexPassword]');
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.fill('input[name="username"]', 'complexPassword@test.com');
    await page.fill('input[name="currentPassword"]', 'OldPassword123!');
    await page.fill('input[name="newPassword"]', 'SecurePassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'SecurePassword123!');

    await page.click('button:has-text("Change Password")');

    await Promise.all([consolePromise, responsePromise]);
    await expect(page.locator('text=Failed due to password complexity policies')).toBeVisible();
  });
});
