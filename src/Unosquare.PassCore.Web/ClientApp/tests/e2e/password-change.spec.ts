import { test, expect } from '@playwright/test';

test.describe('Password Change Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should change password successfully with valid credentials', async ({ page }) => {
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 200);

    await page.getByLabel('Username', { exact: true }).fill('someuser@test.com');
    await page.getByLabel('Current Password', { exact: true }).fill('OldPassword123!');
    await page.getByLabel('New Password', { exact: true }).fill('SecurePassword123!');
    await page.getByLabel('Re-enter New Password', { exact: true }).fill('SecurePassword123!');

    await page.getByRole('button', { name: /change password/i }).click();

    await responsePromise;
    await expect(page.getByTestId('success-dialog')).toBeVisible();
    await expect(page.locator('text=You have changed your password successfully')).toBeVisible();
  });

  test('should show error for invalid current password', async ({ page }) => {
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.getByLabel('Username', { exact: true }).fill('invalidCredentials@test.com');
    await page.getByLabel('Current Password', { exact: true }).fill('wrong');
    await page.getByLabel('New Password', { exact: true }).fill('SecurePassword123!');
    await page.getByLabel('Re-enter New Password', { exact: true }).fill('SecurePassword123!');

    await page.getByRole('button', { name: /change password/i }).click();

    await responsePromise;
    await expect(page.getByTestId('snackbar-notification')).toBeVisible();
    await expect(page.locator('text=You need to provide the correct current password')).toBeVisible();
  });

  test('should show error for user not found', async ({ page }) => {
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.getByLabel('Username', { exact: true }).fill('userNotFound@test.com');
    await page.getByLabel('Current Password', { exact: true }).fill('OldPassword123!');
    await page.getByLabel('New Password', { exact: true }).fill('SecurePassword123!');
    await page.getByLabel('Re-enter New Password', { exact: true }).fill('SecurePassword123!');

    await page.getByRole('button', { name: /change password/i }).click();

    await responsePromise;
    await expect(page.getByTestId('snackbar-notification')).toBeVisible();
    await expect(page.locator('text=We could not find your user account')).toBeVisible();
  });

  test('should show error for change not permitted (group policy)', async ({ page }) => {
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.getByLabel('Username', { exact: true }).fill('changeNotPermitted@test.com');
    await page.getByLabel('Current Password', { exact: true }).fill('OldPassword123!');
    await page.getByLabel('New Password', { exact: true }).fill('SecurePassword123!');
    await page.getByLabel('Re-enter New Password', { exact: true }).fill('SecurePassword123!');

    await page.getByRole('button', { name: /change password/i }).click();

    await responsePromise;
    await expect(page.getByTestId('snackbar-notification')).toBeVisible();
    await expect(page.locator('text=Your password cannot be changed at this time')).toBeVisible();
  });

  test('should show error for password policy violation', async ({ page }) => {
    const responsePromise = page.waitForResponse(response => response.url().includes('/api/password') && response.status() === 400);

    await page.getByLabel('Username', { exact: true }).fill('complexPassword@test.com');
    await page.getByLabel('Current Password', { exact: true }).fill('OldPassword123!');
    await page.getByLabel('New Password', { exact: true }).fill('SecurePassword123!');
    await page.getByLabel('Re-enter New Password', { exact: true }).fill('SecurePassword123!');

    await page.getByRole('button', { name: /change password/i }).click();

    await responsePromise;
    await expect(page.getByTestId('snackbar-notification')).toBeVisible();
    await expect(page.locator('text=The new password was rejected by the domain')).toBeVisible();
  });
});
