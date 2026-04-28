import { test, expect } from '@playwright/test';
import { TEST_USERS, ALERTS } from './test-constants';

test.describe('Password Change Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    // Wait for the form to be loaded and ready
    await page.waitForSelector('input[name="username"]');
  });

  test('should change password successfully with valid credentials', async ({ page }) => {
    const user = TEST_USERS.SUCCESS;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    // Wait for the API response
    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    // Success shows a dialog
    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await expect(dialog.getByText(ALERTS.SUCCESS, { exact: false })).toBeVisible();

    // Close dialog to clean up
    await dialog.getByRole('button', { name: 'Ok' }).click();
    await expect(dialog).not.toBeVisible();
  });

  test('should show error for invalid current password', async ({ page }) => {
    const user = TEST_USERS.INVALID_CREDENTIALS;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    // Errors show in an alert (Snackbar)
    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible({ timeout: 10000 });
    await expect(alert.getByText(ALERTS.INVALID_CREDENTIALS, { exact: false })).toBeVisible();
  });

  test('should show error for user not found', async ({ page }) => {
    const user = TEST_USERS.USER_NOT_FOUND;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible({ timeout: 10000 });
    await expect(alert.getByText(ALERTS.USER_NOT_FOUND, { exact: false })).toBeVisible();
  });

  test('should show error for complexity policy violation', async ({ page }) => {
    const user = TEST_USERS.COMPLEX_PASSWORD;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible({ timeout: 10000 });
    await expect(alert.getByText(ALERTS.COMPLEX_PASSWORD, { exact: false })).toBeVisible();
  });

  test('should show error for restricted group membership', async ({ page }) => {
    const user = TEST_USERS.RESTRICTED_GROUP;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible({ timeout: 10000 });
    await expect(alert.getByText(ALERTS.NOT_ALLOWED, { exact: false })).toBeVisible();
  });

  test('should show error for not being in allowed group', async ({ page }) => {
    const user = TEST_USERS.NOT_ALLOWED_GROUP;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    const alert = page.getByRole('alert');
    await expect(alert).toBeVisible({ timeout: 10000 });
    await expect(alert.getByText(ALERTS.NOT_ALLOWED, { exact: false })).toBeVisible();
  });

  test('should change password successfully for user in allowed group', async ({ page }) => {
    const user = TEST_USERS.ALLOWED_USER;
    await page.fill('input[name="username"]', user.username);
    await page.fill('input[name="currentPassword"]', user.currentPassword);
    await page.fill('input[name="newPassword"]', user.newPassword);
    await page.fill('input[name="newPasswordVerify"]', user.newPassword);

    const responsePromise = page.waitForResponse(response =>
        response.url().includes('/api/password') && response.request().method() === 'POST'
    );
    await page.click('button:has-text("Change Password")');
    await responsePromise;

    const dialog = page.getByRole('dialog');
    await expect(dialog).toBeVisible({ timeout: 10000 });
    await expect(dialog.getByText(ALERTS.SUCCESS, { exact: false })).toBeVisible();

    await dialog.getByRole('button', { name: 'Ok' }).click();
  });
});
