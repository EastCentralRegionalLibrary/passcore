import { test, expect } from '@playwright/test';

test.describe('Password Change Flow', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('should change password successfully with valid credentials', async ({ page }) => {
    await page.fill('input[name="username"]', 'someuser');
    await page.fill('input[name="currentPassword"]', 'OldPassword123!');
    await page.fill('input[name="newPassword"]', 'NewPassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'NewPassword123!');

    await page.click('button[type="submit"]');

    // Wait for success message
    await expect(page.locator('text=You have changed your password successfully')).toBeVisible();
  });

  test('should show error for invalid current password', async ({ page }) => {
    // In our debug provider, the 'invalidCredentials' username triggers this error
    await page.fill('input[name="username"]', 'invalidCredentials');
    await page.fill('input[name="currentPassword"]', 'wrong');
    await page.fill('input[name="newPassword"]', 'NewPassword123!');
    await page.fill('input[name="newPasswordVerify"]', 'NewPassword123!');

    await page.click('button[type="submit"]');

    await expect(page.locator('text=You need to provide the correct current password')).toBeVisible();
  });
});
