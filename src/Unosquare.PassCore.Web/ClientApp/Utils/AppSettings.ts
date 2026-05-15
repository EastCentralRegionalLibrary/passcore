//AppSettings.ts

import { IGlobalContext } from "../types/Providers";

export async function resolveAppSettings(): Promise<IGlobalContext> {
    const response = await fetch('api/password');

    if (!response || !response.ok) {
        throw new Error('Error fetching settings.');
    }

    const responseBody = await response.text();

    try {
        const data: IGlobalContext = responseBody ? JSON.parse(responseBody) : {};
        return data;
    } catch (error) {
        console.error('Error parsing AppSettings:', error);
        throw new Error('Failed to parse AppSettings.');
    }
}