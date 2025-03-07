import { ApiResponse } from '../types/Providers';

/**
 * Makes an HTTP request and returns a typed API response.
 *
 * This function mirrors the server's API response structure, which contains an optional list of errors and a payload.
 *
 * @template T - The type of the payload contained in the ApiResponse. Defaults to unknown.
 * @param url - The API endpoint URL.
 * @param requestMethod - The HTTP method (e.g., 'GET', 'POST').
 * @param requestBody - Optional request payload. If this is not a string, it will be stringified.
 * @returns A promise that resolves to an ApiResponse of type T.
 */
export async function fetchRequest<T = unknown>(
    url: string,
    requestMethod: string,
    requestBody?: unknown
): Promise<ApiResponse<T>> {
    // Create headers indicating we expect and send JSON.
    const headers = new Headers({
        Accept: 'application/json',
        'Content-Type': 'application/json',
    });

    // Determine the body. If requestBody is already a string, use it directly.
    const body =
        typeof requestBody === 'string'
            ? requestBody
            : requestBody
                ? JSON.stringify(requestBody)
                : null;

    // Create a Request object with the provided parameters.
    const request = new Request(url, {
        body,
        headers,
        method: requestMethod,
    });

    // Perform the fetch request.
    const response = await fetch(request);
    const responseBody = await response.text();

    try {
        // Parse and return the response as a typed ApiResponse.
        return responseBody ? (JSON.parse(responseBody) as ApiResponse<T>) : ({} as ApiResponse<T>);
    } catch (error) {
        console.error('Error parsing API response:', error);
        throw new Error(`Failed to parse API response: ${(error as Error).message}`);
    }
}
