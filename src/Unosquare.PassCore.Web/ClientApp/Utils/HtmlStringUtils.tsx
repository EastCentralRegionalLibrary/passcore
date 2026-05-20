// HtmlStringUtils.tsx
import type { ReactNode } from 'react';

/**
 * Parses a limited HTML string, extracting plain text and links.
 * Any other HTML tags are treated as plain text.
 *
 * **Expected Format:**
 * - The function expects a well-formed HTML string with properly closed <a> tags.
 * - It is designed for a limited subset of HTML. Malformed input may result in
 *   unintended or omitted elements (i.e., garbage in, garbage out).
 *
 * @param {string} htmlString - The HTML string to parse.
 * @returns {ReactNode[]} - An array of React elements representing the parsed content.
 */
export function parsePlainTextAndLinks(htmlString: string): ReactNode[] {
    // Split the HTML string on anchor tags.
    // The regex captures two groups: the attributes and the inner text of the <a> tag.
    const parts = htmlString.split(/<a\s+([^>]+)>(.*?)<\/a>/);

    // After splitting, parts come in groups of three:
    //   parts[i]     -> plain text segment
    //   parts[i + 1] -> attributes string for the <a> element
    //   parts[i + 2] -> inner content for the <a> element
    const result: ReactNode[] = [];
    for (let i = 0; i < parts.length; i += 3) {
        if (parts[i]) {
            result.push(parts[i]);
        }

        if (i + 1 < parts.length) {
            // Extract attributes from the anchor tag using regex.
            // The regex accounts for potential trailing whitespace after each attribute.
            const attributes = parts[i + 1].match(/(\w+)=(['"])(.*?)\2\s*/g) || [];
            const attributeMap: { [key: string]: string } = {};

            attributes.forEach((attr: string) => {
                const match = attr.match(/(\w+)=(['"])(.*?)\2/);
                if (match) {
                    const [, key, , value] = match;
                    attributeMap[key] = value;
                }
            });

            const href = attributeMap.href || '#';
            const target = attributeMap.target;
            result.push(
                <a
                    key={href}
                    href={href}
                    target={target}
                    rel={target === '_blank' ? 'noopener noreferrer' : undefined}
                >
                    {parts[i + 2] || ''}
                </a>,
            );
        }
    }

    return result;
}
