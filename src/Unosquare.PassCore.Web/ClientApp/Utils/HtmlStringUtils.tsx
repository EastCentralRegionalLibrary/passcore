// HtmlStringUtils.tsx
import * as React from 'react';

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
 * @returns {React.ReactNode[]} - An array of React elements representing the parsed content.
 */
export function parsePlainTextAndLinks(htmlString: string): React.ReactNode[] {
    // Split the HTML string on anchor tags.
    // The regex captures two groups: the attributes and the inner text of the <a> tag.
    const parts = htmlString.split(/<a\s+([^>]+)>(.*?)<\/a>/).filter(Boolean);

    return parts.reduce<React.ReactNode[]>((elements, part, index) => {
        // Expected parts array indices:
        // index % 3 === 0: Plain text segments.
        // index % 3 === 1: Attributes string for the <a> element.
        // index % 3 === 2: Inner text for the <a> element (already rendered as link content).
        if (index % 3 === 0) {
            // Plain text: push directly to elements.
            elements.push(part);
        } else if (index % 3 === 1) {
            // Extract attributes from the anchor tag using regex.
            // The regex now accounts for potential trailing whitespace after each attribute.
            const attributes = part.match(/(\w+)=(['"])(.*?)\2\s*/g) || [];
            const attributeMap: { [key: string]: string } = {};

            attributes.forEach((attr) => {
                const match = attr.match(/(\w+)=(['"])(.*?)\2/);
                if (match) {
                    const [, key, , value] = match;
                    attributeMap[key] = value;
                }
            });

            const href = attributeMap.href || '#';
            const target = attributeMap.target;
            elements.push(
                <a
                    key={index}
                    href={href}
                    target={target}
                    rel={target === '_blank' ? 'noopener noreferrer' : undefined}
                >
                    {parts[index + 1] || ''}
                </a>,
            );
        }
        // Skip index % 3 === 2 since that inner text is already rendered in the <a> element.
        return elements;
    }, []);
}
