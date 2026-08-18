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
            // Read the anchor's attributes with the platform's own HTML parser rather
            // than with a regex of our own. The two regexes this replaces drew
            // SonarQube's S8786, super-linear runtime from backtracking: both began
            // with an unanchored `(\w+)=`, so on a run of word characters containing
            // no `=` the engine retried from every start position. Rewriting the
            // quoted value with non-backtracking negated classes does not help, since
            // that prefix is the part that backtracks; there is no formulation of
            // "word characters, then an equals sign" that avoids it.
            //
            // The parser has no such cost, and it decodes entity references, so
            // href="a&amp;b" now yields the URL the author wrote. It is also stricter
            // about nothing and more permissive about unquoted values, which suits a
            // function already documented as garbage-in, garbage-out.
            //
            // parseFromString does not execute scripts, and this only reads attributes
            // off the result, so no new trust boundary appears here: href reached the
            // rendered anchor from the same configured help text before.
            const anchor = new DOMParser().parseFromString(`<a ${parts[i + 1]}></a>`, 'text/html').body
                .firstElementChild;

            const href = anchor?.getAttribute('href') || '#';
            const target = anchor?.getAttribute('target') ?? undefined;
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
