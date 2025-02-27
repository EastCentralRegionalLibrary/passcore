import fs from 'fs'; // Import fs using ES6 syntax
import packageJson from './package.json' with { type: "json" }; // Import JSON to retrieve version

const version = packageJson.version;
const versionFileContent = `// Generated version file
export const appVersion = '${version}';
`;

fs.writeFileSync('ClientApp\\version.ts', versionFileContent);

console.log(`Version file generated at version.ts with version: ${version}`);