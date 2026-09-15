#!/usr/bin/env node
import fs from 'node:fs';
import path from 'node:path';
import process from 'node:process';

const args = process.argv.slice(2);
const check = args.includes('--check');
const version = args.find(arg => !arg.startsWith('--'));

const rootDir = process.cwd();
const rootPackagePath = path.join(rootDir, 'package.json');

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function writeJson(file, value) {
  fs.writeFileSync(file, `${JSON.stringify(value, null, 2)}\n`);
}

function listPackageJsons(dir) {
  const abs = path.join(rootDir, dir);
  if (!fs.existsSync(abs)) return [];
  return fs.readdirSync(abs, { withFileTypes: true })
    .filter(entry => entry.isDirectory())
    .map(entry => path.join(abs, entry.name, 'package.json'))
    .filter(file => fs.existsSync(file));
}

function setInternalRanges(pkg, internalNames, targetRange) {
  let changed = false;
  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = pkg[field];
    if (!deps) continue;
    for (const name of Object.keys(deps)) {
      if (internalNames.has(name) && deps[name] !== targetRange) {
        deps[name] = targetRange;
        changed = true;
      }
    }
  }
  return changed;
}

const rootPackage = readJson(rootPackagePath);
const targetVersion = version ?? rootPackage.version;

if (!targetVersion || !/^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$/.test(targetVersion)) {
  console.error(`Usage: node scripts/sync-package-versions.mjs [--check] <semver>`);
  process.exit(1);
}

const packageFiles = listPackageJsons('packages');
const exampleFiles = listPackageJsons('examples');
const packageManifests = packageFiles.map(file => ({ file, pkg: readJson(file) }));
const allManifests = [
  { file: rootPackagePath, pkg: rootPackage, root: true },
  ...packageManifests,
  ...exampleFiles.map(file => ({ file, pkg: readJson(file), example: true })),
];
const internalNames = new Set(packageManifests.map(({ pkg }) => pkg.name).filter(Boolean));
const targetRange = `^${targetVersion}`;
const errors = [];

function noteMismatch(message) {
  errors.push(message);
}

for (const manifest of allManifests) {
  const { file, pkg, root, example } = manifest;
  let changed = false;

  // The private workspace root and all packages under packages/* move in lockstep.
  // Example package versions are left alone, but their internal dependency ranges are synced.
  if (!example && pkg.version !== targetVersion) {
    if (check) noteMismatch(`${path.relative(rootDir, file)} version is ${pkg.version}, expected ${targetVersion}`);
    pkg.version = targetVersion;
    changed = true;
  }

  for (const field of ['dependencies', 'devDependencies', 'peerDependencies', 'optionalDependencies']) {
    const deps = pkg[field];
    if (!deps) continue;
    for (const name of Object.keys(deps)) {
      if (internalNames.has(name) && deps[name] !== targetRange) {
        if (check) noteMismatch(`${path.relative(rootDir, file)} ${field}.${name} is ${deps[name]}, expected ${targetRange}`);
      }
    }
  }

  if (setInternalRanges(pkg, internalNames, targetRange)) changed = true;

  if (changed && !check) writeJson(file, pkg);
}

if (check && errors.length > 0) {
  console.error(errors.join('\n'));
  process.exit(1);
}

if (!check) {
  console.log(`Synchronized workspace package versions to ${targetVersion}`);
}
