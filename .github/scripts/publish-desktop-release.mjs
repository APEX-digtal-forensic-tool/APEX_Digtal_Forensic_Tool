import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import {
  appendFileSync, copyFileSync, lstatSync, mkdirSync, readFileSync, readdirSync, writeFileSync,
} from 'node:fs';
import path from 'node:path';

// Promote the existing, verified build; do not rebuild or execute downloaded installers.
const config = JSON.parse(readFileSync('.github/desktop-release.json', 'utf8'));
const repo = process.env.GH_REPO;
assert.equal(repo, 'APEX-digtal-forensic-tool/APEX_Digtal_Forensic_Tool');
assert.match(config.tag, /^v\d+\.\d+\.\d+$/);
for (const key of ['target_commit', 'build_commit', 'head_commit']) {
  assert.match(config[key], /^[a-f0-9]{40}$/);
}
const gh = (...args) => execFileSync('gh', args, { encoding: 'utf8', maxBuffer: 16 * 1024 * 1024 });
const api = (resource, body) => JSON.parse(execFileSync('gh', [
  'api', `repos/${repo}/${resource}`, ...(body ? ['--method', 'POST', '--input', '-'] : []),
], {
  encoding: 'utf8', maxBuffer: 16 * 1024 * 1024,
  input: body ? JSON.stringify(body) : undefined,
}));
const digest = (file) => `sha256:${createHash('sha256').update(readFileSync(file)).digest('hex')}`;
const version = config.tag.slice(1);
const releaseURL = `https://github.com/${repo}/releases/tag/${config.tag}`;

function verify() {
  for (const [id, workflow] of [
    [config.desktop_run, '.github/workflows/desktop-ci.yml'],
    [config.security_run, '.github/workflows/mcp-ci.yml'],
  ]) {
    const run = api(`actions/runs/${id}`);
    assert.equal(run.repository.full_name, repo);
    assert.equal(run.head_repository.full_name, repo);
    assert.equal(run.head_sha, config.head_commit);
    assert.equal(run.path, workflow);
    assert.equal(run.status, 'completed');
    assert.equal(run.conclusion, 'success');
  }
  const target = api(`git/commits/${config.target_commit}`);
  const built = api(`git/commits/${config.build_commit}`);
  assert.equal(built.tree.sha, target.tree.sha, 'Release source differs from the CI build');
  assert.ok(built.parents.some((parent) => parent.sha === config.head_commit));
  assert.equal(config.target_commit, config.head_commit, 'Preview must target the exact reviewed branch commit');
  const pkg = api(`contents/frontend/package.json?ref=${config.target_commit}`);
  assert.equal(JSON.parse(Buffer.from(pkg.content, 'base64').toString('utf8')).version, version);
  const expectedNames = ['APEX-Windows-x64', 'APEX-macOS-arm64', 'APEX-macOS-x64'];
  assert.deepEqual(config.artifacts.map((item) => item.name).sort(), expectedNames.sort());
  for (const expected of config.artifacts) {
    const artifact = api(`actions/artifacts/${expected.id}`);
    assert.equal(artifact.name, expected.name);
    assert.equal(artifact.digest, expected.digest);
    assert.equal(artifact.expired, false);
    assert.equal(artifact.workflow_run.id, config.desktop_run);
    assert.equal(artifact.workflow_run.head_sha, config.head_commit);
  }
  const existingTag = api(`git/matching-refs/tags/${config.tag}`)
    .find((ref) => ref.ref === `refs/tags/${config.tag}`);
  if (existingTag) {
    assert.equal(existingTag.object.type, 'commit');
    assert.equal(existingTag.object.sha, config.target_commit, 'Existing tag points elsewhere');
  }
  return target.tree.sha;
}

const tree = verify();
if (process.argv[2] === 'verify') {
  appendFileSync(process.env.GITHUB_OUTPUT,
    `run_id=${config.desktop_run}\nartifact_ids=${config.artifacts.map((item) => item.id).join(',')}\n`);
  console.log('CI, preview source tree, package version and immutable artifacts verified.');
} else if (process.argv[2] === 'publish') {
  const files = [
    ['APEX-Windows-x64', `APEX Setup ${version}.exe`, `APEX-${version}-Windows-x64.exe`],
    ['APEX-macOS-arm64', `APEX-${version}-arm64.dmg`, `APEX-${version}-macOS-arm64.dmg`],
    ['APEX-macOS-arm64', `APEX-${version}-arm64-mac.zip`, `APEX-${version}-macOS-arm64.zip`],
    ['APEX-macOS-x64', `APEX-${version}.dmg`, `APEX-${version}-macOS-x64.dmg`],
    ['APEX-macOS-x64', `APEX-${version}-mac.zip`, `APEX-${version}-macOS-x64.zip`],
  ];
  mkdirSync('release-output', { recursive: true });
  for (const artifact of config.artifacts) {
    const actual = readdirSync(path.join('release-input', artifact.name)).sort();
    const expected = files.filter(([name]) => name === artifact.name).map(([, file]) => file).sort();
    assert.deepEqual(actual, expected, `Unexpected files in ${artifact.name}`);
  }
  for (const [artifact, input, output] of files) {
    const source = path.join('release-input', artifact, input);
    const stat = lstatSync(source);
    assert.ok(stat.isFile() && !stat.isSymbolicLink() && stat.size > 0);
    copyFileSync(source, path.join('release-output', output));
  }
  writeFileSync('release-output/build-provenance.json', JSON.stringify({
    tag: config.tag, target_commit: config.target_commit, build_commit: config.build_commit,
    source_tree: tree, desktop_run: config.desktop_run, security_run: config.security_run,
    artifacts: config.artifacts, code_signed: false, notarized: false,
  }, null, 2) + '\n');
  const outputFiles = readdirSync('release-output').filter((name) => name !== 'SHA256SUMS.txt').sort();
  writeFileSync('release-output/SHA256SUMS.txt', outputFiles.map((name) =>
    `${digest(path.join('release-output', name)).slice(7)}  ${name}\n`).join(''));
  outputFiles.push('SHA256SUMS.txt');
  const notes = readFileSync(config.notes, 'utf8');
  let release = api('releases?per_page=100').find((item) => item.tag_name === config.tag);
  if (!release) {
    // Use the creation response; the releases list can lag behind a successful write.
    release = api('releases', {
      tag_name: config.tag, target_commitish: config.target_commit, name: config.title,
      body: notes, prerelease: true, draft: true, make_latest: 'false',
    });
  }
  assert.ok(release, 'Draft release was not created');
  assert.equal(release.target_commitish, config.target_commit);
  assert.equal(release.body.trim(), notes.trim(), 'Existing release has different notes');
  assert.equal(release.prerelease, true);
  assert.ok(release.assets.every((asset) => outputFiles.includes(asset.name)), 'Unexpected release assets');
  for (const name of outputFiles) {
    const local = path.join('release-output', name);
    const existing = release.assets.find((asset) => asset.name === name);
    if (existing) {
      assert.equal(existing.digest, digest(local), `Existing asset differs: ${name}`);
    } else {
      assert.equal(release.draft, true, 'Will not modify an already published release');
      gh('release', 'upload', config.tag, local);
    }
  }
  const uploaded = api(`releases/${release.id}`);
  assert.equal(uploaded.assets.length, outputFiles.length);
  for (const name of outputFiles) {
    const asset = uploaded.assets.find((item) => item.name === name);
    assert.ok(asset && asset.state === 'uploaded');
    assert.equal(asset.size, lstatSync(path.join('release-output', name)).size);
    assert.equal(asset.digest, digest(path.join('release-output', name)));
  }
  if (uploaded.draft) gh('release', 'edit', config.tag, '--draft=false', '--prerelease');
  const published = api(`releases/${release.id}`);
  assert.equal(published.draft, false);
  assert.equal(api(`git/ref/tags/${config.tag}`).object.sha, config.target_commit);
  appendFileSync(process.env.GITHUB_STEP_SUMMARY,
    `[${config.title}](${releaseURL}) published with ${outputFiles.length} verified assets.\n`);
  console.log(releaseURL);
} else {
  throw new Error('Expected verify or publish');
}
