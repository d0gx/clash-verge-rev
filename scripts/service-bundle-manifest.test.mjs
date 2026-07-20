import assert from 'node:assert/strict'
import test from 'node:test'

import {
  createServiceBundleManifest,
  serviceBundleMatches,
} from './service-bundle-manifest.mjs'

const identity = {
  repository: 'example/service',
  version: 'v1.2.3',
  sidecarHost: 'x86_64-pc-windows-msvc',
}
const files = [
  {
    targetFile: 'clash-verge-service.exe',
    targetPath: 'resources/clash-verge-service.exe',
  },
  {
    targetFile: 'clash-verge-service-install.exe',
    targetPath: 'resources/clash-verge-service-install.exe',
  },
  {
    targetFile: 'clash-verge-service-uninstall.exe',
    targetPath: 'resources/clash-verge-service-uninstall.exe',
  },
]

test('matches an unchanged service bundle', async () => {
  const hashes = new Map(
    files.map(({ targetPath }) => [targetPath, `x64:${targetPath}`]),
  )
  const calculateFileHash = async (targetPath) => hashes.get(targetPath)
  const manifest = await createServiceBundleManifest(
    identity,
    files,
    calculateFileHash,
  )

  assert.equal(
    await serviceBundleMatches(manifest, identity, files, calculateFileHash),
    true,
  )
})

test('rejects a shared output path overwritten by another architecture', async () => {
  const hashes = new Map(
    files.map(({ targetPath }) => [targetPath, `x64:${targetPath}`]),
  )
  const calculateFileHash = async (targetPath) => hashes.get(targetPath)
  const manifest = await createServiceBundleManifest(
    identity,
    files,
    calculateFileHash,
  )

  for (const { targetPath } of files) {
    hashes.set(targetPath, `arm64:${targetPath}`)
  }

  assert.equal(
    await serviceBundleMatches(manifest, identity, files, calculateFileHash),
    false,
  )
})

test('rejects legacy manifests without file hashes', async () => {
  const legacyManifest = { ...identity }
  const calculateFileHash = async (targetPath) => `x64:${targetPath}`

  assert.equal(
    await serviceBundleMatches(
      legacyManifest,
      identity,
      files,
      calculateFileHash,
    ),
    false,
  )
})

test('rejects a manifest when an installed bundle file is missing', async () => {
  const calculateInitialHash = async (targetPath) => `x64:${targetPath}`
  const manifest = await createServiceBundleManifest(
    identity,
    files,
    calculateInitialHash,
  )
  const missingPath = files[1].targetPath
  const calculateCurrentHash = async (targetPath) =>
    targetPath === missingPath ? null : `x64:${targetPath}`

  assert.equal(
    await serviceBundleMatches(manifest, identity, files, calculateCurrentHash),
    false,
  )
})
