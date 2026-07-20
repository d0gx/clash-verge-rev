const SERVICE_BUNDLE_MANIFEST_SCHEMA = 1

async function collectFileHashes(files, calculateFileHash) {
  const hashes = {}

  for (const { targetFile, targetPath } of files) {
    const hash = await calculateFileHash(targetPath)
    if (!hash) return null
    hashes[targetFile] = hash
  }

  return hashes
}

export async function createServiceBundleManifest(
  identity,
  files,
  calculateFileHash,
) {
  const hashes = await collectFileHashes(files, calculateFileHash)
  if (!hashes) {
    throw new Error('Unable to hash installed service bundle')
  }

  return {
    schemaVersion: SERVICE_BUNDLE_MANIFEST_SCHEMA,
    ...identity,
    files: hashes,
  }
}

export async function serviceBundleMatches(
  manifest,
  identity,
  files,
  calculateFileHash,
) {
  if (
    manifest?.schemaVersion !== SERVICE_BUNDLE_MANIFEST_SCHEMA ||
    manifest.repository !== identity.repository ||
    manifest.version !== identity.version ||
    manifest.sidecarHost !== identity.sidecarHost
  ) {
    return false
  }

  const hashes = await collectFileHashes(files, calculateFileHash)
  if (!hashes) return false

  return files.every(
    ({ targetFile }) => manifest.files?.[targetFile] === hashes[targetFile],
  )
}
