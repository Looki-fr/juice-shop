/*
 * Copyright (c) 2014-2026 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import path from 'node:path'
import { type Request, type Response, type NextFunction } from 'express'

import * as utils from '../lib/utils'
import * as security from '../lib/insecurity'
import { challenges } from '../data/datacache'
import * as challengeUtils from '../lib/challengeUtils'

export function servePublicFiles () {
  return ({ params }: Request, res: Response, next: NextFunction) => {
    const file = params.file

    // FIX: Instead of checking what is NOT allowed, we check against an allowlist.
    // This prevents traversal characters (../) and unexpected file types.
    const allowedFiles = [
      'acquisitions.md',
      'legal.md',
      'incident-support.kdbx',
      'juiceshop_presskit.pdf'
    ]

    if (allowedFiles.includes(file)) {
      verify(file, res, next)
    } else {
      res.status(403)
      next(new Error('Access denied: The requested file is not in the public repository.'))
    }
  }

  function verify (file: string, res: Response, next: NextFunction) {
    // We keep the original logic for challenge solving but use a safe absolute path.
    file = security.cutOffPoisonNullByte(file)

    challengeUtils.solveIf(challenges.directoryListingChallenge, () => { return file.toLowerCase() === 'acquisitions.md' })
    verifySuccessfulPoisonNullByteExploit(file)

    // Securely resolve the path relative to the intended directory
    const root = path.resolve('ftp')
    const filePath = path.join(root, file)

    // Ensure the resolved path is still within the 'ftp' directory (Defense in Depth)
    if (filePath.startsWith(root)) {
      res.sendFile(filePath)
    } else {
      res.status(403)
      next(new Error('Path traversal attempt detected.'))
    }
  }

  function verifySuccessfulPoisonNullByteExploit (file: string) {
    challengeUtils.solveIf(challenges.easterEggLevelOneChallenge, () => { return file.toLowerCase() === 'eastere.gg' })
    challengeUtils.solveIf(challenges.forgottenDevBackupChallenge, () => { return file.toLowerCase() === 'package.json.bak' })
    challengeUtils.solveIf(challenges.forgottenBackupChallenge, () => { return file.toLowerCase() === 'coupons_2013.md.bak' })
    challengeUtils.solveIf(challenges.misplacedSignatureFileChallenge, () => { return file.toLowerCase() === 'suspicious_errors.yml' })

    challengeUtils.solveIf(challenges.nullByteChallenge, () => {
      return challenges.easterEggLevelOneChallenge.solved || challenges.forgottenDevBackupChallenge.solved || challenges.forgottenBackupChallenge.solved ||
        challenges.misplacedSignatureFileChallenge.solved || file.toLowerCase() === 'encrypt.pyc'
    })
  }
}