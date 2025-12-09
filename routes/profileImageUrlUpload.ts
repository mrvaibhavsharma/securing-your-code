/*
 * Copyright (c) 2014-2024 Bjoern Kimminich & the OWASP Juice Shop contributors.
 * SPDX-License-Identifier: MIT
 */

import fs = require('fs')
import { type Request, type Response, type NextFunction } from 'express'
import logger from '../lib/logger'

import { UserModel } from '../models/user'
import * as utils from '../lib/utils'
const security = require('../lib/insecurity')
const request = require('request')
const { URL } = require('url')
const net = require('net')

const dns = require('node:dns')
const net = require('net')

function isIpOrPrivate(hostname: string, cb: (result: boolean) => void) {
  // If hostname is already an IP, check directly, otherwise resolve it
  function isPrivate(ip: string) {
    // IPv6 localhost
    if (ip === '::1') return true
    // IPv4
    if (ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        ip.startsWith('127.') ||
        ip.startsWith('172.16.') ||
        ip.startsWith('172.17.') ||
        ip.startsWith('172.18.') ||
        ip.startsWith('172.19.') ||
        ip.startsWith('172.20.') ||
        ip.startsWith('172.21.') ||
        ip.startsWith('172.22.') ||
        ip.startsWith('172.23.') ||
        ip.startsWith('172.24.') ||
        ip.startsWith('172.25.') ||
        ip.startsWith('172.26.') ||
        ip.startsWith('172.27.') ||
        ip.startsWith('172.28.') ||
        ip.startsWith('172.29.') ||
        ip.startsWith('172.30.') ||
        ip.startsWith('172.31.')) {
      return true
    }
    // IPv6 link-local or unique-local
    if (ip.startsWith('fe80:') || ip.startsWith('fc00:') || ip.startsWith('fd00:')) return true
    // IPv6 unspecified
    if (ip === '::') return true
    return false
  }
  // If hostname is IP literal
  if (net.isIP(hostname)) {
    return cb(isPrivate(hostname))
  }
  // Otherwise, resolve
  dns.lookup(hostname, { all: true }, (err: any, addresses: Array<any>) => {
    if (err) return cb(true) // treat resolution errors as private/bad
    for (const addr of addresses) {
      if (isPrivate(addr.address)) return cb(true)
    }
    cb(false)
  })
}

module.exports = function profileImageUrlUpload () {
  return (req: Request, res: Response, next: NextFunction) => {
    if (req.body.imageUrl !== undefined) {
      const url = req.body.imageUrl
      // SSRF prevention: validate the URL
      let parsedUrl
      try {
        parsedUrl = new URL(url)
      } catch (e) {
        res.status(400).send('Invalid imageUrl provided.')
        return
      }
      // Only allow http(s) protocol
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        res.status(400).send('Protocol not allowed.')
        return
      }
      // Only allow specific hostnames for image sources
      const allowedHosts = ['images.example.com', 'cdn.example.org']
      if (!allowedHosts.includes(parsedUrl.hostname)) {
        res.status(400).send('Host not allowed.')
        return
      }
      // Disallow IP-literal and internal/private addresses
      isIpOrPrivate(parsedUrl.hostname, (blocked: boolean) => {
        if (blocked) {
          res.status(400).send('Host resolves to an internal or disallowed IP address.')
          return
        }
        if (url.match(/(.)*solve\/challenges\/server-side(.)*/) !== null) req.app.locals.abused_ssrf_bug = true
        const loggedInUser = security.authenticatedUsers.get(req.cookies.token)
        if (loggedInUser) {
          const imageRequest = request
            .get(url)
            .on('error', function (err: unknown) {
              UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
              logger.warn(`Error retrieving user profile image: ${utils.getErrorMessage(err)}; using image link directly`)
            })
            .on('response', function (res: Response) {
              if (res.statusCode === 200) {
                const ext = ['jpg', 'jpeg', 'png', 'svg', 'gif'].includes(url.split('.').slice(-1)[0].toLowerCase()) ? url.split('.').slice(-1)[0].toLowerCase() : 'jpg'
                imageRequest.pipe(fs.createWriteStream(`frontend/dist/frontend/assets/public/images/uploads/${loggedInUser.data.id}.${ext}`))
                UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: `/assets/public/images/uploads/${loggedInUser.data.id}.${ext}` }) }).catch((error: Error) => { next(error) })
              } else UserModel.findByPk(loggedInUser.data.id).then(async (user: UserModel | null) => { return await user?.update({ profileImage: url }) }).catch((error: Error) => { next(error) })
            })
        } else {
          next(new Error('Blocked illegal activity by ' + req.socket.remoteAddress))
        }
        res.location(process.env.BASE_PATH + '/profile')
        res.redirect(process.env.BASE_PATH + '/profile')
      })
    }
  }
}
