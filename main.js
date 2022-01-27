'use strict'

const es = require('evilscan')
const Express = require('express')
const { readFileSync } = require('fs')

const { PORT } = JSON.parse(readFileSync('./config.json'))

Express()
    .use(require('cors')())
    .get('/', async (req, res) => {
        let ip = req.query.ip
        let pr = req.query.pr

        if ( !ip ) res.redirect('/')
        if ( !pr ) pr = '80,443'

        let dataResponse = new String()

        console.log(`[${new Date().toLocaleString()}] ${ip} scanning ports ${pr}`)
        try {
            let O = new Promise((res, rej) => {
                let scanner = new es({
                    target: ip,
                    port: pr,
                    status: 'TROU'
                })

                let resp = new String()
                scanner.on('result', (result) => {
                    resp += `${result.ip}|${result.port}|${result.status === 'open' ? 'open' : 'closed'}\n`
                })

                scanner.on('error', (err) => rej(err))
                scanner.on('done', () => res(resp))
                scanner.run()
            })

            dataResponse = await O
        } catch (err) {
            console.log(err)
            dataResponse = err
        }

        console.log(`[${new Date().toLocaleString()}] ${ip} done.`)
        res.end(dataResponse)
    })
    .all('*', (_, res) => res.end('nmap-api // github.com/110594'))
    .listen(process.env.PORT || PORT, _ => console.log(`API running on port ${PORT}`))