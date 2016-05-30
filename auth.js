'use strict'

let helpers = require('./helpers')

// Laravel Config
// ==============================================
const config = {
	'secret_key': new Buffer('CYR+MUBTKK/gkL7y6FhPeQqhAmv8vmUeNqUw6qGqNcE=', 'base64'),
	'auth_class': 'Illuminate\\Auth\\SessionGuard', // Dont escape to encode slashes...
	'auth_name' : 'login_web_'
}

// Server Initialization
// ==============================================
let server = require('http').createServer()

// Socket.IO Initialization
// ==============================================
let io = require('socket.io').listen(server)

// Check Laravel AUTH
io.use(function (socket, next) {
	if (socket.handshake.query.hasOwnProperty('laravel_session_cookie')) {
		let laravel_session_cookie = socket.handshake.query.laravel_session_cookie

		let session_id = helpers.laravel_session.getSessionId(laravel_session_cookie, config.secret_key);

		if (session_id == false) {
			console.log('Cookie is invalid')

			return next('Cookie is invalid', false)
		}

		logger.info('Session ID successfully decoded from cookie')

		helpers.laravel_session.getSession(session_id).then(function(session) {
			if (config.env == 'development') {
				console.log('Session: ', session)
				console.log('CSRF Token: ', socket.handshake.query.csrf_token)
				console.log('Login: ', user_key)
			}

			// CSRF check
			if (session.hasOwnProperty('_token') && session._token !== socket.handshake.query.csrf_token) {
				let message = 'CSRF token is invalid'

				console.log(message)

				return next(message, false)
			}

			// Generating user key
			let user_key = config.auth_name + crypto.createHash('sha1').update(config.auth_class).digest('hex')

			// Checking if user id is presented in session
			if (session !== null && session.hasOwnProperty(user_key)) {
				// Here you need to get user from db
				// You may do it in your way as you want
				db.users.findById(session[user_key]).then(function(User) {
					socket.user = User

					logger.info('User "' + User.Username + '" successfully authenticated')

					return next(null, true)
				}).catch(function(err) {
					let message = 'User not found'

					console.log(message)

					return next(message, false)
				})
			} else {
				let message = 'User ID not found in session'

				console.log(message)
					
				return next(message, false)
			}
		}).catch(function(err) {
			console.log(err.message)
			
			return next('Session not found', false)
		})
	} else {
		let message = 'No cookie transfered'

		console.log(message)
			
		return next(message, false)
	}
})

server.listen(3000)