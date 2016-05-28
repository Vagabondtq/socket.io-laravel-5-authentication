'use strict'

let redis  = require('redis').createClient(6379, '127.0.0.1'),
	mcrypt = require('mcrypt'),
	PHPUnserialize = require('php-unserialize')

module.exports = {
	getSessionId: function(cookie, secret) {
		try {
			cookie = JSON.parse(new Buffer(cookie, 'base64'))
		} catch(err) {
			return false
		}

		let iv    = new Buffer(cookie.iv, 'base64');
		let value = new Buffer(cookie.value, 'base64');

		let rij_cbc = new mcrypt.MCrypt('rijndael-128', 'cbc');
			rij_cbc.open(secret, iv);

		let decrypted = rij_cbc.decrypt(value).toString();

		let len = decrypted.length - 1;
		let pad = decrypted.charAt(len).charCodeAt(0);

		let session_id = PHPUnserialize.unserialize(decrypted.substr(0, decrypted.length - pad));

		return session_id;
	},
	getSession: function(session_id, item) {
		session_id = 'laravel:' + session_id

		return new Promise(function(resolve, reject) {
			redis.getClient().get(session_id, function(err, session) {
				try {
					session = PHPUnserialize.unserialize(PHPUnserialize.unserialize(session))

					resolve(session)
				} catch (err) {
					console.log('Error unserializing session', err)
					
					reject(err)
				}
			})
		})
	}
}