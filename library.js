'use strict';

((module) => {
	const User = require.main.require('./src/user');
	const Groups = require.main.require('./src/groups');
	const db = require.main.require('./src/database');
	const authenticationController = require.main.require('./src/controllers/authentication');
	const Settings = require.main.require('./src/settings');
	const privileges = require.main.require('./src/privileges');


	const async = require('async');
	const { PassportOIDC } = require('./src/passport-fusionauth-oidc');

	const passport = module.parent.require('passport');
	const nconf = module.parent.require('nconf');
	const winston = module.parent.require('winston');

	const constants = {
		name: 'fusionauth-oidc',
		callbackURL: '/auth/fusionauth-oidc/callback',
		pluginSettingsURL: '/admin/plugins/fusionauth-oidc',
		pluginSettings: new Settings('fusionauth-oidc', '1.0.0', {
			// Default settings
			clientId: null,
			clientSecret: null,
			emailClaim: 'email',
			discoveryBaseURL: null,
			authorizationEndpoint: null,
			tokenEndpoint: null,
			userInfoEndpoint: null,
		}, false, false),
	};

	const Oidc = {};

	/**
	 * Sets up the router bindings for the settings page
	 * @param params
	 * @param callback
	 */
	Oidc.init = function (params, callback) {
		winston.verbose('Setting up FusionAuth OIDC bindings/routes');

		function render(req, res) {
			res.render('admin/plugins/fusionauth-oidc', {
				baseUrl: nconf.get('url'),
			});
		}

		params.router.get(constants.pluginSettingsURL, params.middleware.admin.buildHeader, render);
		params.router.get('/api/admin/plugins/fusionauth-oidc', render);

		callback();
	};

	/**
	 * Binds the passport strategy to the global passport object
	 * @param strategies The global list of strategies
	 * @param callback
	 */
	Oidc.bindStrategy = function (strategies, callback) {
		winston.verbose('Setting up openid connect');

		callback = callback || function () {
		};

		constants.pluginSettings.sync(function (err) {
			if (err) {
				return callback(err);
			}

			const settings = constants.pluginSettings.getWrapper();

			// If we are missing any settings
			if (!settings.clientId ||
				!settings.clientSecret ||
				!settings.emailClaim ||
				!settings.authorizationEndpoint ||
				!settings.tokenEndpoint ||
				!settings.userInfoEndpoint) {
				winston.info('OpenID Connect will not be available until it is configured!');
				return callback();
			}

			settings.callbackURL = nconf.get('url') + constants.callbackURL;

			// If you call this twice it will overwrite the first.
			passport.use(constants.name, new PassportOIDC(settings, (req, accessToken, refreshToken, profile, callback) => {
				const email = profile['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier'];//profile[settings.emailClaim || 'email'];
				let isAdmin = false;
				// Tahaluf Start Block
				if(profile[settings.rolesClaim] != undefined){
					isAdmin = settings.rolesClaim ? (profile[settings.rolesClaim] === 'System_Admin') : false; //|| (profile[settings.rolesClaim].some && profile[settings.rolesClaim].some((value) => value === 'System_Admin')) : false;
				} 
				else 
				{
					return callback(new Error('This User Not Related To Any Group !'));
				}

				// Tahaluf End Block

				Oidc.login({
					oAuthid: profile.sub,
					username: email.split('@')[0],//profile.preferred_username || email.split('@')[0],
					email: email,
					rolesEnabled: settings.rolesClaim && settings.rolesClaim.length !== 0,
					isAdmin: isAdmin,
					groupName:profile[settings.rolesClaim],
					permissions : profile.Permission === undefined ? [] : profile.Permission ,
				}, (err, user) => {
					if (err) {
						return callback(err);
					}

					authenticationController.onSuccessfulLogin(req, user.uid);
					callback(null, user);
				});
			}));

			// If we are doing the update, strategies won't be the right object so
			if (strategies.push) {
				strategies.push({
					name: constants.name,
					url: '/auth/' + constants.name,
					callbackURL: '/auth/' + constants.name + '/callback',
					icon: 'fa-openid',
					scope: ['openid', settings.emailClaim],
				});
			}

			callback(null, strategies);
		});
	};

	
	Oidc.login = function (payload, callback) {
		async.waterfall([
			// Lookup user by existing oauthid
			(callback) => Oidc.getUidByOAuthid(payload.oAuthid, callback),
			// Skip if we found the user in the pevious step or create the user
			function (uid, callback) {
				if (uid !== null) {

			async.waterfall([
				(callback) => Oidc.getUidByOAuthid(payload.oAuthid, callback),
				function (uid, callback) {
					if (uid > 0) {
						prepareGroup({
							groupName: payload.groupName,
							userId : uid,
						}, callback);
					} else {
					callback(null, uid);
					}
				},
				function (uid, callback) {
					if (payload.groupName != '') {
						giveDefaultPrivileges({
							groupName: payload.groupName,
							userId : uid,
						}, callback);
					} else {
						callback(null, uid); 
					}
				},
			], callback);

				} else {
					// New User
					if (!payload.email) {
						return callback(new Error('The email was missing from the user, we cannot log them in.'));
					}

					async.waterfall([
						(callback) => User.getUidByEmail(payload.email, callback),
						function (uid, callback) {
							if (!uid) {
								User.create({
									username: payload.username,
									email: payload.email,
								}, callback);
							} else {
								callback(null, uid); // Existing account -- merge
							}
						},
						function (uid, callback) {
							// Save provider-specific information to the user
							User.setUserField(uid, constants.name + 'Id', payload.oAuthid);
							db.setObjectField(constants.name + 'Id:uid', payload.oAuthid, uid);

							callback(null, uid);
						},
						function (uid, callback) {
							if (uid > 0) {
								prepareGroup({
									groupName: payload.groupName,
									userId : uid,
								}, callback);
							} else {
								callback(null, uid); // Existing account -- merge
							}
						},
						function (uid, callback) {
							if (payload.groupName != '') {
								giveDefaultPrivileges({
									groupName: payload.groupName,
									userId : uid,
								}, callback);
							} else {
								callback(null, uid); // Existing account -- merge
							}
						},
					], callback);
				}
			},
			// Get the users membership status to admins
			(uid, callback) => Groups.isMember(uid, 'administrators', (err, isMember) => {
				callback(err, uid, isMember);
			}),
			// If the plugin is configured to use roles, add or remove them from the admin group (if necessary)
			(uid, isMember, callback) => {
				if (payload.rolesEnabled) {
					if (payload.isAdmin === true && !isMember) {
						Groups.join('administrators', uid, (err) => {
							callback(err, uid);
						});
					} else if (payload.isAdmin === false && isMember) {
						Groups.leave('administrators', uid, (err) => {
							callback(err, uid);
						});
					} else {
						// Continue
						callback(null, uid);
					}
				} else {
					// Continue
					callback(null, uid);
				}
			},
		], function (err, uid) {
			if (err) {
				return callback(err);
			}
			callback(null, {
				uid: uid,
			});
		});
	};

	async function prepareGroup(data, callback) {
		const allSystemGroups = await db.getSortedSetRange('groups:createtime', 0, -1);
		const exists = await Groups.exists(data.groupName);

		if (exists) {
			const isMember = await Groups.isMember(data.userId, data.groupName); // to be used if needed

			await Promise.all([
				Groups.leave(allSystemGroups, data.userId),
				//giveDefaultPrivileges(data.groupName),
			]);
			await callback(null, data.userId);
		} else {
			await Groups.create({
				name: data.groupName,
				userTitle: data.groupName,
				description: 'Forum wide members of ' + data.groupName,
				hidden: 0,
				private: 1,
				disableJoinRequests: 1,
			});
			await Promise.all([
				Groups.leave(allSystemGroups, data.userId),
				Groups.join(data.groupName, data.userId),
				//giveDefaultPrivileges(data.groupName, data.permissions, data.userId),
			]);
			await callback(null, data.userId);
		}
	}

	async function giveDefaultPrivileges(group, callback) {

		let data = '';
		let permisstions = [];
		let resArray = [];

		const https = require('https')
		const options = {
			hostname: 'events.tahaluf.ae',
			port: 443,
			path: '/SecurityAPi/api/security/group/' + group.groupName + '/permissions',
			method: 'GET',
			async:true,
			headers: {
				'ApiKey': 'VVuUND0qDNW0MTosWVl8DM2XZrK5DLNnnldBwvcsXv8=9c28ba29-abd0-49af-acaa-180ef90c922b',
				'AccountCode': 'NHP',
			}
		}
		const req = https.request(options, res => {
			console.log(`statusCode: ${res.statusCode}`);

			res.on('data', function (items) {
				data += items;
			});

			res.on('end', async function () {
				resArray = JSON.parse(data);
				resArray.forEach(item => permisstions.push(item.code));
				if (permisstions.length > 0) {
					await privileges.global.give(permisstions, group.groupName);
					await Groups.join(group.groupName, group.userId),
					await callback(null, group.userId);
				}
			});
		})

		req.on('error', error => {
			console.error(error)
		})

		

		req.end();

		/*
		let defaultPrivileges = permissions;

		if(defaultPrivileges.length == 0){
			
			await Groups.join('verified-users' , userId);

			defaultPrivileges = [
				'groups:chat', 'groups:upload:post:image', 'groups:signature', 'groups:search:content',
				'groups:search:users', 'groups:search:tags', 'groups:view:users', 'groups:view:tags', 'groups:view:groups',
				'groups:local:login',
			];
		}
		
		await privileges.global.give(defaultPrivileges, groupName);
		*/
	}

	Oidc.getUidByOAuthid = function (oAuthid, callback) {
		db.getObjectField(constants.name + 'Id:uid', oAuthid, (err, uid) => {
			if (err) {
				return callback(err);
			}
			callback(null, uid);
		});
	};

	Oidc.deleteUserData = function (data, callback) {
		async.waterfall([
			async.apply(User.getUserField, data.uid, constants.name + 'Id'),
			(oAuthIdToDelete, next) => {
				db.deleteObjectField(constants.name + 'Id:uid', oAuthIdToDelete, next);
			},
		], (err) => {
			if (err) {
				winston.error('[sso-oauth] Could not remove OAuthId data for uid ' + data.uid + '. Error: ' + err);
				return callback(err);
			}

			callback(null, data);
		});
	};

	// If this filter is not there, the deleteUserData function will fail when getting the oauthId for deletion.
	Oidc.whitelistFields = function (params, callback) {
		params.whitelist.push(constants.name + 'Id');
		callback(null, params);
	};

	Oidc.bindMenuOption = function (header, callback) {
		winston.verbose('Binding menu option');
		header.authentication.push({
			route: constants.pluginSettingsURL.replace('/admin', ''), // They will add the /admin for us
			name: 'OpenID Connect',
		});

		callback(null, header);
	};

	Oidc.redirectLogout = function (payload, callback) {
		const settings = constants.pluginSettings.getWrapper();

		if (settings.logoutEndpoint) {
			winston.verbose('Changing logout to OpenID logout');
			let separator;
			if (settings.logoutEndpoint.indexOf('?') === -1) {
				separator = '?';
			} else {
				separator = '&';
			}
			payload.next = settings.logoutEndpoint + separator + 'client_id=' + settings.clientId;
		}

		return callback(null, payload);
	};

	module.exports = Oidc;
})(module);
