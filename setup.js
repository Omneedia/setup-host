var fs = require('fs');
var path = require('path');
var request = require('request');
var figlet = require('figlet');
var colorize = require('colors');
var shelljs = require('shelljs');
const uuidv4 = require('uuid/v4');
var crypto = require('crypto');
var shasum = crypto.createHash('sha512');
var inquirer = require('inquirer');
var os = require("os");
var emoji = require('node-emoji');
var PID="";

var CA_CERT=__dirname+path.sep+'tls'+path.sep+'ca.pem';
var CA_KEY=__dirname+path.sep+'tls'+path.sep+'ca-key.pem';
var CLIENT_CERT=__dirname+path.sep+'tls'+path.sep+'cert.pem';
var CLIENT_KEY=__dirname+path.sep+'tls'+path.sep+'key.pem';
var SERVER_CERT=__dirname+path.sep+'tls'+path.sep+'server.pem';
var SERVER_KEY=__dirname+path.sep+'tls'+path.sep+'server-key.pem';
var PASSPHRASE='0mneediaRulez!';

var _service=[
	'[Service]',
	'ExecStart=/usr/bin/nodejs /opt/worker/bin/worker.js',
	'Restart=always',
	'StandardOutput=syslog',
	'StandardError=syslog',
	'SyslogIdentifier=OAWORKER',
	'User=root',
	'Group=root',
	'Environment=NODE_ENV=production',
	' ',
	'[Install]',
	'WantedBy=multi-user.target'	
];

function error(err) {
	console.log('\n'+emoji.get('heavy_exclamation_mark')+" "+err.red+"\n");
	process.exit();	
};

function getIPAddress() {
  var interfaces = require('os').networkInterfaces();
  for (var devName in interfaces) {
    var iface = interfaces[devName];

    for (var i = 0; i < iface.length; i++) {
      var alias = iface[i];
      if (alias.family === 'IPv4' && alias.address !== '127.0.0.1' && !alias.internal)
        return alias.address;
    }
  }

  return '0.0.0.0';
}

var daemon = {
    "hosts": [
        "unix:///var/run/docker.sock",
        "tcp://0.0.0.0:2376"
    ],
    "labels": [],
    "tls": true,
    "tlscacert": "/etc/docker/ca.pem",
    "tlscert": "/etc/docker/server.pem",
    "tlskey": "/etc/docker/server-key.pem",
    "tlsverify": true
};

var questions=[
	{
 		type: 'input',
  		name: 'URL',
  		message: 'Cluster URL',
		default: 'https://api.omneedia.com/'
	},
	{
		type: 'input',
		name: 'LOGIN',
		message: 'Login'
	},
	{
		type: 'password',
		name: 'PASSWORD',
		message: 'Password'
	},
	{
 		type: 'input',
  		name: 'IP',
  		message: 'Host IP',
		default: getIPAddress()
	},
	{
 		type: 'input',
  		name: 'DNS',
  		message: 'Host DNS',
		default: os.hostname()
	},
	{
 		type: 'input',
  		name: 'LABEL',
  		message: 'Host label',
		default: uuidv4()
	},
];

function makeTLS(A) {
	if (!fs.existsSync(__dirname+path.sep+'tls')) fs.mkdirSync(__dirname+path.sep+'tls'); else {
		shelljs.rm('-rf',__dirname+path.sep+'tls');
		fs.mkdirSync(__dirname+path.sep+'tls');
	};
	console.log(' ');
	console.log(emoji.get('key')+' Generating server certificate ');
	
	var cmd='openssl genrsa -aes256 -passout pass:$PASSPHRASE -out $CA_KEY 2048';
	cmd=cmd.replace('$PASSPHRASE',PASSPHRASE).replace('$CA_KEY',CA_KEY);
	shelljs.exec(cmd,{silent:true});
	
	var cmd='openssl req -new -x509 -days 365 -key $CA_KEY -sha256 -passin pass:$PASSPHRASE -subj "/C=FR/ST=MyState/O=MyOrg" -out $CA_CERT';	cmd=cmd.replace('$CA_KEY',CA_KEY).replace('$PASSPHRASE',PASSPHRASE).replace('$CA_CERT',CA_CERT);
	shelljs.exec(cmd,{silent:true});
	
	var cmd='openssl genrsa -out $SERVER_KEY 2048'.replace('$SERVER_KEY',SERVER_KEY);
	shelljs.exec(cmd,{silent:true});
	var cmd='openssl req -subj "/CN='+A.DNS+'" -new -key $SERVER_KEY -out server.csr 2>/dev/null';
	cmd=cmd.replace('$SERVER_KEY',SERVER_KEY);
	shelljs.exec(cmd,{silent:true});
	var cmd='openssl req -subj "/CN='+A.DNS+'" -new -key $SERVER_KEY -out server.csr 2>/dev/null';
	cmd=cmd.replace('$SERVER_KEY',SERVER_KEY);
	shelljs.exec(cmd,{silent:true});
	fs.writeFileSync('extfile.cnf','subjectAltName = IP:'+A.IP);
	var cmd='openssl x509 -passin pass:$PASSPHRASE -req -days 365 -in server.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $SERVER_CERT -extfile extfile.cnf';
	cmd=cmd.replace('$PASSPHRASE',PASSPHRASE).replace('$CA_CERT',CA_CERT).replace('$CA_KEY',CA_KEY).replace('$SERVER_CERT',SERVER_CERT);
	shelljs.exec(cmd,{silent:true});
	
	console.log('						'+emoji.get('heavy_check_mark').green+' done.');
	console.log(' ');
	console.log(emoji.get('key')+' Generating client keys ');
	
	var cmd='openssl genrsa -out $CLIENT_KEY 2048'.replace('$CLIENT_KEY',CLIENT_KEY);
	shelljs.exec(cmd,{silent:true});
	var cmd="openssl req -subj '/CN=client' -new -key $CLIENT_KEY -out client.csr 2>/dev/null";
	cmd=cmd.replace('$CLIENT_KEY',CLIENT_KEY);
	shelljs.exec(cmd,{silent:true});
	fs.writeFileSync('extfile.cnf','extendedKeyUsage = clientAuth')
	var cmd='openssl x509 -passin pass:$PASSPHRASE -req -days 365 -in client.csr -CA $CA_CERT -CAkey $CA_KEY -CAcreateserial -out $CLIENT_CERT -extfile extfile.cnf';
	cmd=cmd.replace('$PASSPHRASE',PASSPHRASE).replace('$CA_CERT',CA_CERT).replace('$CA_KEY',CA_KEY).replace('$CLIENT_CERT',CLIENT_CERT);
	shelljs.exec(cmd,{silent:true});
	
	console.log('						'+emoji.get('heavy_check_mark').green+' done.');
	console.log(' ');
	
	console.log(emoji.get('eight_pointed_black_star').green+' Configuring server.');
	
	fs.unlinkSync('client.csr');
	fs.unlinkSync('server.csr');
	fs.unlinkSync('extfile.cnf');
	fs.unlinkSync('tls/ca.srl');
	
	fs.chmodSync(CA_KEY,400);
	fs.chmodSync(CLIENT_KEY,400);
	fs.chmodSync(SERVER_KEY,400);
	fs.chmodSync(CA_CERT,444);
	fs.chmodSync(SERVER_CERT,444);
	fs.chmodSync(CLIENT_CERT,444);
	
	fs.copyFileSync(CA_CERT,'/etc/docker/'+path.basename(CA_CERT));
	fs.renameSync(SERVER_CERT,'/etc/docker/'+path.basename(SERVER_CERT));
	fs.renameSync(SERVER_KEY,'/etc/docker/'+path.basename(SERVER_KEY));
	
	fs.writeFileSync('/etc/docker/daemon.json',JSON.stringify(daemon,null,4));
	
	var service = '/etc/systemd/system/multi-user.target.wants/docker.service';
	var inf=fs.readFileSync(service,'utf-8').split('\n');
	for (var i=0;i<inf.length;i++) {
		if (inf[i].substr(0,9)=="ExecStart") inf[i]='ExecStart=/usr/bin/dockerd';	
	};
	fs.writeFileSync(service,inf.join('\n'));
	
	shelljs.exec('systemctl daemon-reload',{silent:true});
	shelljs.exec('service docker restart',{silent:true});
	
	console.log('						'+emoji.get('heavy_check_mark').green+' done.');
	console.log(' ');
	
	console.log(emoji.get('eight_pointed_black_star').green+' Registering server.');
	
	var ca=fs.readFileSync('tls/'+path.basename(CA_CERT),'utf-8');
	var cert=fs.readFileSync('tls/'+path.basename(CLIENT_CERT),'utf-8');
	var key=fs.readFileSync('tls/'+path.basename(CLIENT_KEY),'utf-8');
	var info={
		
	};
	var info={
		hid: require('shortid').generate(),
		pid: PID,
		ca: ca.split('\n').join('|'),
		cert: cert.split('\n').join('|'),
		key: key.split('\n').join('|'),
		ip: A.IP,
		host: A.DNS,
		label: A.LABEL
	};
	request({
		url: A.URL+'api/register_host', 
		form: info,
		method: "post", 
		encoding: null
	}, function (err, resp, body) {
		if (err) return error("Server is unreachable. Check your proxy settings or try again later.");
		//console.log(body.toString('utf-8'));
		var response=JSON.parse(body.toString('utf-8'));
		if (response.status=="success") {
			console.log('						'+emoji.get('heavy_check_mark').green+' done.'); 
		} else {
			console.log('						'+emoji.get('heavy_exclamation_mark').green+' Failed.'); 
			console.log(JSON.stringify(response,null,4).yellow);
			console.log(' ');
			return;
		};
		delete info.pid;
		delete info.ca;
		delete info.cert;
		delete info.key;
		fs.writeFileSync('/root/.omneedia',JSON.stringify(info));
		if (!fs.existsSync(__dirname+path.sep+'..'+path.sep+'worker'+path.sep+'config')) fs.mkdirSync(__dirname+path.sep+'..'+path.sep+'worker'+path.sep+'config');
		var conf={
			cluster: response.cluster,
			port: 9090
		};	fs.writeFileSync(__dirname+path.sep+'..'+path.sep+'worker'+path.sep+'config'+path.sep+'worker.json',JSON.stringify(conf,null,4));
		// install service
		fs.writeFileSync('/etc/systemd/system/multi-user.target.wants/oaworker.service',_service.join('\n'));
		shelljs.exec('systemctl daemon-reload',{silent:false});
		shelljs.exec('service oaworker restart',{silent:false});
		console.log(' Your server is up and running!'.green);
		console.log(' ');
	});	
};

function Answer(A) {
	shasum.update(A.PASSWORD);
	request({
		url: A.URL+'login', 
		form: {
			l: A.LOGIN, 
			p: shasum.digest('hex')
		},
		method: "post", 
		encoding: null
	}, function (err, resp, body) {
		if (err) return error("Server is unreachable. Check your proxy settings or try again later.");
		var response=JSON.parse(body.toString('utf-8'));
		if (response.success) PID=response.pid; else error("Access denied.");
		console.log('');
		console.log(emoji.get('heavy_check_mark').green+' Access granted.');
		makeTLS(A);
	});
};



figlet('omneedia.setup', function(err, data) {
	console.log(err);
	console.log(data.cyan);
	console.log(' ');
	console.log('This script will guide you through the process of creating and registering an omneedia host.'.green);
	console.log(' ');
	inquirer.prompt(questions).then(Answer);
});
