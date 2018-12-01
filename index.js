var express = require('express');
var app = express();
app.use(express.static('public'));

var bodyParser = require('body-parser');
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); 

var url = require('url');

const ecc = require('eosjs-ecc')
const { Api, JsonRpc, JsSignatureProvider } = require('eosjs');

const fetch = require('node-fetch');                            // node only; not needed in browsers
const { TextDecoder, TextEncoder } = require('text-encoding');  // node, IE11 and IE Edge Browsers  

app.use(function (req, res, next) {
    res.header("Access-Control-Allow-Origin", "*");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    next();
});

app.get('/verify', async function (request, response) {

    var urlParts = url.parse(request.url, true);
    var parameters = urlParts.query;
    var student = parameters.student; 
    var sig = parameters.sig;
  
    var privKey = process.env.HCM_PRIV_KEY;
    var publicKey = ecc.privateToPublic(privKey);
      
    var data = ecc.sha256(student + publicKey);
    var result = ecc.recover(sig, data) === publicKey;

    response.json({
        result: result
    })
  
});

app.get('/sign', async function (request, response) {

    //if this student really has dgree
  
    var urlParts = url.parse(request.url, true);
    var parameters = urlParts.query;
    var student = parameters.student; 
  
    var privKey = process.env.HCM_PRIV_KEY;
    var publicKey = ecc.privateToPublic(privKey);
  
    var data = ecc.sha256(student + publicKey);
    var sig = ecc.sign(data, privKey);    

    response.json({
        data:data,
        sig: sig
    })  
  
});

app.get('/hash', async function (request, response) {

    var urlParts = url.parse(request.url, true);
    var parameters = urlParts.query;
    var student = parameters.student; 
  
    var privKey = process.env.HCM_PRIV_KEY;
    var publicKey = ecc.privateToPublic(privKey);
  
    var data = ecc.sha256(student + publicKey);  

    response.json({
        data:data
    })  
  
});



app.listen(3000, function () {
    console.log('Example app listening on port 3000!')
  });