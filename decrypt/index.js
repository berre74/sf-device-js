const crypto = require('@trust/webcrypto')
var ab2str = require('arraybuffer-to-string')

//don't forget npm install

async function decryptME() {
    //the aes key
    let hash = Buffer.from("6F9EC8C833F00D3F7153A818D2297119EA6E19A6770EDBACD57FD0DF4C09E423", "hex")

    //Make cryptokey object from this key
    let key = await crypto.subtle.importKey('raw', new Uint8Array(hash), 'AES-GCM', false, ['encrypt', 'decrypt']);

    //decrypt
    let output = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: Buffer.from("0bff3044d99d34a36128fd7878b67efa", "hex")
        },
        key,
        Buffer.from("8c1f791816cbcc096f1abc200cb8cd18c50391687202c63a90c19ab74331ec9479ddb87e08968321fddaa65093eabdb1118eb308b3134259e42adafd5e5c58111c571be1f7765e0df042f67d9f51980c39cf54466f0098c4a0ba1f647ccce8faa06723007f60f7ed6b1727dcaec1aab01c3186b0ab7007389e25492df01b990fde871f1254320de91f9cf9e9159667d4c787eea38c1ec20254f88cf75a2e85d61497caf65c1c8836a03b1451a893ee45adec16825c4ea102c618763139b351b234084bef432c29f811f14cf28ac6c58f1af9757849e24467138e29402b1e0ba334ef0dce70ddee92a060230fd6d0b7c6df5d47f0703078e070ccbadd34c1701192928a97d81a2db6c4d8aded2b4242054f6be4f464ccec9797f659def87ad8d739b1fd1e2c73de1097c384bf71c1faec882bc8fe193e6bd52b8fab0245cab590484da1093263840fc75fbb324d9a1e8a411792ffd8293764a00ce6d90a8f4d308cb3d3beb017216d3ab02858a8c70faf7296d9a8afb446286a09c93a53cbe00f24240a3332b711cd232ca1c88e73b62d2e70c9cfbc4e8f392e84654ef5", "hex")
    )

    //output result
    console.log(ab2str(output));
}

decryptME();