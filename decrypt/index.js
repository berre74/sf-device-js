const crypto = require('@trust/webcrypto')
var ab2str = require('arraybuffer-to-string')

const secret = "ZrvcwsWtZmqunpWjl-L_RSgueq7PIwPIIPn1WhArTT8";
const sHex = Buffer.from("ee844b5f8321a5c3", "hex");
const iv = Buffer.from("523a7daa64993c9b4c8fe2dda6f34277", "hex");
const ct = Buffer.from("b2cc9b9c42a00795191599e3acc98d117e440e1afc1e5927b23cafdbf75c2ef433cb197cf76fc9c17afdbe1b58ff7394974570d18194cd71defbbf7a4b1435f62fb4ddc423e48117ee9b36a825d44b920b56a45f821816ce602eab151b2ddef92e55b45d38744daffe555ba7fe0aef20cae039e3d619a229fe4645b68ab98c989b1e35520c7d97e04df7cce8e334ad4a59f130317ef77a90451a9012620f1431e4a1249f9b507ea2d27a4a9722eab9b22efbd537c17361d45855931fa86a19d2ad66325b7275886ca81ad8f2005953a2a7f27029aff4365c0f74b520327141e14741598a0dd73bd806341cfab973a30637d7ced01025a65a454f322620c755929200ac464561dd1a76f922506d00d345ccb007b433d21f2a524a42fbc887131d576dff2479dead0b5219feb73393ae9eb852a95744563a5688c33ecb968e6d116e16545cfea2332635d7b148e3a665b31b5b57f4e12ddb3bdf8f0edc0de18f3736aa83d76fc62bcc853453cf72c21ad985bdaf07acaba821948ba9083074c92c13bfe002dd71464ee8d1410eb16b3c726525543da150d864f5fcdef558", "hex");

async function decryptME() {
    //the aes key derived from debugging in the browser
    //let hash = Buffer.from("a7c193ae14848eb903cd81c9ebf1fdb8c72b54e4c6afd513619471dc051985f7", "hex");
    
    //do it ourselves...
    const sp = Buffer.from("7oRLX4MhpcM=", 'base64');

    // Conversion Base64 to Latin-1
    var sLatin = String.fromCharCode.apply(null, new Uint16Array(sp));
    console.log("sLatin :" + sLatin);

    // Conversion Hexa to Latin-1 (ISO/CEI 8859-1)
    //var s = '';
    //for (var i = 0; i < shex.length; i+=2){
    //    s += String.fromCharCode( parseInt( shex.substr(i,2), 16 ) );
    //}
    //console.log("s :" + s);

    const test = crypto.getRandomValues(new Uint8Array(8));
    const combo = secret + (sLatin || test ).toString();
    
    console.log("combo: "+ combo);

    const sha = await crypto.subtle.digest({name: 'SHA-256'},combo);
    console.log("sha: " + sha );

    //Make cryptokey object from this key
    const key = await crypto.subtle.importKey('raw', new Uint8Array(sha), 'AES-GCM', false, ['encrypt', 'decrypt']);

    //decrypt
    let output = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: iv
        },
        key,
        ct
    )

    //output result
    console.log(ab2str(output));
}

decryptME();