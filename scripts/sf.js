var gun;
var user;
var device;

function log(msg){
    console.log((new Date()).toUTCString() + ' : ' + msg)
}

/*
Gun.on('opt', function (ctx) {
    if (ctx.once) {
      return
    }	
     ctx.on('out', function (msg) {
      var to = this.to
      // Adds headers for put
      msg.headers = {
        token: 'thisIsTheTokenForReals' 
      }
      to.next(msg) // pass to next middleware
    })
  })
 */


function connectGun(relaynode, port){
  var url = relaynode + ':' + port + '/gun';
  //var url = 'http://137.117.197.174:8765/gun';
  //var url = 'http://localhost:8765/gun';
  log('Connecting to = ' + url);  
  
  //gun = Gun('http://137.117.197.174:8765/gun');
  gun = Gun(url);
/* 
  if(port=='all'){
    gun = Gun(['http://localhost:8763/gun', 'http://localhost:8764/gun', 'http://localhost:8765/gun', 'http://localhost:8766/gun']); // Gun([url, url, ...]) // multiple gateway peers
  }
  else{
    gun = Gun([url]) 
  }
*/  
  //TODO: create this object out of this function
  user = gun.user();
  log('Gun & User objects created ')

  //show pub key in UI
  gun.on('auth', showPub);

  return url;
}


async function RegisterDevice(deviceId, deviceKey){
  if(!gun) connectGun();
  device = gun.user();
  await device.create(deviceId, deviceKey);  
  //TODO: remove if not debug
  //gun.get('devices').set({deviceId: deviceId, deviceKey: deviceKey, devicePub: device.is.pub});
  log('Device Registered with Pub key = ' + device.is.pub);
}

async function AuthDevice(deviceId, deviceKey){
  if(!gun) connectGun();
  device = gun.user();
  await device.auth(deviceId, deviceKey, async function(ack){
    if(ack.err) log(deviceId + ' authentication error: ' + JSON.stringify(ack))
    else log(deviceId + ' authenticated successfully')           
  });
}


async function ClaimDevice(serviceProvPub, devicePub, deviceId, devicePac, userPub, mobileId){

  try {

    // put notif on gun (GdprData/serviceProvPub)
    log('Put shareNotif on gun');
    var shareNotif = { userPub: userPub, gdprDataType: 'Claim', deviceId: deviceId }
    gun.get('GdprData').get(serviceProvPub).put(shareNotif);

    // put claim on user profile
    var claim = {  gdprDataType: 'Claim', mobileId: mobileId, deviceId: deviceId, devicePac: devicePac }
    log('Put enClaim on user');
    var sec = await Gun.SEA.secret(device.epub, user.pair()); // Diffie-Hellman
    var encClaim = await Gun.SEA.encrypt(claim, sec);
    user.get(serviceProvPub).get(deviceId).put(encClaim); 

    log('ClaimDevice sent ');

  } catch (error) {
    log('ClaimDevice failed: ' + error)
  }


}

async function BurnKey(action, serviceProvPub, deviceId, devicePub, userPub, mobileId, index){

  try {
    
    //Retrieve key to Open/Close from device
    var device = gun.user(devicePub);
    var deviceId = await device.then();
    log('DeviceId loaded : ' + deviceId.alias);
    
    var encKey = await device.get(userPub).get(mobileId).get('Key_' + index).once();
    //log('Opening device with encKey: ' + JSON.stringify(encKey));

    var sec = await Gun.SEA.secret(deviceId.epub, user.pair()); // Diffie-Hellman
    var keyToBurn = await Gun.SEA.decrypt(encKey, sec);
    if(!keyToBurn) {
      alert('No key found on ' + mobileId + ' on key index ' + index);
      throw 'No Key';
    }
    log('Opening device with decrypted key: ' + JSON.stringify(keyToBurn));

    // create burnedKey message
    var burnedKey = { gdprDataType: action, deviceId: deviceId.alias, devicePub: deviceId.pub, userPub: userPub, mobileId: mobileId, index: index, keyToBurn: keyToBurn}
    log('Saving & Sending Burned Key ' + JSON.stringify(burnedKey) + ' from ' + userPub + ' for serviceProvPub ' + serviceProvPub);

    // encode burnedKey
    var sec = await Gun.SEA.secret(deviceId.epub, user.pair()); // Diffie-Hellman
    var encBurnedKey = await Gun.SEA.encrypt(burnedKey, sec);
    //save burnedKey in SEA user profile
    user.get(serviceProvPub).get(deviceId.alias).put(encBurnedKey); 

    log('BurnedKey saved successfully');      
  } 
  catch (error) {
    console.error('Failed to save BurnedKey: ' + error);      
  }

}

async function SetGdprPubSub(serviceProvPub, deviceId, devicePub, 
  toServiceProvPub, gdprType){

  try {
    
    var gdprPubSub = { gdprDataType: 'gdprPubSub', 
    serviceProvPub: serviceProvPub, devicePub: devicePub, deviceId: deviceId, 
    toServiceProvPub: toServiceProvPub, gdprType: gdprType }
  
    log('Put gdprPubSub on user');
    var sec = await Gun.SEA.secret(device.epub, user.pair()); // Diffie-Hellman
    var encGdprPubSub = await Gun.SEA.encrypt(gdprPubSub, sec);
    user.get(serviceProvPub).get(deviceId).put(encGdprPubSub); 

    log('gdprPubSub sent');

  } catch (error) {
    console.error('Failed to setGdprPubSub: ' + error);  
  }

}


async function AssignUserRole(serviceProvPub, deviceId, devicePub, userPub, mobileId, devicePac, 
  toUserPub, userRole, from, to){

  try {

    var userRole = { gdprDataType: 'AssignUserRole', 
    devicePub: devicePub, deviceId: deviceId, devicePac: devicePac,
    toUserPub: toUserPub, userRole: userRole, 
    from: from, to: to }
  
    log('Put encUserRole on user');
    var sec = await Gun.SEA.secret(device.epub, user.pair()); // Diffie-Hellman
    var encUserRole = await Gun.SEA.encrypt(userRole, sec);
    user.get(serviceProvPub).get(deviceId).put(encUserRole); 

    log('AssignUserRole sent');

  } catch (error) {
    console.error('Failed to AssignUserRole: ' + error);  
  }

}

async function RemoveUserRole(serviceProvPub, deviceId, devicePac, toUserPub){
  try {

    var userRole = { gdprDataType: 'AssignUserRole', 
    deviceId: deviceId, devicePac: devicePac, 
    toUserPub: toUserPub, userRole: 'del'}

    log('Put encUserRole on user');
    var sec = await Gun.SEA.secret(device.epub, user.pair()); // Diffie-Hellman
    var encUserRole = await Gun.SEA.encrypt(userRole, sec);
    user.get(serviceProvPub).get(deviceId).put(encUserRole); 

    log('RemoveUserRole sent');
    
  } catch (error) {
    console.error('Failed to RemoveUserRole: ' + error);  
  }
}

const ListenToGun = async function(devicePub, userPub){

  // load device
  var dev = gun.user(devicePub);
  var devId = await dev.then();
  log('deviceId loaded : ' + devId.alias);

  // wait for new PAC
  dev.get(userPub).get('PAC').on(async function(encPAC){
    var sec = await Gun.SEA.secret(devId.epub, user.pair()); // Diffie-Hellman
    var newPAC = await Gun.SEA.decrypt(encPAC, sec);
    if(newPAC)log('Received new PAC: ' + newPAC)
    else log('No PAC received');
    $('#devicePac').val(newPAC);
  });

  // wait for new sfinxKeys
  for (let index = 0; index < 5; index++) {
    dev.get(userPub).get('mobile01').get('Key_' + index).on(async function(encSfinxKey, slot){
      if(encSfinxKey) log('New encrypted SfinxKey received in ' + slot);
      else log('encrypted SfinxKey REMOVED from ' + slot);
    });
  }  

  // wait for RealTimeFeedback
  for (let index = 0; index < 5; index++) {
    dev.get(userPub).get('mobile01').get('FeedbackKey_' + index).on(async function(feedbackData, slot){
      if(feedbackData) {
        var fb = 'Feedback received in Key_' + slot + ': ' + JSON.stringify(feedbackData);
        log(fb);
        alert(fb);
      }
      else log('FeedbackKey REMOVED from ' + slot);
    });
  }  

  // wait for Actions to sign
  dev.get(userPub).get('Cloud').get('Action').on(async function(actionData, index){
    log('Action data received from cloud: ' + JSON.stringify(actionData));
    actionData.mobileId = 'mobile01';
    actionData.index = 4;
    BurnKey(actionData.action, actionData.serviceProvPub, actionData.deviceId, actionData.devicePub, actionData.userPub, actionData.mobileId, actionData.index);
  });

}
