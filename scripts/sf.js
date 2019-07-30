var gun;
var user;
var device;

const gunOverPublic = true;

function log(msg){
    console.log((new Date()).toUTCString() + ' : ' + msg)
}


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
    if(!gunOverPublic){
      log('Put shareNotif on gun');
      var shareNotif = { userPub: userPub, gdprDataType: 'Claim', deviceId: deviceId }
      gun.get('GdprData').get(serviceProvPub).put(shareNotif);  
    }

    // put claim on user profile
    var claim = {  gdprDataType: 'Claim', mobileId: mobileId, deviceId: deviceId, devicePac: devicePac }
    var serviceProv = await gun.user(serviceProvPub).then();
    var sec = await Gun.SEA.secret(serviceProv.epub, user.pair()); // Diffie-Hellman
    var encClaim = await Gun.SEA.encrypt(claim, sec);  
    if(gunOverPublic){
      log('Put enClaim on public gun');
      var gdprData = { pub: user.is.pub, epub: user.is.epub, data: encClaim.substring(3, encClaim.length) }  
      gun.get('GdprData').get(serviceProvPub).put(gdprData); 
    }
    else {
      log('Put enClaim on private gun user');
      user.get(serviceProvPub).put(encClaim);   
    }

    log('ClaimDevice sent ');

  } catch (error) {
    log('ClaimDevice failed: ' + error)
  }


}

async function BurnKey(action, serviceProvPub, deviceId, devicePub, userPub, mobileId, index){
  try {

    // load vendor
    var vend = gun.user(serviceProvPub);
    var vendId = await vend.then();
    log('vendorId loaded: ' + vendId.alias);
    
    //Retrieve key to Open/Close from device
    var device = gun.user(devicePub);
    var deviceId = await device.then();
    log('DeviceId loaded : ' + deviceId.alias);
    
    // 1 get Key from Gun Device-node
    //var encKey = await device.get(userPub).get(mobileId).get('Key_' + index).once();
    var encKey = await vend.get(userPub).get(devicePub).get(mobileId).get('Key_' + index).once();

    // 2 use Key with lock via BLE
    //log('Opening device with encKey: ' + JSON.stringify(encKey));
    var sec = await Gun.SEA.secret(vendId.epub, user.pair()); // Diffie-Hellman
    //var sec = await Gun.SEA.secret(deviceId.epub, user.pair()); // Diffie-Hellman
    var keyToBurn = await Gun.SEA.decrypt(encKey, sec);
    if(!keyToBurn) {
      alert('No key found on ' + mobileId + ' on key index ' + index);
      throw 'No Key';
    }
    log('Opening device with decrypted key: ' + JSON.stringify(keyToBurn));

    // 3 send back used Key to Gun Vendor-Node
    // create burnedKey message
    var burnedKey = { gdprDataType: action, deviceId: deviceId.alias, devicePub: deviceId.pub, userPub: userPub, mobileId: mobileId, index: index, keyToBurn: keyToBurn}
    log('Saving & Sending Burned Key ' + JSON.stringify(burnedKey) + ' from ' + userPub + ' for serviceProvPub ' + serviceProvPub);

    // encode burnedKey
    var serviceProv = await gun.user(serviceProvPub).then();
    var sec = await Gun.SEA.secret(serviceProv.epub, user.pair()); // Diffie-Hellman
    var encBurnedKey = await Gun.SEA.encrypt(burnedKey, sec);

    if(gunOverPublic){
      var gdprData = { pub: user.is.pub, epub: user.is.epub, data: encBurnedKey.substring(3, encBurnedKey.length) }  
      gun.get('GdprData').get(serviceProvPub).put(gdprData);
    }
    else{
      //save burnedKey in SEA user profile
      user.get(serviceProvPub).put(encBurnedKey); 
    }

    var ret = 'BurnedKey ' + index + ' saved successfully';
    log(ret);   
    return ret;   
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
  
    var sec = await Gun.SEA.secret(device.epub, user.pair()); // Diffie-Hellman
    var encGdprPubSub = await Gun.SEA.encrypt(gdprPubSub, sec);

    if(gunOverPublic){
      var gdprData = { pub: user.is.pub, epub: user.is.epub, data: encGdprPubSub.substring(3, encGdprPubSub.length) }  
      gun.get('GdprData').get(serviceProvPub).put(gdprData);
    }
    else{
      user.get(serviceProvPub).put(encGdprPubSub); 
    }

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
  
    var serviceProv = await gun.user(serviceProvPub).then();
    var sec = await Gun.SEA.secret(serviceProv.epub, user.pair()); // Diffie-Hellman
    var encUserRole = await Gun.SEA.encrypt(userRole, sec);

    if(gunOverPublic){
      var gdprData = { pub: user.is.pub, epub: user.is.epub, data: encUserRole.substring(3, encUserRole.length) }  
      gun.get('GdprData').get(serviceProvPub).put(gdprData);
    }
    else{
      user.get(serviceProvPub).put(encUserRole); 
    }

    log('AssignUserRole sent');

  } catch (error) {
    console.error('Failed to AssignUserRole: ' + error);  
  }

}

async function RemoveUserRole(serviceProvPub, deviceId, toUserPub){
  try {

    var userRole = { gdprDataType: 'AssignUserRole', 
    deviceId: deviceId, 
    toUserPub: toUserPub, userRole: 'del'}

    log('Put encUserRole on user');
    var serviceProv = await gun.user(serviceProvPub).then();
    var sec = await Gun.SEA.secret(serviceProv.epub, user.pair()); // Diffie-Hellman
    var encUserRole = await Gun.SEA.encrypt(userRole, sec);

    if(gunOverPublic){
      var gdprData = { pub: user.is.pub, epub: user.is.epub, data: encUserRole.substring(3, encUserRole.length) }  
      gun.get('GdprData').get(serviceProvPub).put(gdprData);
    }
    else{
      user.get(serviceProvPub).put(encUserRole); 
    }

    log('RemoveUserRole sent');
    
  } catch (error) {
    console.error('Failed to RemoveUserRole: ' + error);  
  }
}

const ListenToGun = async function(serviceProvPub, devicePub, userPub){

  // load vendor
  var vend = gun.user(serviceProvPub);
  var vendId = await vend.then();
  log('vendorId loaded: ' + vendId.alias);

  // load device
  var dev = gun.user(devicePub);
  var devId = await dev.then();
  log('deviceId loaded: ' + devId.alias);


  // wait for new PAC
  //dev.get(userPub).get('PAC').on(async function(encPAC){
  vend.get(userPub).get(devicePub).get('PAC').on(async function(encPAC){
    //var sec = await Gun.SEA.secret(devId.epub, user.pair()); // Diffie-Hellman
    var sec = await Gun.SEA.secret(vendId.epub, user.pair()); // Diffie-Hellman
    var newPAC = await Gun.SEA.decrypt(encPAC, sec);
    if(newPAC)log('Received new PAC: ' + newPAC)
    else log('No PAC received');
    $('#devicePac').val(newPAC);
  });

  // wait for new sfinxKeys
  var mobileId = 'mobile01';
  for (let index = 0; index < 5; index++) {
    //dev.get(userPub).get(mobileId).get('Key_' + index).on(async function(encSfinxKey, slot){
    vend.get(userPub).get(devicePub).get(mobileId).get('Key_' + index).on(async function(encSfinxKey, slot){
      if(encSfinxKey) {
        log('New encrypted SfinxKey received in ' + slot + ' on ' + mobileId);
      }
      else log('encrypted SfinxKey REMOVED from ' + slot);
    });
  }  

  // wait for RealTimeFeedback
  for (let index = 0; index < 5; index++) {
    //dev.get(userPub).get('mobile01').get('FeedbackKey_' + index).on(async function(feedbackData, slot){
    vend.get(userPub).get(devicePub).get('mobile01').get('FeedbackKey_' + index).on(async function(feedbackData, slot){
      if(feedbackData) {
        var fb = 'Feedback received in Key_' + slot + ': ' + JSON.stringify(feedbackData);
        log(fb);
        alert(fb);
      }
      else log('FeedbackKey REMOVED from ' + slot);
    });
  }  

  // wait for Actions to sign
  //dev.get(userPub).get('Cloud').get('Action').on(async function(actionData, index){
  vend.get(userPub).get(devicePub).get('Cloud').get('Action').on(async function(actionData, index){
    log('Action data received from cloud: ' + JSON.stringify(actionData));
    actionData.mobileId = 'mobile01'; //TODO: retrieve this mobileId
    actionData.index = 0; //TODO: choose an key slot with non-burnedkey
    BurnKey(actionData.action, actionData.serviceProvPub, actionData.deviceId, actionData.devicePub, actionData.userPub, actionData.mobileId, actionData.index);
  });

}
