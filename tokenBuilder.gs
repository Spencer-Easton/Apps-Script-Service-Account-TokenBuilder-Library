/**
* GAS library for generating user OAuth Tokens via Google service account. see 
* @param {String} rsaKey Your private RSA key in PEM64
* @param {Array} Scopes An Array of scopes you want to authenticate
* @param {String} saEmail The service account Email
* @return {object} self for chaining
*/
function tokenBuilder(rsaKey, Scopes, saEmail){
  var self = this;
  var rsaKey_ = Utilities.newBlob(Utilities.base64DecodeWebSafe(rsaKey)).getDataAsString();
  var Scopes_ = Scopes;
  var saEmail_ = saEmail;
  var jwts_ ;
  var tokens_ = {};
  var expireTime_;
  var subAccounts_;
  var signingServer_ = "https://130.211.114.57:8080/";
  
  if (!rsaKey_) {
    throw 'You must provide the private rsa key';
  }
  if(!(Scopes_.constructor === Array)){
    throw "The Scopes must be in a valid array"
  }
  
  if (!Scopes_) {
    throw 'You must provide atleast one scope';
  }
  
  if (!saEmail_) {
    throw 'You must provide the service account email';
  }
  
  self.setSigningServer = function(serverUrl){
    signingServer_ = serverUrl;
  }
  
  self.addUser = function(userEmail){
    if(!subAccounts_){
      subAccounts_ = [];
    }
    subAccounts_.push(userEmail);
    return self;
  }
  
  self.generateJWT = function(){
    if(!subAccounts_){
      throw new Error("You must add at least one user account");
    }
    var sPayloads = [];
    for(var i=0; i<subAccounts_.length;i++){
      sPayloads.push({"claim":makeClaim(subAccounts_[i]),"user":subAccounts_[i],"expire":expireTime_});
    } 
    
    var payload = {"payloads":sPayloads, "key":rsaKey_, "algorithm": "RS256"};
    var stringifiedPayload = JSON.stringify(payload);
    var sResult = null;
    try {
      sResult = UrlFetchApp
      .fetch(signingServer_,
             {"validateHttpsCertificates":false,
              "method":"post",
              "payload":JSON.stringify(payload),
              "contentType":"application/json"}
            )
      .getContentText();
      
      jwts_ = JSON.parse(sResult);
      
    } catch (ex) {
      throw new Error("Error generating JWT: " + ex);
    }
    return self;
  } 
  
  self.getToken = function(userEmail){
    if(!(userEmail in tokens_)){
      throw new Error("User not found");    
    }else{
      return tokens_[userEmail];
    }
  }
  
  self.getTokens = function(){
    return tokens_;
  }
  
  self.requestToken = function(){
    if(!jwts_){
      throw 'You must run generateJWT'
    }
    
    var params = {
      grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
      assertion: ''
    }
    
    
    var url = "https://accounts.google.com/o/oauth2/token"
    var parameters = { 'method' : 'post',                    
                      'payload' : params,
                      muteHttpExceptions:true};
    
    var response = "";
    
    for(var user in jwts_){
      params.assertion = jwts_[user].claim;
      response = JSON.parse(UrlFetchApp.fetch(url,parameters).getContentText());
      if(response.error){
        throw new Error('There was an error requesting a Token from the OAuth server: '+ response.error);
      }
      
      if(response.access_token)
      {
        tokens_[user]={};
        tokens_[user].token = response.access_token;
        tokens_[user].expire = jwts_[user].expire;
      }
    }
    return self;
  }
  
  
  return self;
  
  function makeClaim(subAccount){
    var now = (Date.now()/1000).toString().substr(0,10);
    var exp = (parseInt(now) + 3600).toString().substr(0,10);
    expireTime_ = exp;
    var claim = 
        {
          "iss": saEmail_,
          "sub": subAccount,
          "scope": Scopes_.join(" "),
          "aud":"https://accounts.google.com/o/oauth2/token",
          "iat": now,
          "exp": exp
        };
    return claim;
  }
  
}
