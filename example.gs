//TO CREATE RSA PEM64 KEY: openssl pkcs12 -in YOURPRIVATEKEY.p12 -nodes | openssl rsa | base64 > myfile.pem.b64
//Depends on the library : MLMfbjxn4nA3IwygCAa7Pqsh00DPSBbB3
var RSAKEYBASE64 = PropertiesService.getScriptProperties().getProperty('key');
var SCOPES = ["https://www.googleapis.com/auth/drive"];
var SERVICE_ACCOUNT = "5883499270....nj3tc6mt1hokig@developer.gserviceaccount.com"


function test_tokenBuilder_Library(){
  var testBuilder = tokenBuilder(RSAKEYBASE64, SCOPES, SERVICE_ACCOUNT);
  
  // Not needed if you want to use the public signing micro service
  // testBuilder.setSigningServer("https://123.123.123.123") 
  
  testBuilder.addUser("1test@example.com")
             .addUser("2user@example.com")
             .addUser("3user@example.com")  
             .addUser("4user@example.com")  
             .generateJWT()
             .requestToken();
    
             
             
   var t1 = testBuilder.getToken("1test@example.com");
   Logger.log({"token":t1.token,"expiration":t1.expire});
   
   Logger.log(testBuilder.getTokens());
}
