var searchIndex = JSON.parse('{\
"custodian_password":{"doc":"TODO","t":[3,4,13,13,6,11,11,11,11,0,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,0,11,11,11,11,11,11,11,11,11,11,11,3,3,3,3,3,3,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,3,3,3,3,3,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11,11],"n":["Config","Error","Login","Registration","Result","borrow","borrow","borrow_mut","borrow_mut","client","clone","clone","clone_into","clone_into","cmp","cmp","default","deserialize","eq","eq","fmt","fmt","fmt","from","from","hash","hash","into","into","ne","new","partial_cmp","partial_cmp","serialize","server","to_owned","to_owned","to_string","try_from","try_from","try_into","try_into","type_id","type_id","vzip","vzip","Login","LoginRequest","LoginResponse","Register","RegistrationRequest","RegistrationResponse","borrow","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","clone","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","clone_into","cmp","cmp","cmp","cmp","cmp","cmp","deserialize","deserialize","deserialize","deserialize","deserialize","deserialize","eq","eq","eq","eq","eq","eq","finish","finish","fmt","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","from","hash","hash","hash","hash","hash","hash","into","into","into","into","into","into","login","ne","ne","ne","ne","ne","ne","partial_cmp","partial_cmp","partial_cmp","partial_cmp","partial_cmp","partial_cmp","register","serialize","serialize","serialize","serialize","serialize","serialize","to_owned","to_owned","to_owned","to_owned","to_owned","to_owned","try_from","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","type_id","vzip","vzip","vzip","vzip","vzip","vzip","Login","LoginResponse","Registration","RegistrationBuilder","RegistrationResponse","borrow","borrow","borrow","borrow","borrow","borrow_mut","borrow_mut","borrow_mut","borrow_mut","borrow_mut","clone","clone","clone","clone","clone","clone_into","clone_into","clone_into","clone_into","clone_into","cmp","cmp","cmp","cmp","cmp","deserialize","deserialize","deserialize","deserialize","deserialize","eq","eq","eq","eq","eq","finish","finish","fmt","fmt","fmt","fmt","fmt","from","from","from","from","from","hash","hash","hash","hash","hash","into","into","into","into","into","login","ne","ne","ne","ne","ne","partial_cmp","partial_cmp","partial_cmp","partial_cmp","partial_cmp","register","serialize","serialize","serialize","serialize","serialize","to_owned","to_owned","to_owned","to_owned","to_owned","try_from","try_from","try_from","try_from","try_from","try_into","try_into","try_into","try_into","try_into","type_id","type_id","type_id","type_id","type_id","vzip","vzip","vzip","vzip","vzip"],"q":["custodian_password","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","custodian_password::client","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","custodian_password::server","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"d":["Common password configuration between server and client.","<code>Error</code> type for this crate.","Error during login.","Error during registration.","<code>Result</code> for this crate.","","","","","OPAQUE client side handling.","","","","","","","","","","","","","","","","","","","","","Builds new default [<code>Config</code>].","","","","OPAQUE server side handling.","","","","","","","","","","","","Starts a login process on the client.","Send this to the server to drive the login process.","Send this back to the server to finish the registration …","Starts a registration process on the client.","Send this to the server to drive the registration process.","Send this to the server to finish the registration.","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Finishes the login. The returned [<code>LoginResponse</code>] has to …","Finishes the registration. The returned […","","","","","","","","","","","","","","","","","","","","","","","","","Starts the login process. The returned [<code>LoginRequest</code>] has …","","","","","","","","","","","","","Starts the registration process. The returned […","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Login process on the server.","Send this back to the client to drive the login process.","Registration object needed to <code>login</code>. Typically this is …","Starts a registration process on the server.","Send this back to the client to drive the registration …","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","","Finishes the login. Authentication is successful if this …","Finishes the registration process. The returned […","","","","","","","","","","","","","","","","","","","","","Starts the login process. The returned […","","","","","","","","","","","Starts the registration process. The returned […","","","","","","","","","","","","","","","","","","","","","","","","","","","","","",""],"i":[0,0,1,1,0,2,1,2,1,0,2,1,2,1,2,1,2,2,2,1,2,1,1,2,1,2,1,2,1,2,2,2,1,2,0,2,1,1,2,1,2,1,2,1,2,1,0,0,0,0,0,0,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,3,4,5,6,7,8,3,4,5,6,7,8,4,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,3,4,5,6,7,8,0,0,0,0,0,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,11,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,10,9,10,11,12,13,9,10,11,12,13,11,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13,9,10,11,12,13],"f":[null,null,null,null,null,[[]],[[]],[[]],[[]],null,[[],["config",3]],[[],["error",4]],[[]],[[]],[[["config",3]],["ordering",4]],[[["error",4]],["ordering",4]],[[],["config",3]],[[],["result",4]],[[["config",3]],["bool",15]],[[["error",4]],["bool",15]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],[[]],[[]],[[]],[[["config",3]],["bool",15]],[[]],[[["config",3]],[["ordering",4],["option",4]]],[[["error",4]],[["ordering",4],["option",4]]],[[],["result",4]],null,[[]],[[]],[[],["string",3]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],null,null,null,null,null,null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["login",3]],[[],["register",3]],[[],["loginresponse",3]],[[],["loginrequest",3]],[[],["registrationrequest",3]],[[],["registrationresponse",3]],[[]],[[]],[[]],[[]],[[]],[[]],[[["login",3]],["ordering",4]],[[["register",3]],["ordering",4]],[[["loginresponse",3]],["ordering",4]],[[["loginrequest",3]],["ordering",4]],[[["registrationrequest",3]],["ordering",4]],[[["registrationresponse",3]],["ordering",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["login",3]],["bool",15]],[[["register",3]],["bool",15]],[[["loginresponse",3]],["bool",15]],[[["loginrequest",3]],["bool",15]],[[["registrationrequest",3]],["bool",15]],[[["registrationresponse",3]],["bool",15]],[[["loginresponse",3]],[["loginresponse",3],["result",6]]],[[["registrationresponse",3]],[["result",6],["registrationresponse",3]]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["config",3]],["result",6]],[[["login",3]],["bool",15]],[[["register",3]],["bool",15]],[[["loginresponse",3]],["bool",15]],[[["loginrequest",3]],["bool",15]],[[["registrationrequest",3]],["bool",15]],[[["registrationresponse",3]],["bool",15]],[[["login",3]],[["ordering",4],["option",4]]],[[["register",3]],[["ordering",4],["option",4]]],[[["loginresponse",3]],[["ordering",4],["option",4]]],[[["loginrequest",3]],[["ordering",4],["option",4]]],[[["registrationrequest",3]],[["ordering",4],["option",4]]],[[["registrationresponse",3]],[["ordering",4],["option",4]]],[[["config",3]],["result",6]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[]],[[]],null,null,null,null,null,[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[],["login",3]],[[],["registration",3]],[[],["registrationbuilder",3]],[[],["loginresponse",3]],[[],["registrationresponse",3]],[[]],[[]],[[]],[[]],[[]],[[["login",3]],["ordering",4]],[[["registration",3]],["ordering",4]],[[["registrationbuilder",3]],["ordering",4]],[[["loginresponse",3]],["ordering",4]],[[["registrationresponse",3]],["ordering",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[["login",3]],["bool",15]],[[["registration",3]],["bool",15]],[[["registrationbuilder",3]],["bool",15]],[[["loginresponse",3]],["bool",15]],[[["registrationresponse",3]],["bool",15]],[[["loginresponse",3]],["result",6]],[[["registrationresponse",3]],[["result",6],["registration",3]]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[["formatter",3]],["result",6]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[]],[[["loginrequest",3]],["result",6]],[[["login",3]],["bool",15]],[[["registration",3]],["bool",15]],[[["registrationbuilder",3]],["bool",15]],[[["loginresponse",3]],["bool",15]],[[["registrationresponse",3]],["bool",15]],[[["login",3]],[["ordering",4],["option",4]]],[[["registration",3]],[["ordering",4],["option",4]]],[[["registrationbuilder",3]],[["ordering",4],["option",4]]],[[["loginresponse",3]],[["ordering",4],["option",4]]],[[["registrationresponse",3]],[["ordering",4],["option",4]]],[[["registrationrequest",3],["config",3]],["result",6]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[]],[[]],[[]],[[]],[[]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["result",4]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[],["typeid",3]],[[]],[[]],[[]],[[]],[[]]],"p":[[4,"Error"],[3,"Config"],[3,"Login"],[3,"Register"],[3,"LoginResponse"],[3,"LoginRequest"],[3,"RegistrationRequest"],[3,"RegistrationResponse"],[3,"Login"],[3,"Registration"],[3,"RegistrationBuilder"],[3,"LoginResponse"],[3,"RegistrationResponse"]]}\
}');
if (window.initSearch) {window.initSearch(searchIndex)};