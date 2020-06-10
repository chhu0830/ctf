/* Run first function and get the result directly. */
/* The list is as below
 * [
 * 	 "tjctf{",
 * 	 "getElementsByName",
 * 	 "toString",
 * 	 "value",
 * 	 "4312a7be33f09cc7ccd1d8a237265798",
 * 	 "Sorry. Wrong username or password.",
 * 	 "admin"
 * ]
 */
var _0xb31c=['value','4312a7be33f09cc7ccd1d8a237265798','Sorry.\x20Wrong\x20username\x20or\x20password.','admin','tjctf{','getElementsByName','toString'];

(function(_0xcd8e51,_0x31ce84){
  var _0x55c419=function(_0x56392e){
    while(--_0x56392e){
      _0xcd8e51['push'](_0xcd8e51['shift']());
    }
  };
  _0x55c419(++_0x31ce84);
}(_0xb31c,0x1e7));
  
/* Return the nth element of list above */
var _0x4a84=function(_0xcd8e51,_0x31ce84){
  _0xcd8e51=_0xcd8e51-0x0;
  var _0x55c419=_0xb31c[_0xcd8e51];
  return _0x55c419;
};

/* Make the check */
checkUsername=function(){
  username=document[_0x4a84('0x1')]('username')[0x0]['value'];
  password=document[_0x4a84('0x1')]('password')[0x0][_0x4a84('0x3')];

  temp=md5(password)[_0x4a84('0x2')]();
  
  if(username==_0x4a84('0x6') && temp==_0x4a84('0x4'))
    alert(_0x4a84('0x0')+password+'890898}');
  else 
    alert(_0x4a84('0x5'));
};
