rule Html_Phishing_Bank_323
{
strings:
	$a0 = { 77696c6c206265207465726d696e617465642e207768696c6520646f696e67206f757220726567756c6172207363686564756c65206163636f756e7420766572696669636174696f6e2077652068617665206e6f7469636564206120736c69676874206572726f7220696e20796f75722062696c6c696e6720696e666f }

condition:
	$a0
}

        