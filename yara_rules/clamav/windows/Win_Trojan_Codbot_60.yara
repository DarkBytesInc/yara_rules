rule Win_Trojan_Codbot_60
{
strings:
	$a0 = { 0f7520409a6d052ddf00032bdaa4c5f8cec30ec93c941be08c0ab8199500b0acefbb9368588e00fca39ffd2af740c61c3f7cda40c57eac6a7948b85907afcad5b9a1430750d8c0bc1d01135e9a1759f4f630095fee8400d53a5bf28eabe5690049572cb1 }

condition:
	$a0
}

        
