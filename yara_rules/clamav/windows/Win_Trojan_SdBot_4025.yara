rule Win_Trojan_SdBot_4025
{
strings:
	$a0 = { 8ca30363347b7f346130a6b9b59d49c5ed9330d26f122b4e4c2cf9b275984dee11fd8f11a5b8955e47bf0edb32bdfe14fed46997b7558f1ba764de5ada4c9a57bbe340dd682f194719eebdc15aa380a718d18a2c2a14 }

condition:
	$a0
}

        
