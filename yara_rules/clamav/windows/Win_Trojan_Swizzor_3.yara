rule Win_Trojan_Swizzor_3
{
strings:
	$a0 = { 5c87d1eb783f3f636d3e930282adbaf3c9aad57d743b25ba2d5f653592dfbd154c9f78c7e90d11020372aa3c32da410fbae946231bc3387df61eb3b043dff34c45549b3957958c59c2b7ad0499de965c7e941fff3af005a5fa29 }

condition:
	$a0
}

        
