rule Win_Trojan_Mybot_8470
{
strings:
	$a0 = { 6a73ef5a2302681e596c876f4d9231ee59cfa9f4bacd4906bda44a4527e8fc6f7daa5033f58cb04c7dc8156cb248547640b04101e41ca9f757ea906e86e88d0a2304c7330e2509dbc295bbe1c45cbd4ac935b66aef }

condition:
	$a0
}

        
