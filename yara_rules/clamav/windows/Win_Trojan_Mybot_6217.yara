rule Win_Trojan_Mybot_6217
{
strings:
	$a0 = { 5ccb4acf9459c4e649a81b5b2db945866183496145f94b0b897f7c046310883ca91bd1f13fc1130d779f01a0097c06808dc5c08d2a3747df5243ca6a86bf0a4cf6c208de3aabd1305038c889529d5ab22b4b06665113a86fd8370d7cf08c8c723ad8400004e0c0d0300e115e3fd5e9e33b553074e52c060e5cf7f302e1ef4eca10e04d951555cd2878954530 }

condition:
	$a0
}

        