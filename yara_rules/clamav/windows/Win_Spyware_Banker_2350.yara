rule Win_Spyware_Banker_2350
{
strings:
	$a0 = { dda470fe9ca22b2408e8cc405c2dc34898e4f30f5bf6cda4f6fe9fd04dcd7323261f2444e0d8fceeccabb9336099e6d2138581d5c7b2ed43cadd7db5301e354a9ec8e0b0d173d107b1dce49164d8a1c663631b7dbc755168c2f38c087c9bbf704c6ea6933912cb8e9d769ac2efaa }

condition:
	$a0
}

        
