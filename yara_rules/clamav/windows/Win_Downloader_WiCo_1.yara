rule Win_Downloader_WiCo_1
{
strings:
	$a0 = { 5baa6fd47272cf566572732e5c457a8fba254f7064d23f81b6dba5b46c6f26722e08653fd7ddfea6227474703a2f2f77002e774b752ee6fbb1ff65732e636f6d2f72782e7068703f6b3d5235eadb2b43176d005c44ab186dfb193520d72046696c365c4fdfe78251152c2b580b5c5eebdeec636d64730b15 }

condition:
	$a0
}

        