rule Win_Trojan_Bancos_744
{
strings:
	$a0 = { 245e9d10bc1c857a0c45a67be3b5a8b706b756a62704748b163150e120eadf54d41ecb198b4b90ac119a995a0a4cc23d5f61661f854e940c58656fbabf406459579cfaa1 }

condition:
	$a0
}

        
