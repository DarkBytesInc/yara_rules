rule Win_Trojan_Hupigon_902
{
strings:
	$a0 = { 9a9ca9c0b0a16174444cba5aa21bfbb70ae7fc1311416784b83afd9282fa0df71c65d0f781ebdacc69beb8acbd5f44b44ace3c48ca81c777aff3b437c2110f07257139ba8f436e1d37f39f7e9316526a69abb7371346e8b3af189cb4351fcc }

condition:
	$a0
}

        
