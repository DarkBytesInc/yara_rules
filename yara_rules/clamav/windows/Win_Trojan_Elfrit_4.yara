rule Win_Trojan_Elfrit_4
{
strings:
	$a0 = { 48e52bf2d0c7633feacabd1372142755bc3886714520f52fef1972f67e082f5e5f3f66b33554237c996c4298af9ec30f7cd746359b18019ceaf4faba8220fe1b7c95b001cd1954b841908d47d964c2fe234d697ea087e27e864b273a4d1b65368eecbee547f255fc57793dec732fbd6320a7ce16ca90f8c00aa4542cf6f955346029e37e3b19e4f96b004a66 }

condition:
	$a0
}

        