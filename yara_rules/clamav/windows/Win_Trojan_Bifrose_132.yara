rule Win_Trojan_Bifrose_132
{
strings:
	$a0 = { e69eeebca2ee0d4e994595c8f1acf5337b3a7faf02b3d007621b57957cc7a3b500b9f93b87163503ea35588be675b6fa49f9394a924d9c6a519dbcef41f34275ab589ed11adbb6846bf9477ac281c2d4fd8a667ba63a49495eee153016623d4ea75794d621bb0b4e995c79472e7aa2df3bed0e46984865331a6693c60dbedf166919f5c3a93c7dbfeba0e81b550a5f9279c4a0b500c1 }

condition:
	$a0
}

        