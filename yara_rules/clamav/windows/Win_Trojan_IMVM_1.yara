rule Win_Trojan_IMVM_1
{
strings:
	$a0 = { 64722b646f63756d656e742e56472e712e76616c75652b2254686520222b646f63756d656e742e56472e6e756d652e76616c75652b22205649525553222b225c725c6e222b646f63756d656e742e56472e712e76616c75652b22627920222b646f63756d656e742e56472e6175746f722e76616c75652b64722b }

condition:
	$a0
}

        