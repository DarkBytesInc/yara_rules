rule Win_Downloader_Dadobra_59
{
strings:
	$a0 = { 6257266d72d62e6578650b6d7362e2c4d390638f2117aefdffdf8670a6b1b16b71747e777d78716db26d776c7b050ff59bc1feb27d7173b27e6e2b0a2f696d676d70d9b2cb6ef17067135c60130454b66c680026a0226402cc557cabeb32138bc07b03b9dc0e96001c1f13ac202024ddffffbfcbccc8 }

condition:
	$a0
}

        