rule Win_Spyware_ot_179
{
strings:
	$a0 = { c7e939d65a0ad4405413ce1c5435a864286c224b26ef3f495844324c4f696c4f4411461b5dd4998060a054381001ee2e96adf2fde3ec9980cf3b5aa903e863082786cacefa284efd04599408a852a5c79767e306878904056dc25fa3c0a78c0b991c156b4cea23e2b920eec7ddb709316f81942a4f48d51bf04db5 }

condition:
	$a0
}

        