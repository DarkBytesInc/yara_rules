rule Doc_Trojan_Appder_3
{
strings:
	$a0 = { 44696769744324203d20576f726442617369632e5b4765745072697661746550726f66696c65537472696e67245d28224d6963726f736f667420576f7264222c2022205645524d494e222c202257494e574f5244362e494e49202229 }

condition:
	$a0
}

        