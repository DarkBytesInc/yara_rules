rule Win_Trojan_Mendwar_1
{
strings:
	$a0 = { 362c06ebe7c8fbdcc5398a8cbc6cfbfcfedce2414c3614dcddb121f14d48fadc47d0ec0e636734ffe8ff07acf0583211294953cb56b1104ec40059eecb0e21215ceee6319bbdf766932752ff6916d81472d96f806419b221fb6cac6854587f44 }

condition:
	$a0
}

        
