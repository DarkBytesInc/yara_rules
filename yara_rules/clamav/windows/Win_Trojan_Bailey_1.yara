rule Win_Trojan_Bailey_1
{
strings:
	$a0 = { 5d81ed03011e060e0e1f078db653018dbe4b01b90400f3a5b41a8d966802cd218d962202e83100b41aba8000071fcd218cc00510002e01864d012e0386 }

condition:
	$a0
}

        
