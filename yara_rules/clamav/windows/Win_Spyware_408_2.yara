rule Win_Spyware_408_2
{
strings:
	$a0 = { 8cf14144cbb9b22272d03c0500aede739907c3ccb954a4e26d8a1828f49d93facdacce06c329d8fb8e8d2cc83c69fbe501d12cacd3163c603f6605939052453b4f2a4c42dd37d677c60dd5268a46 }

condition:
	$a0
}

        
