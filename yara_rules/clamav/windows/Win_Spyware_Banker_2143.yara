rule Win_Spyware_Banker_2143
{
strings:
	$a0 = { c25953204483d5abe19615443241f57371dfb1bce73cb2ffaaf84f907d585c88068ed57d4fbd0fcf1c3cc0b8638639139695dedb7c3132f656e57c6471454abfcf9d9c12ee4c740435a67c26b34c }

condition:
	$a0
}

        
