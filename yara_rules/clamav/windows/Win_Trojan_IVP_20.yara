rule Win_Trojan_IVP_20
{
strings:
	$a0 = { 408d96560259cd217210b002e82900b440b927018d960501cd21b801572e8b8e42022e8b9644 }

condition:
	$a0
}

        
