rule Win_Trojan_Diamond_1
{
strings:
	$a0 = { 450490eb10902d03009090c605e99090894501909090ba740590b9180090b4409090cd2190720a }

condition:
	$a0
}

        
