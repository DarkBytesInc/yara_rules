rule Win_Trojan_Htbot_1
{
strings:
	$a0 = { 5c706970655c68656c6c6f }
	$a1 = { 433a5c666c6173685c6f747465725c696d6d5c50456368656b615c77696e64666f726d325c72656c656173655c2e706462 }

condition:
	$a0 and $a1
}

        