rule Win_Trojan_Scratch_1
{
strings:
	$a0 = { 258b441aa300018b441ca30201e80500b9000151c3061e0e33c98ed9803e1504537507803e16040573518cc5b8 }

condition:
	$a0
}

        
