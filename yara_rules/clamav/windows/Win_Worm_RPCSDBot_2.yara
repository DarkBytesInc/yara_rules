rule Win_Worm_RPCSDBot_2
{
strings:
	$a0 = { 5c6578706c6f7265722e657865006578706c6f7265722e6578652025730025642c202564203a20555345524944203a20554e4958203a2025730d }

condition:
	$a0
}

        