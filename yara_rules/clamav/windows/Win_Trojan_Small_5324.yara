rule Win_Trojan_Small_5324
{
strings:
	$a0 = { 50afe5b290e17e05b5f24262659d5a46be075c45c4fbb74828f2e5d9b6eead43bc28d8f5e70263edefe496f02bac11366b222477b299d92cf24d63ee649de5336128692037a02127baa9cef0cedd }

condition:
	$a0
}

        
