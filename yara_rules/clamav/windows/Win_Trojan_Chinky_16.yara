rule Win_Trojan_Chinky_16
{
strings:
	$a0 = { 6848124000e8f0ffffff0000000000003000000040000000000000009ae9498775debe4a9a1447d474a1907400000000000001000000000000000000????????????????0000000000000000000000000600000078384000070000001030400007000000 }

condition:
	$a0
}

        