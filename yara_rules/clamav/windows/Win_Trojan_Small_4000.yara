rule Win_Trojan_Small_4000
{
strings:
	$a0 = { 0fc1d0e83300000009c0742e31d20fc1c281c2fe1149008d8a58f000ff8d894414ff005231 }

condition:
	$a0
}

        
