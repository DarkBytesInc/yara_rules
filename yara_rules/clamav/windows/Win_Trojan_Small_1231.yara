rule Win_Trojan_Small_1231
{
strings:
	$a0 = { 5068d40240006801000080ff15e00140006a048d45f8506a046a0068fc014000ff75fcff15e4014000 }

condition:
	$a0
}

        
