rule Win_Trojan_FakeAV_213
{
strings:
	$a0 = { 558bec83ec105356be58c49b005633db53ff1570a49600391d58c49b00740833c040e98b000000575633ff6aff475389 }

condition:
	$a0
}

        
