rule Win_Spyware_Goldun_98
{
strings:
	$a0 = { 06142e73796d61eb63158d8d6844b59f618cb6b284fd6d636166656513471df601321032617670075ad5de4e72 }

condition:
	$a0
}

        
