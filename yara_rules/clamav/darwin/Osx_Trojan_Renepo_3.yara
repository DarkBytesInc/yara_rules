rule Osx_Trojan_Renepo_3
{
strings:
	$a0 = { 2f62696e2f62617368[0-100]6f70656e657220[0-15]2073746172747570207363726970[0-50]75726e206f6e20736572766963657320616e64206761746865722075736572 }
	$a1 = { 6e6964756d702070617373776420 }

condition:
	$a0 and $a1
}

        