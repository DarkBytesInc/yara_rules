rule Win_Trojan_Agent_32721
{
strings:
	$a0 = { 8afc8f92f27ea17eaa7eb349bcec3fed3ff63ffc0e0d37184e1d8e56c97627cebac7d8e7f1e119382d2494073939333a613b852e91ee93b483b8d0f3e5f3f0f2f5e8e8073a721d7424763690917a4b7c557e8b7ea9 }

condition:
	$a0
}

        
