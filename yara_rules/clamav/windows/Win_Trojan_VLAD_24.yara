rule Win_Trojan_VLAD_24
{
strings:
	$a0 = { c86b072bc88bd9456764657467696e447552617062504b6c6c6c2e72617062706b2e637469b91d0003f3bec302bf }

condition:
	$a0
}

        
