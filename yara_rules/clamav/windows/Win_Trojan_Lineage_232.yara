rule Win_Trojan_Lineage_232
{
strings:
	$a0 = { bf934e1dd282659952a10b0e6cf41fb7828bdb47d6014b071b80364a8e929d148d0beff0fccfa8b282b0c8c54102fcf099733d70dcb91126396c8c4cc9fa08a7a1024538c1bc2b9fc138dffa8c63d2dc2004c616d5571cbf57e5371bc71cc9e3c3be }

condition:
	$a0
}

        
