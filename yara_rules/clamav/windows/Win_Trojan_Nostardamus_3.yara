rule Win_Trojan_Nostardamus_3
{
strings:
	$a0 = { beee08262efc0e1f0bc9b80c0806078034c02c00eb0340262e46487530c62824c441061bc79b4e034e1b70c026e12bc07fc0c197656564034c00c5d0c0c5c0c03a4e107cc0c03beec39cda4303 }

condition:
	$a0
}

        
