rule Win_Trojan_Hupigon_853
{
strings:
	$a0 = { fb237befa4c220b8a87f42fc0718c90d8c6ab2f896b751bd1784b21f145dbd1dc9b06232db3a680b47b367a65c2cf128a5efd258ef9969ee24763f68e9d1d57cdcc4cf1d13e8bbf4f643af0f4bb50ac6b7bddc1669f8a25d7b4fe6d3aa5bce }

condition:
	$a0
}

        
