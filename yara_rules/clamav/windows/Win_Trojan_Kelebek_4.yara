rule Win_Trojan_Kelebek_4
{
strings:
	$a0 = { 28246e756d746f6b28256173622e7370616d6368616e732c333229[0-55]707269766d7367[0-25]6c7466656e }

condition:
	$a0
}

        
