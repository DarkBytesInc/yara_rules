rule Win_Trojan_Delf_627
{
strings:
	$a0 = { 8bd853e8724cf6ffa3084853006a0068800000006a036a006a03680000004053e8454cf6ffa30c485300 }

condition:
	$a0
}

        
