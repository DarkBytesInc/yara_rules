rule Win_Trojan_CVE_2012_0201_1
{
strings:
	$a0 = { 5b50726f66696c655d0d0a[0-125]a58831678240166418fcffffc0201c64 }

condition:
	$a0
}

        
