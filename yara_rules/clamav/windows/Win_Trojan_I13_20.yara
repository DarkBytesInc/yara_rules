rule Win_Trojan_I13_20
{
strings:
	$a0 = { 50535152565755061eb430cd213c07735fb8534ecd213d13cd7455e800005d81ed1f01b82135cd212e899e9d012e8c }

condition:
	$a0
}

        
