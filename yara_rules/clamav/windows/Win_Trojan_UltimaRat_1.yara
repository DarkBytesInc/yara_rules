rule Win_Trojan_UltimaRat_1
{
strings:
	$a0 = { 399ffeffff20416c72656164792073656e64696e672066696c653657726b7fbbfb69746520460d6e616d084e6f7420456e11 }

condition:
	$a0
}

        
