rule Win_Trojan_Bifrose_159
{
strings:
	$a0 = { 00ec7e277088e4a9860020d6c0fed3bd5efc009dc9609c03ff2aa300377776d159027f253bc84c007931268a0b971300f0c22f07f7fa4a5c7403017451dfdb3ba8343ea0 }

condition:
	$a0
}

        
