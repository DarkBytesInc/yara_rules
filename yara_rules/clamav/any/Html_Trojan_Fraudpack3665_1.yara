rule Html_Trojan_Fraudpack3665_1
{
strings:
	$a0 = { 89857cffffffc78574ffffff00000000e90f0000008b8d74ffffff83c101898d74ffffff8b9574ffffff3b9578ffffff0f8d740000008b857cffffff0fb708c1f90c83f9030f854b000000d3e24a8b5584a18040400003028b8d7cffffff0fb71181e2ff }

condition:
	$a0
}

        
