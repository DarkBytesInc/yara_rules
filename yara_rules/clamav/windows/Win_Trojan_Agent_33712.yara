rule Win_Trojan_Agent_33712
{
strings:
	$a0 = { 40e02ac9fdbf86f456ca992d55f2cd040e668197484cb8a063de018afc4a04462cbad3ebcbb9dcf541ec3513f089c787bce0fb355ad7a1ceda5b0ecc2fcd0b50bb5f2ed3dbc7354a24bf2734b4d0b7a64874defc53053b9b2abb1250bd272d }

condition:
	$a0
}

        
