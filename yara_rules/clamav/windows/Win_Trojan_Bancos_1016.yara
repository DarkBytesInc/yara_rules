rule Win_Trojan_Bancos_1016
{
strings:
	$a0 = { d30544863f3b13fbcf9ee6922694ab6d68d94b58a56bf3c8a02de1f9664f7d1624192291926b87de221b486d9385d3aa659b88eb4e5dd6852ad5059707c01644 }

condition:
	$a0
}

        
