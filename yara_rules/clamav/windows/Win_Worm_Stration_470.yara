rule Win_Worm_Stration_470
{
strings:
	$a0 = { 6e1519a7b6cadac24da0d065ed3b2ffe0a31d954872caf9bb01b9d0aae77abc0382a415083dc0dd4ed7207faed8503c3894e2b6ef65dcde1da28444764e8b66d52c182b83a4e649c428f04df912c9f1fb7f7d197a47efdd389c07a4a4270015dec849dc95d02c16e5828 }

condition:
	$a0
}

        
