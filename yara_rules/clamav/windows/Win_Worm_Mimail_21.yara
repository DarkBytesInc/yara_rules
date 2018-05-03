rule Win_Worm_Mimail_21
{
strings:
	$a0 = { 76697275732e9f6b77bf4d6d5d202a2f37526567f8c2a069d8dfb76d76502563ed6bd46c33329fada1fdee5379216d44656275670bb07757f6df06 }

condition:
	$a0
}

        
