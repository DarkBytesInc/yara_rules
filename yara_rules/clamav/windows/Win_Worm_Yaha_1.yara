rule Win_Worm_Yaha_1
{
strings:
	$a0 = { 534e46e467180b95cc212f4a63438460d1c76b0a6ce917ff0656e631ec1756414c45a1947dff4e54494e2e5343520f22 }

condition:
	$a0
}

        
