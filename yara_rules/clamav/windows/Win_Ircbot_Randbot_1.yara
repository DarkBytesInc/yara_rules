rule Win_Ircbot_Randbot_1
{
strings:
	$a0 = { 860b1ed5c3480c4be93c3c8dcdefc0afb52fbd82beccbef00afaf2fb882bb797930145979170e7fea48658b61bc29623afc6d3d279c301d99fdaa70c58479bcb9a8353ee380f7483bbf09c1f03c17760fab7d5f0d37df31fe4c5b3f06117aabbe622e865d8ac2f6ccd9f83055a7678ed }

condition:
	$a0
}

        
