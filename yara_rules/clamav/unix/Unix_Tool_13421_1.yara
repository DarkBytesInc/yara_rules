rule Unix_Tool_13421_1
{
strings:
	$a0 = { eb345e89f783ef2231c9b18cd1c9b07bf2aeffcfac2807e2f5897b0891887b07897b0cb00b89f38d7b088d7b0ccd8031db89d840cd80e8c7ffffff0535352d2519120d0813 }

condition:
	$a0
}

        
