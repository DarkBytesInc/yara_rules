rule Win_Trojan_Hupigon_912
{
strings:
	$a0 = { f03c08baefe131f01d743ecdfaba6da6af84cc0fc3aa8a8b0b81d1ed8ce039d9e04d3cc418df754b138e3c158dc8454c1315df2ad8187d0a976b44dcfa05844cac5faccf6a4854d025e6ef5ea998586ead78e92172d17f30ae92bb95f5440e }

condition:
	$a0
}

        
