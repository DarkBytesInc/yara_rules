rule Win_Trojan_IRCBot_629
{
strings:
	$a0 = { e761d9afbdf4ca7bca53914865c7246491c89e3e3566fc3d69e0eef08f1298eca824e65d187d470ec49373303cc0ee55fc4aa02ecd23b28610519445fbc37be41d6828492c74bf59599ffaf23c00 }

condition:
	$a0
}

        
