rule Win_Trojan_Dasmin_3
{
strings:
	$a0 = { bc1ec2debb3ab68a823a7f306241cb6edbd38bf4add4ba2526756d256e2f3a2c8addd6ce8a2e6b31a9dbf2ad623bf8afc95c235a85bd75ee689c540c9046265bce86709878a521d852cbc37b2b1ede1111a4897d0c7d5c14cfc72a082fb26a7b9b8db7c2d1244b209b321e5f11f36b9d511f6742b5efa7 }

condition:
	$a0
}

        
