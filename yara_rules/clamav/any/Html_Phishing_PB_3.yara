rule Html_Phishing_PB_3
{
strings:
	$a0 = { 687474703a2f2f7777772e706f737462616e6b696e672e6f7267[0-200]20616c743d22646575747363686520706f737462616e6b206167 }

condition:
	$a0
}

        