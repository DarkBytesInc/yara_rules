rule Win_Trojan_Bancos_1433
{
strings:
	$a0 = { fbcfa3a1bec9e22c38184d892b95ebe14782bb7287e5cfdc3c98e4fda5d8a9eceba27f1d9870b81e8ff86a770d79bcc027454607b61d2d77abdfe7b5e7414786cd4077bc17cef55a69507764c9c7ac5f5278e45a65f20c484cc207a0c7 }

condition:
	$a0
}

        
