rule Win_Trojan_Small_3856
{
strings:
	$a0 = { 293f0139293fc24911cbb1a8eb39cdcca803fcd5e8bfb1a8ee39e5ccb405f4a69b37b5cca82cb32d7423af35e7b1c212a1ad46f997c4c5b9d8aefca01eaee5d1250572faeb0570bed8bfb1a802b0c7fb006f8ee89896ad9a98aef46ca905dba89784c1a7aefe81e8 }

condition:
	$a0
}

        
