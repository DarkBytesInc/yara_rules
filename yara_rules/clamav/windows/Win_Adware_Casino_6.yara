rule Win_Adware_Casino_6
{
strings:
	$a0 = { f14100538945ecffd6837de8008945f00f8493000000837dec000f848900000085c00f8481000000576a015fc745fcf0f1410068dcf1410053ffd68bf085f674286a4458506a008945f8ff15e45041008bd885db74138d45f850536a0057ffd685c07405895dfc33ff6a036a02680000001057ff75fc8d45e86a01ff750850e80800e6dd83c4208bf085ff5f7509ff75fcff15e05041 }

condition:
	$a0
}

        