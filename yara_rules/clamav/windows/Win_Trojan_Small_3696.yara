rule Win_Trojan_Small_3696
{
strings:
	$a0 = { b737a7955f3c608d094073d50fe9ce940cd74c861fbff17d2ebca495dc7bbc6a2b9bbc6a4ab7b4d55fe0fac804e667c308d7a4855fbfce9da0aa9c851fbff46a4a83b4d55f3454ff5fd587c335bf5b800bafe495da7fd0a7d48294851fbff26a883a64e17ae95b42dfc3946a03caacc3a06824 }

condition:
	$a0
}

        
