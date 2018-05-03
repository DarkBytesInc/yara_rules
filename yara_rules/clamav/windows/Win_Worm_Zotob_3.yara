rule Win_Worm_Zotob_3
{
strings:
	$a0 = { 8546482afa1549b7b161bbaa0d0a54968d29bf9fb73c121416e17314246c48b5dd705bbcfbbdbf06d32ded }

condition:
	$a0
}

        
