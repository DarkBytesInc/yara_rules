rule Win_Trojan_Spambot_99
{
strings:
	$a0 = { 37a9fa52709bb0da45fa943fb3a069ffffffffaf21e035ab8090c6c62a5e5d6bc0ea39811330b2928900d06d8efabfd2c7ffffff3e4c05641a8aca694353b979ebf95ceaf18cc574da84877b32ea3ffff5ffff03a91be3015a84519fcfbb3a902c5e56eff26ea1f46a90d287ffff }

condition:
	$a0
}

        
