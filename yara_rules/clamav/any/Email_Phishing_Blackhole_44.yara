rule Email_Phishing_Blackhole_44
{
strings:
	$a0 = { 7472797b6e65776c6f636174696f6e28293b7d636174636828717171297b }

condition:
	$a0
}

        
