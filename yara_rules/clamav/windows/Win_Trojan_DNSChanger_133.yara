rule Win_Trojan_DNSChanger_133
{
strings:
	$a0 = { 1270201d91a9c903d9b2731bcc6ccd2a1572741b91f9c68390b9921b90bf372bd1a9aede1aef6f2a1543741b91e2d02b06c2c68595fc7250ddbab31be4fc72908da9898fa2e973a4d69dff988de56e8f0635e90fcd9ce889fb }

condition:
	$a0
}

        
