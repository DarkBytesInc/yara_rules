rule Win_Downloader_Agent_35035
{
strings:
	$a0 = { 3303d5101d6eeb464e3dc6123d3fbdc81e6bef151c3adca25f5aeb468e4db2182135dc1a0a6eeb425330b41e0a6eeb42572ca8020a6eeb424b28ac060a6eeb424f24a00a0a6eeb424320a40e0a6eeb4247dc58f20a6eeb42bbd85cf60a6e }

condition:
	$a0
}

        
