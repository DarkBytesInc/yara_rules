rule Win_Proxy_Lager_68
{
strings:
	$a0 = { b2ffcf331248407a91d64c7375f05e869654dcb4338a37b90ae0f2c0c62bb11f081038bf9cc90feda5b10c8adf7c47daa6fee2e910c339f6bff25b0c0ae93aaff16dd486efac }

condition:
	$a0
}

        
