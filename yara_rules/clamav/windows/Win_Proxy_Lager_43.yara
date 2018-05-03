rule Win_Proxy_Lager_43
{
strings:
	$a0 = { c24d65d50fd11f9a5ef16b3642f70939345ff13a5e1fa3a8ddc7ee2abaf226eae4ff0841e2fa7628def56e5f1d284a546688b32b05d8fe6e03f711dd898e9eb1f0988b2a32a8 }

condition:
	$a0
}

        
