rule Win_Downloader_Banload_590
{
strings:
	$a0 = { 65116a4c02380c8790a57cc6b94107195d5ddf5932a4acfebf83e699c5c33c29b2aeb5ec57d892a5240cc7581b03505023505f47864b28c6aa26a94e6c7012e5b22dae18 }

condition:
	$a0
}

        
