rule Win_Downloader_Banload_763
{
strings:
	$a0 = { 9c5f54df300bf8a0afb0e9180e6b88f1259ea2e06c0acdf5f616c05542d0855f842eb0b4dd3113305a8439f855b75f0376805319b3a3f52e997f6cde541d1f4208e01c0d59e62f351a794f7d99ccb189c3846acc9afd305fd4b2 }

condition:
	$a0
}

        
