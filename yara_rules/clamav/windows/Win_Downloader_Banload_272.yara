rule Win_Downloader_Banload_272
{
strings:
	$a0 = { 1c843dc7d9a5323352a5d9ecf44f20cdc786866bcdb16c553326e5e57cce7a8b3bdc51ca32fc780c35db6623af4591169bc858189ac2c0a4fc600e9ff0b050cfc3eca56e2a2bda66682dc1187d4e7d1314074f145c17af52e1397059e74ab830b2a10d1e73e6ebe3aa73e03ebb470f0b0ea98b8129afc5a4c1a128c6aa530f5801b98de4042d2af4c3cfc3f7 }

condition:
	$a0
}

        