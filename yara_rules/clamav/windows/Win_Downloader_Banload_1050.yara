rule Win_Downloader_Banload_1050
{
strings:
	$a0 = { c4a1fdee3baaee5d4047a785d9c2cde5f3075562cc65a1fefcdbd8dd55acb79b28b5240074c487ec8f1020129e34a2fa1ae7276914bcec8e96e58b7fe6ca593e9c7204919138c0891f439ee52da06ee2ad4ae9700b1dd003afd1fb21aed39b4e4f23ba291b912d38383cc1f2f3df3c5200698a9595afca77 }

condition:
	$a0
}

        
