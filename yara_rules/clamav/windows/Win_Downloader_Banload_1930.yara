rule Win_Downloader_Banload_1930
{
strings:
	$a0 = { 7e293d2d91bb50b81a60fbc4fb15c6dc86a612aeb283a240284f78e774e73eeebe2531219d7b9078da6cf7c8f7d5061c46aa1ea2be436280e84374eb7827fe2e7e293d2d91bb50b81a60fbc4fb15c6dc86a612aeb283a240284f78e774e73eeebe2531219d7b9078da6cf7c8f7d5061c46aa1ea2be436280e84374eb7827fe2e7e293d2d91bb50b81a60fbc4fb15c6dc86 }

condition:
	$a0
}

        