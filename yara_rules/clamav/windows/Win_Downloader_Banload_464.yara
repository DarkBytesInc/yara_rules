rule Win_Downloader_Banload_464
{
strings:
	$a0 = { bc8046e01148936a5c9e58de2aa7a59fa35205766b8f2aed8dc6c71cb96d6ecaabfc5b67bbebd61c661411ad75e92ae5039873d7373428443d7fd4bd7b5f45b90b49eac516c2861b81ccada3a27201316e5d152c }

condition:
	$a0
}

        
