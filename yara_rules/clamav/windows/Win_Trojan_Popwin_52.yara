rule Win_Trojan_Popwin_52
{
strings:
	$a0 = { f3ab66abaa8d8d00fcffff518b8dfcfbffffe8192500008d9500fcffff52e8b1fb000083c40485c0743068602802108d8500fcffff50e819fc000083c40885c07418686c2802108d8d00fcffff51e801f10000 }

condition:
	$a0
}

        
