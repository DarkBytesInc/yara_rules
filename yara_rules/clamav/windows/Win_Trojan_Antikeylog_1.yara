rule Win_Trojan_Antikeylog_1
{
strings:
	$a0 = { 350020400088140500204000468d0d0020400083c8ff40803c010075f939c676d98d8500fcffff50e8190700008985e4fbfdff83bde4fbfdff00750fc70594404000ffffffffe9c8030000e84cfeffffe847feffffe842feffffe83dfeffff66 }

condition:
	$a0
}

        
