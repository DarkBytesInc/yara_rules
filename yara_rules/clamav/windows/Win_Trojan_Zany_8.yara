rule Win_Trojan_Zany_8
{
strings:
	$a0 = { 2421b44ee90600b43ecd21b44fbacc01cd21726eb8023dba9e00cd218bd8b80057cd2183f90074dfb8024233d233c9cd21a3d401b8004233c933d2cd21b43f8b0ed4018b167a02cd21 }

condition:
	$a0
}

        
