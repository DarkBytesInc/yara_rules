rule Win_Trojan_Mybot_8493
{
strings:
	$a0 = { 879ceee45c9b89bfcaf22bbcd783b7bc7f93c5dc2cf3da0e9f978bb67bd4dfed1b50e9c816f90197c8034e39df1b08fec370df87c55deb539d6d6e5fe9c4ae16c303cee627bd452e7309e73907801cc2a0423fd2dd }

condition:
	$a0
}

        
