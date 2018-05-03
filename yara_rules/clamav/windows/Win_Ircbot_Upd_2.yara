rule Win_Ircbot_Upd_2
{
strings:
	$a0 = { aeffe83700b43c2bc98d966005cd2193b419cd21046188863a05b440b93e008d961105cd21e814 }

condition:
	$a0
}

        
