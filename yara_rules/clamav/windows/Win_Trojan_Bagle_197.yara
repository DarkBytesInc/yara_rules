rule Win_Trojan_Bagle_197
{
strings:
	$a0 = { f9027cada3aa2400126b59290005a3355ad0dda6c3acc6eb53f4bfc75ce327e8be077dd24b13d57aff8b20184fcceb4a92049ca7e77ab633246540a26f6c3dfec7d3e682fba0549145c66dec632ddcfe8c9be27dccd12ebf400894018a5ece47 }

condition:
	$a0
}

        
