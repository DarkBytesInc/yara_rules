rule Win_Trojan_Ciadoor_218
{
strings:
	$a0 = { 34535b663faa7c84b0ce7dd61d3452479c7d5e67d7c559bd7e103722af70d84ebd692b15a0a8039e8541b76b3ae279100cccfa7bffaab6c2ae1b086a4ae79d7ed6b07708aecc0bc7bac2b721deca65863ab8ea548ca748dc14b506f2ac242f6cadac8866 }

condition:
	$a0
}

        
