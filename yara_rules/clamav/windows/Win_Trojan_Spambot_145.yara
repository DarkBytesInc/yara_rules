rule Win_Trojan_Spambot_145
{
strings:
	$a0 = { 01bbea7dacdc8bb427f2ef08d81d9344d28ad2fff146c388ffffffff62056943559fb8982bac5b6fc89cf89902434a91f19b1fdbcdaff887f4b84ee9ffffffff8973f149df5769206504c10c2fb75238fa528679ee26c801bab00ff3e7808019ff7ff1fff1c36242421437fb751d }

condition:
	$a0
}

        
