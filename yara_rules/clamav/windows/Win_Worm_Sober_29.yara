rule Win_Worm_Sober_29
{
strings:
	$a0 = { 23776e5dd8544e6e83fd6f4361636865ad576718572885bce44030305783ebbdde1e51cd35f35b2bc6baaddf08030c1502dffd60c5675c4136d85f5f7662615ba07573dd7c556eedd565133461a109412b6903f692d4b47965 }

condition:
	$a0
}

        