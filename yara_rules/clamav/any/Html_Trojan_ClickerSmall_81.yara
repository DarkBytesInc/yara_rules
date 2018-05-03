rule Html_Trojan_ClickerSmall_81
{
strings:
	$a0 = { 6c23794b7924424357337159624eb8d15ae97123452b194f00656e385af7786b4ec2094304a43ade686c1a506eb05c496e4f6eb5c7dfc61a610d47656f006943b4ec }

condition:
	$a0
}

        
