rule Win_Trojan_Agent_34599
{
strings:
	$a0 = { 55545d83ec20ff750c58ff25d531341a5f5e5bc9c20c000f84f2f1ffffe926f2ffff74bcff25ee34341aff75fc8b0dff34341ae831f6ffff50ff351b39341ae946020000508d45ec508d45f45057e91cfeffff6a0158c3897dbc8995a0feffff89b5a4fe }

condition:
	$a0
}

        
