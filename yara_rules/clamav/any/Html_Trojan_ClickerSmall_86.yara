rule Html_Trojan_ClickerSmall_86
{
strings:
	$a0 = { 010d010072750000000001002606006f7f284176d55152d8d3e9650afdd6aedfd753e3758f5c0b890bafb6ef01e47ef4f32149858f5f1984c6de87cc8b5825b243d53a1a6d25095487e3e0818850a2f78c89eedf0984b26186d663775f24700a44d6854e09c8cbfb0be7925ac0dad68900cf415e7d4d6137b5831d2179d4cad27facb602788385720bc78e67f72561a9 }

condition:
	$a0
}

        