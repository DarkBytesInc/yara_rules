rule Win_Spyware_Banker_5703
{
strings:
	$a0 = { 938b6d17e0160040b0fb6a95d2490b1f6f8f697e3b219c42f9c58ee2ff2227f40f10750573aeec2dc305f193fc57a7b18dccbe34767ff4b790d7a2f2891cb0a8f574fde9b4ef8456a28dbc646fd2fc810dd51443a61537684f1d }

condition:
	$a0
}

        