rule Win_Trojan_IRCBot_731
{
strings:
	$a0 = { 290663b3fdc99bf7caaea3158515ff63b3f8bb5c0ae65748011a3aad24a963cb4e48f3245fb9c39739d20bc26b692eb43cbc1eac831d6e9ffd8567067de4dd44fb953897e2f70c41c3c3da35b019525259119aa59da7f5ea528cdac79f13f69010631d45660c14fc644842692105c6094e7b181f3e39f12335c20a1cb422c7e71574c2e9bb83b3946e211e80c32cb93d5984d2606762 }

condition:
	$a0
}

        