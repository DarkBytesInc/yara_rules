rule Win_Trojan_Hupigon_933
{
strings:
	$a0 = { bce0a4df02f1b9d4ff0d5a878d892ba0120bba2067bf80c0b6d85f7301ce1b76b0c424261a34f214e498561984b257d2fe5166b4adb219bce3f83927d805581ca4ea794bdf7050cf1bb6ac5028d9d305930e62bbfa9a6fe3089c056cf541fe37b53fb6a9a5bc2eacc0733b8ea4e490ca90e0c7719b405b0ab5b332db4c5fad7b }

condition:
	$a0
}

        