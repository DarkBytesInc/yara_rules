rule Win_Trojan_QQPass_49
{
strings:
	$a0 = { 7d1e50cca8396676a75d8006f224f078e36590e8bda87daee986c4cee7d2422f9aa6ed881972a712fd23db19ea7b8e497252774a7858795b1d38254aed3c7536bbd38cc06155f03fb0b31ce8042b6ae8f56a5dc850bc66c2524e4b7092ee52c9b9fbd0602b08bea333a425cd1157cdb5 }

condition:
	$a0
}

        