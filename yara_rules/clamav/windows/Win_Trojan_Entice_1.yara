rule Win_Trojan_Entice_1
{
strings:
	$a0 = { 202276627322206f72204578744e616d65203d202276626522207468656e0d0a092020205365742053637269707473203d2046534f2e4f70656e5465787446696c652853637269707446696c65732e706174682c2031290d0a0909496620536372697074732e526561644c696e65203c3e2022275642532f44454d4f4e }

condition:
	$a0
}

        