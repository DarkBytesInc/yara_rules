rule Win_Trojan_Bancos_1960
{
strings:
	$a0 = { 3e0771a1acada0e94db1aa5e888a0e6a5888e7433aa1abedfc0409a6f284a72f1ac84b1cb21daad34be05e3932151ecc24a5127c83924115fd37311630bc19a5e34116d54ae4a3b6209c0dc80d1a11f2df9077c951c9b9152f59 }

condition:
	$a0
}

        
