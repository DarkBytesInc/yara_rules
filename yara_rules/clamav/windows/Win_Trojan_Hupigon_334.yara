rule Win_Trojan_Hupigon_334
{
strings:
	$a0 = { 87ebce68b0eb8dee7c0e0bef75e9439c6daa3777328ba38df8fc1d02dffd7a7ccf716833e2d62582d2fb17070b4685400172564bf442cc7f59ef7beaad7091419c3314462ee880f8969346a1cd587a332561acc8c719df24b5dc }

condition:
	$a0
}

        
