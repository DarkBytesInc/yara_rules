rule Win_Trojan_Hupigon_740
{
strings:
	$a0 = { 30d622dbf9057dab6e528436fd92039ce91ab4346818bd8022292f89ac69a42e4b4a8748c55f8eeda5866a111f478ccecc1ce801a53ba84cddaab9705ca59647c1c1bf0559277ec0f64b24c2672f8fc967d74d3b9d42294b }

condition:
	$a0
}

        
