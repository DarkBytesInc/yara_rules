rule Win_Trojan_Sql_1
{
strings:
	$a0 = { 7275733a272c405669727573436f6465290d0a7365742040623d43484152494e44455828636f6e766572742876617263686172283230292c307834373446353434463230353636393732373537333434364636453635292c405669727573436f6465290d0a73657420405669727573436f64653d535542535452494e }

condition:
	$a0
}

        