rule Win_Trojan_Lineage_289
{
strings:
	$a0 = { 0f20c7e2f4b7d61b59ea730ca574c5d4c9ec9b52a11b9afbf4e5d056cf0aaa2d2004ac382bd49997a36b23282d3f40a605b3940fad81e24d182b63d434468fb5ee18b448145923fc0e0b8d89edb073fd2f515acb99e87837f5bd865b }

condition:
	$a0
}

        
