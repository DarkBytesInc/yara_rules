rule Win_Downloader_Zlob_1996
{
strings:
	$a0 = { ec048b1d21434000c7830a0700000000000080eedd8b451039830a0700007c04b663eb2f8b750803b30a070000c6060080ce8980eeee8b830a07000089830607000080ed36b2a083830a0700000180c93bebc2c9c20c00b1a55580f40f89e581eca40000008b1d21434000c683080300006c80e644c683fe02000065c6830303000033c683070300006cc683060300006480ed8380c5 }

condition:
	$a0
}

        