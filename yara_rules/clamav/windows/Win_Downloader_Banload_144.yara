rule Win_Downloader_Banload_144
{
strings:
	$a0 = { 39a2592ea80220419e0b457ebe8aee297ab97582227af60ddee1100ec404a50ff6abbaa46d4273ac4dfea95ed667bb067c589c451ef7fa695f1570b10ab76527bdeaf49a354f8c4817f1926d29f199d807754056c051ce46ba0fe53f4b1294230481ca31f5f6a5fb138246395e75daa973720455ff11d84c1c13f2071b62c7666afb59510f7f91d78390096768a9f66ddb5ea3e80108 }

condition:
	$a0
}

        