rule Win_Trojan_SdBot_3600
{
strings:
	$a0 = { 6cd286e1186a9fe53c9bd6573ae783af4e2e07e6dba00b5240c64487fe3746c4dba25a954c9338201832427b6be25350b22b2b676e40ae9c26aa3cc70190d42d588738e7dc7eef7a62e205365b8a327172d513d52de84d35c43f8ce4c5cd18358c2a10e019232ae98914e08e3e0c64f8f1d76c7070d9feb1f23e738ff76d34f0a3384e9696d034b1a383c1b9 }

condition:
	$a0
}

        