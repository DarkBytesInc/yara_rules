rule Win_Trojan_Lineage_380
{
strings:
	$a0 = { 401e16b82627ef4a31af0612334e183a9d7d8bbed4d1ea7ef0f0917b7ac8ea82673d644a14d8d7622863f0db4bb73f74398fe151e42d73d7504833f245b5d67966c316da99d1d971b37a527645c20d35c56b4164bf82bff31d3e2de635f2852b8ac949dbdf8b079c14d487047a3fa0958878136a648ef5ae53880d82cf328c2153c33b138e069bcded131b99c81c204b9199f555 }

condition:
	$a0
}

        