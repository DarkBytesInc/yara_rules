rule Win_Trojan_Startpage_335
{
strings:
	$a0 = { 1a8b74240856e843ebffff85c05974088b46fc83e8095ec356eb04ff7424086a00ff3540874000ff153c6040005ec3558bec83ec10568d45f850ff15286040008b75fc3375f8ff152c60400033f0ff153060400033f0ff153460400033f08d45f050ff156c6040008b45f43345f033f0893570824000750ac705708240004ee640bb5ec9c3681801000068c0724000e801dbffffa170 }

condition:
	$a0
}

        