rule Win_Trojan_Small_3982
{
strings:
	$a0 = { 61a3e8ae0c7b5486417bad87d26858f2be5e1a0fedc65f300d0738aecc6b605dfd43e0d61e91910a1fdc4382b0765cddc92814b4c598e01c423baf1128ec722f28147e2934d049648947ceb2bba39fe1e781ad1abe547329c5eaa571dd0658ebded740160ba543f32860b22b212b350d399595a108749c03cb6808a943394b13b1452d03ac5eac24901af51cc2c67d8b231d0d19ca33 }

condition:
	$a0
}

        