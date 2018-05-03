rule Win_Worm_SomeFool_30
{
strings:
	$a0 = { 4a16c818cdf2001d9f4a1315525456a1e178ed50b1198762e8038f470001a0a0a03f70bedd2cf0a4c88fd659e1a86f17ec00e3eae995dde953ec16662b95ca1f161da9ffba8600ec18a9df59ced75800d0898bf73ab43c48 }

condition:
	$a0
}

        
