rule Win_Spyware_Goldun_138
{
strings:
	$a0 = { 18004aaca20167ce5f7c002af4e1c86f59681700ca10a3730338702000ce9ff52a89c75aa600d3c51d74d74bd28a00d6dc4355f619a9fe00e2e42ef98fcac5dd0042b13ef2bf56e88000e7 }

condition:
	$a0
}

        
