rule Win_Trojan_Worm_11
{
strings:
	$a0 = { 9c05bafc058f0675baaa71aff6fbaaaa3d7a2afafafafafafafa3d7a2efafafafafafafa7987eafa8ef2058f0675bad211f971bf06a13338f6faaf7116058ff290fb90fa1272c6fafa3338fefaaf711671aff271e8058ff205a8f23338fefaaf7116793e0277af02058ff675f83db8fe }

condition:
	$a0
}

        
