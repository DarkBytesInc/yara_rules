rule Win_Trojan_Agent_35221
{
strings:
	$a0 = { 35e32d2676ac82cb1e37ca74110a4aa3d7a186fd70d1dfe1115fad7893c2525ef4a9791cd00a3da467ff23525a28e9d643372564ed5dcd19ae57066a43866006aeae7a488afa2fcf092400641afb9fb08cd1cab25569197ceab4 }

condition:
	$a0
}

        
