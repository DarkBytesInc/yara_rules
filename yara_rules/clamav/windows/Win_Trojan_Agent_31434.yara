rule Win_Trojan_Agent_31434
{
strings:
	$a0 = { 977c5061a858d88f5fdece71cf1d38591de5135c15cf03b87d976529dc1c9ced3e792571931da7ae32418551c920e07db9aa3db942ded6badb5404a2287f15bce51773b890f1d4496019a2c1e4c3e6098a59b47e6070ba1fcf727005744f7251840aec65738958146fc3db09580ad711f55fbb497948511d101ed1c3e80867984947f5928f626bc498935211032237b10ca73aee1680 }

condition:
	$a0
}

        