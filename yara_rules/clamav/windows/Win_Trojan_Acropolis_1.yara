rule Win_Trojan_Acropolis_1
{
strings:
	$a0 = { 32881edfd71532335a0dcf5946d15c9900cb90fd3066fe00b19f2ee3eb56aa81ebdaa9c8d4b15dfd19e6d825a36947f6ebda1db013eecdc3e76f6aafde1b37443894db60523eff30b58e1cd890e11a1722d335ac75577da922a3d75c2537b3237e2ce84f70dd0a7bbe1c1659fa }

condition:
	$a0
}

        
