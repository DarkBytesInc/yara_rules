rule Win_Trojan_SdBot_1499
{
strings:
	$a0 = { 79503fff5306670601204ca423e005931976d0fc016a92e9025fb027eff41f025553455233322e64d34d5356430401a1ee50363018e93202aa5891291d500097ff07dcd8aebecc67eb105a4a33c966b97d1b5d10fe0180340a99e2fa3ceb6ffef6bfc47095989999c3fd38a9990c12d99512e9853491124112fffeffffeaa512ed87e19a6a12e7b99a6212d78daa74cf }

condition:
	$a0
}

        