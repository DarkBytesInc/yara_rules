rule Win_Trojan_Mybot_7073
{
strings:
	$a0 = { 58005959bf0002406701e1744156be608b0603d850d379c20b8d46da50fcc4260cdddc575000d0744e44bb83c63c83c41c837e17bc1600f80075c65eff35a8a24d002bf3505366b13ff7b06a00c26258e0ff7510500c252eb016080062553202de84000b87385f5bc9f0eecd7902278b454d407e0414ff34c5e0ff15e83743004fd113be6808023a5e2de80c }

condition:
	$a0
}

        