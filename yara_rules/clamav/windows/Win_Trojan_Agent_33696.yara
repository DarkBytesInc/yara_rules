rule Win_Trojan_Agent_33696
{
strings:
	$a0 = { af25d611ccce3464382a79179b321c9eab01861f65ea491cb370b0d75e5bdfc05da52baedf6fcd2abe5aea1947f260ce1fb6bb57fc07417530ddd336a1e5486b658a2ae9a5e44c30aadde74187c9670288ff040e3b39de8a698d1b3ac0add8 }

condition:
	$a0
}

        
