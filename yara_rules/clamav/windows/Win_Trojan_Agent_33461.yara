rule Win_Trojan_Agent_33461
{
strings:
	$a0 = { 41c4bcb52bac42bc99f782c9298e43f5aedc38cf846fa1b5e68ac25eb62e2715a3380d570a14f4f902de4defbdea4b9131cdb23cf65d75dcfbb0fd5c972ed915cb4c648898a3bc46b494c7dbea62be04978299bf49f95f6843f03d201a76f9a35705f91d617ee2d59bf8ef9ee30eb96d67f236b17db3aa0783cc8e6da69871fe23c78112852c6580fa5b681a77886c7a91466708 }

condition:
	$a0
}

        