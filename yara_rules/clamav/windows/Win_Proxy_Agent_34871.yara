rule Win_Proxy_Agent_34871
{
strings:
	$a0 = { 07b8becf38c593e1d726bb8a92a93afca4b47b747694b23b160a8234672ae5cb03a6ea360d47edd7bdce82af0fc2ba3ace8adcfc8b33b9e6c3040d38d45a5c55eb381c4da8e42a2b2d6507240e130557787392f09777a3c87246d50f4f0484dfbc6de3d7e8f67a4efd8527ef6eb7a2d81f8fec1f4f3ea99bc2ddb5 }

condition:
	$a0
}

        