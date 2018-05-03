rule Win_Worm_Stration_403
{
strings:
	$a0 = { e6ae139807fa86c6ceacf4e6ea47392f32f014e89e125ab68578dd3b0959339bdbca234b4e87464f668fed1a85489bb3bcfa459e9ac34bcfaa3b41c6e99f307c3dc747b07296c0fca1152db5ec953f6637c5dce1bd49991ed48ece51f8bf840b }

condition:
	$a0
}

        
