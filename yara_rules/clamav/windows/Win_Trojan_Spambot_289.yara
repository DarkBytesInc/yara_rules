rule Win_Trojan_Spambot_289
{
strings:
	$a0 = { 18210323f472e082c3a2ffffffff9bd4105c6bdbb7c8b2e06933eac2ae89fd0eb57fbbc7c3a65de9507946e7e48dfdffffffc1fe1664b5334e3525146373b9c2b081be73d2666d00eb96edde957fc0b47ff0ff1f49ed3e7cca3d534e16f04cd471651167478dcd4725fbff5f7ffc }

condition:
	$a0
}

        
