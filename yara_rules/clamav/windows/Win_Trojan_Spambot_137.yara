rule Win_Trojan_Spambot_137
{
strings:
	$a0 = { 981d10d6464100e258b4b675623dffff17ffd201ae921861a000656b1e8a6de8cea79d06dfce7f611de0c07a1ffeffff60dea3848e7f66fd45f2bc68832abaf6bc5afe26c8a987dd01cafbffffff66ea637fa9572e7a634e606ae689431f95be95729da21dbc1ca667da7847ffff }

condition:
	$a0
}

        
