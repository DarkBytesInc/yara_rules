rule Win_Worm_Gaobot_90
{
strings:
	$a0 = { 2573203a73637265772079f73fecdb6f751a210d0a004b47476f20686f6d65206e3bcec2398562ae532763f7ffd77700546f706963436d642e4e65745e1f76d33e09ce2d6f066e73007c1ee7e50fa43a1f33333200762d000020c8bef74d4f4445566d3632341f04ecbfbc4d021e36365f3055 }

condition:
	$a0
}

        