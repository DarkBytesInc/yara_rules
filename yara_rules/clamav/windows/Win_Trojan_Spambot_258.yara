rule Win_Trojan_Spambot_258
{
strings:
	$a0 = { 801e2ed05645d4c144ffa1f4e1068abea1ff7f35c0b3198b519cc852736437fdebcfd1e0acdaffffffffda2e826532420414fd658fdd3d0da7c24a224d6728a818cf780cd6f6b46931c5ffffffff158f2fbd8d2784d9df9caec76dfc061ada6620b82596d85eb89614e24bb9a471 }

condition:
	$a0
}

        
