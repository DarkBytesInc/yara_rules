rule Win_Trojan_SdBot_92
{
strings:
	$a0 = { ab54f701ba617d96ad88d366bd780bcf6c73736713059d2c35ae7e7988cb9dba69838ea90abd96b188d39eb988cb3a6d844269f996adbbcb360c4220afc7aaaa9de59d3efca31eacd8560e3cae7725bea7ceed8f5e1d6e215e25bcde4d3ada0a3aca120f2d2b2b37e1869533ab504aea3bfb4bd8d6d8a4a11e063f035982 }

condition:
	$a0
}

        
